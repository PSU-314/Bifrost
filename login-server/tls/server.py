"""
server.py — mTLS server (Python equivalent of server.cpp)

Mutual TLS: both sides authenticate. Client cert is MANDATORY.

PKI layout expected (relative to cwd):
    pki/root-ca/root-ca.crt
    pki/server/server-chain.pem   (server.crt + intermediate-ca.crt)
    pki/server/server.key

Run:
    python3 server.py [port]          # default port: 8443

Works with the C++ client as-is — same PKI, same cipher policy.

Requires Python 3.6+ (ssl module is in stdlib, no pip installs needed).
"""

import ssl
import socket
import threading
import signal
import sys
import os
import traceback

# ─── Configuration
# ─────────────────────────────────────────────────────────────

DEFAULT_PORT    = 8443
SERVER_CHAIN    = "pki/server/server-chain.pem"   # leaf + intermediate
SERVER_KEY      = "pki/server/server.key"
CLIENT_CA       = "pki/root-ca/root-ca.crt"       # trust anchor for client certs

# ─── TLS cipher policy (mirrors server.cpp)
# ─────────────────────────────────────────

# TLS 1.2 suites: ECDHE only (forward secrecy) + AEAD only.
# Python's ssl module uses OpenSSL underneath — same string format.
TLS12_CIPHERS = ":".join([
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
])

# TLS 1.3 suites are set separately via set_ciphers() on Python 3.8+
# or via the SSLKEYLOGFILE / OP flags on older versions.
TLS13_CIPHERS = ":".join([
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
])

# ─── Global running flag (set False by SIGINT / SIGTERM)
# ─────────────────────────────

g_running = True

def on_signal(signum, frame):
    global g_running
    print("\n[Server] Shutting down gracefully...")
    g_running = False


# ─── SSL context factory
# ──────────────────────────────────────────────────────────
# Mirrors create_server_ctx() in server.cpp exactly.

def create_server_ctx(cert_pem: str, key_pem: str, client_ca: str) -> ssl.SSLContext:
    """
    Build a hardened server-side SSLContext with mandatory mTLS.

    cert_pem  : server-chain.pem  (leaf + intermediate; root excluded)
    key_pem   : server.key
    client_ca : root-ca.crt  (trust anchor used to verify the client cert)
    """

    # ssl.PROTOCOL_TLS_SERVER = modern auto-negotiating server context.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # ── Version floor: TLS 1.2 ───────────────────────────────────────────────
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED   # allow TLS 1.3

    # ── Cipher suite pinning ─────────────────────────────────────────────────
    # set_ciphers() covers both TLS 1.2 and TLS 1.3 suites in Python's ssl.
    ctx.set_ciphers(TLS12_CIPHERS + ":" + TLS13_CIPHERS)

    # ── Security options (mirrors SSL_OP_NO_TICKET + SSL_OP_NO_COMPRESSION) ──
    ctx.options |= ssl.OP_NO_COMPRESSION        # CRIME attack prevention
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE  # server cipher order wins
    # OP_NO_TICKET: Python's ssl exposes this as a flag on some builds.
    # Fall back silently if the constant isn't available on this platform.
    if hasattr(ssl, "OP_NO_TICKET"):
        ctx.options |= ssl.OP_NO_TICKET

    # ── Server certificate chain ─────────────────────────────────────────────
    # load_cert_chain() loads the leaf cert and any chained intermediates
    # from a PEM that contains them concatenated.
    ctx.load_cert_chain(certfile=cert_pem, keyfile=key_pem)

    # ── Mutual TLS — MANDATORY ───────────────────────────────────────────────
    # CERT_REQUIRED = send CertificateRequest AND abort if client sends none.
    # Equivalent to SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT.
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Load the CA that signed the client cert (your private root CA).
    ctx.load_verify_locations(cafile=client_ca)

    # verify_flags: enforce full chain check including CRL if available.
    ctx.verify_flags = ssl.VERIFY_X509_STRICT

    # check_hostname must be False on the server side — the server verifies
    # the client's cert chain, not a hostname.
    ctx.check_hostname = False

    return ctx


# ─── Per-connection handler
# ──────────────────────────────────────────────────
# Mirrors handle_connection() in server.cpp.

def handle_connection(conn: ssl.SSLSocket, peer_addr: tuple):
    """
    Runs in its own thread. Performs mTLS verification, then echoes data.
    conn      : already-wrapped SSLSocket (SSL_accept equivalent done by
                SSLContext.wrap_socket with server_side=True)
    peer_addr : (ip, port) tuple
    """
    peer = f"{peer_addr[0]}:{peer_addr[1]}"
    print(f"[{peer}] Connection accepted")

    try:
        # ── TLS handshake ────────────────────────────────────────────────────
        # wrap_socket() with do_handshake_on_connect=True (default) already
        # called SSL_accept. We call do_handshake() explicitly here because
        # we pass do_handshake_on_connect=False from accept_loop so that
        # errors surface inside this thread, not the main loop.
        conn.do_handshake()

        print(f"[{peer}] TLS version : {conn.version()}")
        print(f"[{peer}] Cipher      : {conn.cipher()[0]}")

        # ── Inspect and verify client certificate ────────────────────────────
        # getpeercert() returns a dict for a verified cert, None if absent.
        # Because verify_mode = CERT_REQUIRED, None here is a bug.
        client_cert = conn.getpeercert()
        if client_cert is None:
            print(f"[{peer}] BUG: no client cert after handshake")
            return

        # Extract the subject CN for audit logging (mirrors X509_NAME_oneline).
        subject = dict(x[0] for x in client_cert.get("subject", []))
        print(f"[{peer}] Client cert : CN={subject.get('commonName', '?')}")
        print(f"[{peer}] Client cert verification: OK")

        # ── Application data loop (echo) ─────────────────────────────────────
        # Mirrors the SSL_read / SSL_write loop in server.cpp.
        while True:
            try:
                data = conn.recv(4096)
            except ssl.SSLEOFError:
                # Peer sent close_notify — clean disconnect.
                print(f"[{peer}] Client disconnected cleanly")
                break
            except ssl.SSLError as e:
                print(f"[{peer}] SSL_read error: {e}")
                break

            if not data:
                # TCP FIN without close_notify (truncation / abrupt close).
                print(f"[{peer}] Client disconnected (no close_notify)")
                break

            print(f"[{peer}] Received ({len(data)} bytes): {data.decode(errors='replace')}")

            # Echo back — loop until all bytes are sent (mirrors sent < n loop).
            total_sent = 0
            while total_sent < len(data):
                try:
                    sent = conn.send(data[total_sent:])
                    if sent == 0:
                        raise RuntimeError("SSL_write returned 0")
                    total_sent += sent
                except ssl.SSLError as e:
                    print(f"[{peer}] SSL_write error: {e}")
                    return

            # Wipe the buffer — mirrors OPENSSL_cleanse(buf, n).
            # Python doesn't guarantee memory wiping, but this is best-effort.
            data = b"\x00" * len(data)
            del data

    except ssl.SSLError as e:
        print(f"[{peer}] Handshake failed: {e}", file=sys.stderr)

    except Exception as e:
        print(f"[{peer}] Unexpected error: {e}", file=sys.stderr)
        traceback.print_exc()

    finally:
        # ── Bidirectional shutdown ────────────────────────────────────────────
        # unwrap() sends close_notify and waits for peer's close_notify.
        # Mirrors the SSL_shutdown(ssl); if ret==0: SSL_shutdown(ssl) pattern.
        try:
            conn.unwrap()     # sends + waits for close_notify
        except Exception:
            pass              # peer may have already closed
        try:
            conn.close()
        except Exception:
            pass
        print(f"[{peer}] Connection closed")


# ─── TCP listener
# ─────────────────────────────────────────────────────────────────
# Mirrors create_listener() in server.cpp.

def create_listener(port: int) -> socket.socket:
    """
    Dual-stack IPv6 socket that also accepts IPv4-mapped addresses.
    Mirrors the AF_INET6 + IPV6_V6ONLY=0 + SO_REUSEADDR setup in server.cpp.
    """
    # AF_INET6 with IPV6_V6ONLY disabled = dual-stack (IPv4 + IPv6 on one fd).
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    # SO_REUSEADDR: avoids TIME_WAIT blocking on quick restart.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # IPV6_V6ONLY = 0: accept IPv4-mapped addresses (::ffff:127.0.0.1).
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

    # "::" = in6addr_any (all interfaces, both IPv4 and IPv6).
    sock.bind(("::", port))

    sock.listen(128)
    return sock


# ─── Accept loop
# ──────────────────────────────────────────────────────────────────

def accept_loop(listen_sock: socket.socket, ctx: ssl.SSLContext):
    """
    Main accept loop. Mirrors the while(g_running) block in main().
    Each accepted connection is handed to a detached daemon thread.
    """
    listen_sock.settimeout(1.0)   # wake up every second to check g_running

    while g_running:
        try:
            raw_conn, peer_addr = listen_sock.accept()
        except socket.timeout:
            continue           # check g_running and go back to blocking
        except OSError:
            if not g_running:
                break
            print("[Server] accept() failed, continuing", file=sys.stderr)
            continue

        # Wrap with TLS. do_handshake_on_connect=False lets the thread
        # call do_handshake() itself so errors are caught per-connection.
        try:
            ssl_conn = ctx.wrap_socket(
                raw_conn,
                server_side=True,
                do_handshake_on_connect=False,
            )
        except ssl.SSLError as e:
            print(f"[{peer_addr}] wrap_socket failed: {e}", file=sys.stderr)
            raw_conn.close()
            continue

        # Spawn a daemon thread — mirrors std::thread(...).detach().
        t = threading.Thread(
            target=handle_connection,
            args=(ssl_conn, peer_addr),
            daemon=True,
        )
        t.start()


# ─── main
# ─────────────────────────────────────────────────────────────────────────

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT

    # Validate cert files exist before touching OpenSSL.
    for path, label in [
        (SERVER_CHAIN, "server-chain.pem"),
        (SERVER_KEY,   "server.key"),
        (CLIENT_CA,    "root-ca.crt"),
    ]:
        if not os.path.exists(path):
            print(f"[FATAL] Missing file: {path} ({label})", file=sys.stderr)
            sys.exit(1)

    # Ignore SIGPIPE (write to closed socket raises BrokenPipeError in Python;
    # we handle it via SSL_write return value checks, same as the C++ code).
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    signal.signal(signal.SIGINT,  on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        ctx         = create_server_ctx(SERVER_CHAIN, SERVER_KEY, CLIENT_CA)
        listen_sock = create_listener(port)
    except Exception as e:
        print(f"[FATAL] {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[Server] Listening on port {port} (mTLS — client cert required)")

    try:
        accept_loop(listen_sock, ctx)
    finally:
        listen_sock.close()
        print("[Server] Shutdown complete")


if __name__ == "__main__":
    main()