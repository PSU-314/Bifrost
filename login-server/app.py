"""
auth2fa — Two-Factor Authentication demo with X25519 key exchange.

mTLS registration endpoint added: Bifrost C++ client connects via mutual TLS,
sends a GET request to the signup URL (bifrost-totp://host=.../signup/<pin>&port=...),
and receives PW_KEY=<hex>&ACC_INFO=<username> in the response body.

PKI layout expected (relative to cwd):
    pki/root-ca/root-ca.crt
    pki/server/server-chain.pem   (leaf + intermediate)
    pki/server/server.key
"""

import logging
import os
import random
import socket
import ssl
import sys
import threading
import time

import argon2.low_level

print("RUNTIME PYTHON VERSION:", sys.version)

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from utils import dh, totp
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# App & Database setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
    basedir, "bifrost.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ---------------------------------------------------------------------------
# PKI paths
# ---------------------------------------------------------------------------

SERVER_CHAIN = "./pki/server/server-chain.pem"
SERVER_KEY = "./pki/server/server.key"
CLIENT_CA = "./pki/root-ca/root-ca.crt"

# ---------------------------------------------------------------------------
# mTLS server configuration
# ---------------------------------------------------------------------------

MTLS_PORT = int(os.environ.get("MTLS_PORT", 8443))
MTLS_ENABLED = all(os.path.exists(p) for p in [SERVER_CHAIN, SERVER_KEY, CLIENT_CA])

# BUG 6 FIX: This label must match BIFROST_EXPORTER_LABEL in tls.hpp exactly.
# Both sides call their respective export_keying_material APIs with this label,
# which implements RFC 5705 (TLS 1.2) / RFC 8446 §7.5 (TLS 1.3) and produces
# identical output.  The old approach used conn.export_keying_material with
# the label "EXPORTER_SECRET", which is an RFC 5705 derivation — completely
# different from the raw EXPORTER_SECRET captured by the C++ keylog callback.
BIFROST_EXPORTER_LABEL = "bifrost-ms"

# ---------------------------------------------------------------------------
# Database Models
# ---------------------------------------------------------------------------


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    shared_secret_hex = db.Column(db.String(64), nullable=True)


class ExchangeToken(db.Model):
    pin = db.Column(db.String(6), primary_key=True)
    username = db.Column(db.String(80), db.ForeignKey("user.username"), nullable=False)
    server_priv_hex = db.Column(db.String(64), nullable=False)
    server_pub_hex = db.Column(db.String(64), nullable=False)
    # PW_KEY: Argon2id-derived bytes sent to Bifrost over mTLS.
    # Bifrost uses it with HKDF(ikm=exporter_secret, salt=PW_KEY) to derive
    # the TOTP key.  The server does the same derivation and stores the result.
    pw_key_hex = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.Float, nullable=False)


with app.app_context():
    db.create_all()

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

TOKEN_TTL = 300  # 5 minutes

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_pw_key(password: str) -> bytes:
    """Derive a 16-byte PW_KEY using Argon2id as per the diagram."""
    salt = os.urandom(16)
    return argon2.low_level.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=2,
        memory_cost=65536,
        parallelism=1,
        hash_len=16,
        type=argon2.low_level.Type.ID,
    )


def _purge_expired_tokens() -> None:
    now = time.time()
    expired = ExchangeToken.query.filter(
        ExchangeToken.created_at < now - TOKEN_TTL
    ).all()
    for t in expired:
        db.session.delete(t)
        log.info("Purged expired exchange token %s.", t.pin)
    db.session.commit()


def _get_shared_secret() -> bytes | None:
    raw = session.get("shared_secret_hex")
    return bytes.fromhex(raw) if raw else None


def _generate_pin() -> str:
    return f"{random.SystemRandom().randint(0, 999_999):06d}"


# ---------------------------------------------------------------------------
# mTLS server — handles Bifrost C++ client registrations
# ---------------------------------------------------------------------------


def _create_mtls_ctx() -> ssl.SSLContext:
    """Build a hardened mTLS SSLContext (mirrors create_client_ctx in tls.cpp)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED

    tls12 = ":".join(
        [
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
        ]
    )
    tls13 = ":".join(
        [
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
        ]
    )
    ctx.set_ciphers(tls12 + ":" + tls13)

    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    if hasattr(ssl, "OP_NO_TICKET"):
        ctx.options |= ssl.OP_NO_TICKET

    ctx.load_cert_chain(certfile=SERVER_CHAIN, keyfile=SERVER_KEY)

    # Mandatory mutual TLS — client cert required
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=CLIENT_CA)
    # ctx.verify_flags = ssl.VERIFY_X509_STRICT
    ctx.check_hostname = False

    return ctx


import ctypes
import ctypes.util
import hashlib
import hmac as hmac_mod


def hkdf_extract_and_expand(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """Standard HKDF-SHA256 — matches hkdf_sha256() in HKDF.hpp."""
    # Extract
    prk = hmac_mod.new(salt if salt else b"\x00" * 32, ikm, hashlib.sha256).digest()
    # Expand (single block; length must be <= 32 for SHA-256)
    t = hmac_mod.new(prk, info + b"\x01", hashlib.sha256).digest()
    return t[:length]


# ---------------------------------------------------------------------------
# SSL_export_keying_material via ctypes
#
# Python 3.12's ssl.SSLSocket does not expose export_keying_material()
# (that was added in 3.13).  We call OpenSSL directly using ctypes.
#
# CPython layout of _ssl._SSLSocket (Modules/_ssl.c, 3.12):
#   offset  0: ob_refcnt   (PyObject_HEAD, 8 bytes)
#   offset  8: ob_type     (8 bytes)
#   offset 16: PySSLContext *ctx  (8 bytes)
#   offset 24: SSL *ssl           (8 bytes)  ← the pointer we need
#
# Verified empirically: offset 24 is the only offset at which
# SSL_export_keying_material() returns 1 (success).
# ---------------------------------------------------------------------------
_SSL_PTR_OFFSET = 24

_libssl = ctypes.CDLL(ctypes.util.find_library("ssl"))
_libssl.SSL_export_keying_material.restype = ctypes.c_int
_libssl.SSL_export_keying_material.argtypes = [
    ctypes.c_void_p,  # SSL *s
    ctypes.c_char_p,  # unsigned char *out
    ctypes.c_size_t,  # size_t olen
    ctypes.c_char_p,  # const char *label
    ctypes.c_size_t,  # size_t llen
    ctypes.c_char_p,  # const unsigned char *context
    ctypes.c_size_t,  # size_t contextlen
    ctypes.c_int,  # int use_context
]


def ssl_export_keying_material(
    ssock: ssl.SSLSocket, label: bytes, length: int
) -> bytes:
    """
    Call SSL_export_keying_material() on the underlying OpenSSL SSL* object.
    Implements RFC 5705 (TLS 1.2) / RFC 8446 §7.5 (TLS 1.3), identical to
    the C++ SSL_export_keying_material() call in tls.cpp.
    """
    obj_addr = id(ssock._sslobj)
    ssl_ptr = ctypes.c_void_p.from_address(obj_addr + _SSL_PTR_OFFSET).value
    out = ctypes.create_string_buffer(length)
    ret = _libssl.SSL_export_keying_material(
        ssl_ptr, out, length, label, len(label), None, 0, 0
    )
    if ret != 1:
        raise RuntimeError(
            f"SSL_export_keying_material failed (ret={ret}); "
            "label may not be supported or handshake is incomplete"
        )
    return bytes(out.raw)


def _handle_bifrost_connection(conn: ssl.SSLSocket, peer_addr: tuple) -> None:
    """
    Handle one Bifrost registration connection.
    """
    peer = f"{peer_addr[0]}:{peer_addr[1]}"
    log.info("[mTLS] %s connected", peer)

    try:
        conn.do_handshake()
        log.info(
            "[mTLS] %s  version=%s  cipher=%s", peer, conn.version(), conn.cipher()[0]
        )

        client_cert = conn.getpeercert()
        if client_cert is None:
            log.warning("[mTLS] %s sent no client cert — dropping", peer)
            return

        raw = conn.recv(4096)
        if not raw:
            return

        request_text = raw.decode(errors="replace")
        lines = request_text.split("\r\n")
        if not lines or not lines[0]:
            return

        # BUG 4 FIX: Parse the PIN from the request line so we look up the
        # correct ExchangeToken instead of blindly picking the most-recent one.
        # The C++ client sends: GET /signup/<pin> HTTP/1.1
        # Old code: ExchangeToken.query.order_by(created_at.desc()).first()
        #   — races between concurrent registrations and ignores the PIN entirely.
        request_line = lines[0]  # e.g. "GET /signup/123456 HTTP/1.1"
        pin = None
        parts = request_line.split()
        if len(parts) >= 2:
            # path is e.g. "/signup/123456"
            path_parts = parts[1].rstrip("/").split("/")
            # path_parts = ['', 'signup', '123456']
            if len(path_parts) >= 3 and path_parts[1] == "signup":
                pin = path_parts[2]

        if not pin:
            log.warning("[mTLS] %s — could not parse PIN from '%s'", peer, request_line)
            _send_mtls_error(
                conn, "400 Bad Request", "Missing or malformed PIN in path"
            )
            return

        log.info("[mTLS] %s — PIN=%s", peer, pin)

        with app.app_context():
            _purge_expired_tokens()

            # Look up by PIN, not by recency
            token = db.session.get(ExchangeToken, pin)

            if token is None:
                _send_mtls_error(
                    conn, "404 Not Found", f"No registration token for PIN {pin}"
                )
                return

            if time.time() - token.created_at > TOKEN_TTL:
                db.session.delete(token)
                db.session.commit()
                _send_mtls_error(conn, "410 Gone", "Registration token expired")
                return

            user = User.query.filter_by(username=token.username).first()
            if not user:
                _send_mtls_error(conn, "400 Bad Request", "User not found")
                return

            pw_key_hex = token.pw_key_hex
            acc_info = token.username

            # ----------------------------------------------------------------
            # Use ssl_export_keying_material() which calls OpenSSL directly
            # via ctypes (ssl.SSLSocket.export_keying_material was only added
            # in Python 3.13; we support 3.12 via the ctypes wrapper above).
            # ----------------------------------------------------------------
            try:
                ms = ssl_export_keying_material(
                    conn,
                    BIFROST_EXPORTER_LABEL.encode(),
                    48,
                )
                pw_key_bytes = bytes.fromhex(pw_key_hex)

                # BUG 5 FIX: info must be exactly 16 bytes — no null terminator.
                # C++ previously used sizeof() on a char array literal which
                # includes the implicit '\0', giving 17 bytes and a different key.
                # tls.hpp now builds TOTP_HKDF_INFO via string_view (16 bytes).
                hkdf_info = b"bifrost-totp-key"  # 16 bytes, matches C++

                derived_secret = hkdf_extract_and_expand(
                    salt=pw_key_bytes,
                    ikm=ms,
                    info=hkdf_info,
                    length=48,
                )

                user.shared_secret_hex = derived_secret.hex()
                db.session.delete(token)
                db.session.commit()
                log.info("[mTLS] Derived and stored TOTP secret for '%s'", acc_info)

            except Exception as e:
                log.error("[mTLS] Key derivation failed: %s", e)
                _send_mtls_error(conn, "500 Internal Error", "Key derivation failed")
                return

        # ----------------------------------------------------------------
        # Send PW_KEY + ACC_INFO back to the client so it can run the same
        # HKDF and arrive at the same TOTP secret.
        # ----------------------------------------------------------------
        body = f"PW_KEY={pw_key_hex}&ACC_INFO={acc_info}"
        http_response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
            f"{body}"
        )
        conn.sendall(http_response.encode())

    except Exception as exc:
        log.error("[mTLS] %s unexpected error: %s", peer, exc)
    finally:
        try:
            conn.unwrap()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def _send_mtls_error(conn: ssl.SSLSocket, status: str, msg: str) -> None:
    try:
        body = f"ERROR={status}: {msg}"
        http_error = (
            f"HTTP/1.1 {status}\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
            f"{body}"
        )
        conn.sendall(http_error.encode())
    except Exception:
        pass


def _mtls_accept_loop(listen_sock: socket.socket, ctx: ssl.SSLContext) -> None:
    listen_sock.settimeout(1.0)
    log.info("[mTLS] Listening on port %d", MTLS_PORT)

    while True:
        try:
            raw_conn, peer_addr = listen_sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        try:
            ssl_conn = ctx.wrap_socket(
                raw_conn,
                server_side=True,
                do_handshake_on_connect=False,
            )
        except ssl.SSLError as exc:
            log.error("[mTLS] wrap_socket failed for %s: %s", peer_addr, exc)
            raw_conn.close()
            continue

        t = threading.Thread(
            target=_handle_bifrost_connection,
            args=(ssl_conn, peer_addr),
            daemon=True,
        )
        t.start()


def _start_mtls_server() -> None:
    if not MTLS_ENABLED:
        log.warning("[mTLS] PKI files missing — mTLS server NOT started.")
        return

    try:
        ctx = _create_mtls_ctx()
    except Exception as exc:
        log.error("[mTLS] Failed to create TLS context: %s", exc)
        return

    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", MTLS_PORT))
    sock.listen(128)

    t = threading.Thread(target=_mtls_accept_loop, args=(sock, ctx), daemon=True)
    t.start()
    log.info("[mTLS] Server started on port %d", MTLS_PORT)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/")
def page_1():
    return render_template("page1.html")


@app.route("/signup", methods=["GET"])
def page_2():
    username = request.args.get("username", "").strip()
    password = request.args.get("password", "").strip()

    if username and password:
        if len(username) < 3 or len(password) < 6:
            return render_template(
                "page2.html",
                error="Username must be ≥ 3 chars and password ≥ 6 chars.",
            )

        user = User.query.filter_by(username=username).first()

        if user and user.shared_secret_hex:
            return render_template(
                "page2.html",
                error="An account with this username has already completed the exchange. Please log in.",
            )

        if not user:
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
            )
            db.session.add(user)
        else:
            user.password_hash = generate_password_hash(password)

        db.session.commit()
        session["saved_username"] = username

        server_priv = dh.generate_private_key()
        server_pub = dh.public_key(server_priv)

        pw_key = _generate_pw_key(password)

        _purge_expired_tokens()
        ExchangeToken.query.filter_by(username=username).delete()
        db.session.commit()

        pin = _generate_pin()

        token_entry = ExchangeToken(
            pin=pin,
            username=username,
            server_priv_hex=server_priv.hex(),
            server_pub_hex=server_pub.hex(),
            pw_key_hex=pw_key.hex(),
            created_at=time.time(),
        )
        db.session.add(token_entry)
        db.session.commit()

        exchange_url = url_for("exchange_endpoint", pin=pin, _external=True)

        server_host = request.host.split(":")[0]
        bifrost_uri = (
            f"bifrost-totp://host={server_host}{url_for('exchange_endpoint', pin=pin)}"
            f"&port={MTLS_PORT}"
        )

        log.info(
            "Signup: token for user '%s'  PIN=%s  bifrost_uri=%s",
            username,
            pin,
            bifrost_uri,
        )

        return render_template(
            "page2.html",
            show_token=True,
            server_pub=server_pub.hex(),
            exchange_url=exchange_url,
            pin=pin,
            bifrost_uri=bifrost_uri,
        )

    return render_template("page2.html")


@app.route("/signup/<pin>", methods=["GET", "POST"])
def exchange_endpoint(pin: str):
    token_entry = db.session.get(ExchangeToken, pin)

    if token_entry is None:
        if request.is_json:
            return jsonify({"error": "Endpoint not found or already used."}), 404
        return render_template("page_exchange.html", expired=True), 404

    if time.time() - token_entry.created_at > TOKEN_TTL:
        db.session.delete(token_entry)
        db.session.commit()
        if request.is_json:
            return jsonify({"error": "Endpoint expired."}), 410
        return render_template("page_exchange.html", expired=True), 410

    if request.method == "GET":
        return render_template(
            "page_exchange.html",
            server_pub=token_entry.server_pub_hex,
            token=pin,
        )

    if request.is_json:
        body = request.get_json(silent=True) or {}
        client_pub_hex = str(body.get("bifrost-public-key", "")).strip()
    else:
        client_pub_hex = request.form.get("bifrost-public-key", "").strip()

    if not client_pub_hex:
        return jsonify({"error": "Missing bifrost-public-key parameter"}), 400

    user = User.query.filter_by(username=token_entry.username).first()
    if not user:
        return jsonify({"error": "User associated with token no longer exists"}), 400

    if user.shared_secret_hex:
        db.session.delete(token_entry)
        db.session.commit()
        return jsonify({"error": "Key exchange already completed for this user."}), 403

    try:
        server_priv = bytes.fromhex(token_entry.server_priv_hex)
        client_pub = bytes.fromhex(client_pub_hex)
        secret = dh.diffie_hellman(server_priv, client_pub)
    except Exception as exc:
        return jsonify({"error": f"Key exchange failed: {exc}"}), 400

    server_pub_hex = token_entry.server_pub_hex

    user.shared_secret_hex = secret.hex()
    db.session.delete(token_entry)
    db.session.commit()

    return jsonify(
        {
            "status": "success",
            "server-public-key": server_pub_hex,
            "message": "Key exchange complete",
        }
    ), 200


@app.route("/signup/status", methods=["GET"])
def signup_status():
    """Poll endpoint: returns true once the mTLS thread has saved shared_secret_hex."""
    username = session.get("saved_username")
    if not username:
        return jsonify(
            {"completed": False, "error": "No active registration session"}
        ), 400

    user = User.query.filter_by(username=username).first()
    if user and user.shared_secret_hex:
        return jsonify({"completed": True})

    return jsonify({"completed": False})


@app.route("/login", methods=["GET"])
def page_3():
    username = request.args.get("username", "").strip()
    password = request.args.get("password", "").strip()

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session["saved_username"] = user.username
            session["shared_secret_hex"] = user.shared_secret_hex
            return redirect(url_for("page_4"))

        return render_template("page3.html", error="Invalid username or password.")

    return render_template("page3.html")


@app.route("/2fa", methods=["GET"])
def page_4():
    user_code = request.args.get("code", "").strip()

    if user_code:
        shared_secret = _get_shared_secret()
        if not shared_secret:
            return render_template(
                "page4.html",
                error="No shared secret — please complete sign-up exchange first.",
            )

        if totp.verify_otp(shared_secret, user_code):
            session["authenticated"] = True
            return redirect(url_for("page_5"))

        return render_template("page4.html", error="Incorrect code. Please try again.")

    return render_template("page4.html")


@app.route("/success")
def page_5():
    if not session.get("authenticated"):
        return redirect(url_for("page_1"))
    return render_template("page5.html", username=session.get("saved_username", "User"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("page_1"))


if __name__ == "__main__":
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        _start_mtls_server()
    app.run()

