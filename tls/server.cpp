/**
 * server.cpp — mTLS server (mutual TLS — both sides authenticate)
 *
 * Changes from the previous version:
 *   1. mTLS is now MANDATORY, not optional. client_ca is a required argument.
 *      The server refuses to start without it. An auth server that allows
 *      unauthenticated clients is not an auth server.
 *
 *   2. SSL_CTX_set_verify_depth(ctx, 2) added.
 *      Required for a 3-level chain (root → intermediate → leaf).
 *      Without this the verifier stops at depth 1 (intermediate) and never
 *      confirms the root is trusted.
 *
 *   3. Usage string updated: client-ca.pem is now a required 4th argument.
 *
 * Compile:
 *   g++ -std=c++17 server.cpp -o server -lssl -lcrypto -lpthread
 *
 * Run:
 *   ./server 8443 server/server-chain.pem server/server.key root-ca/root-ca.crt
 *
 * server-chain.pem = cat server/server.crt intermediate-ca/intermediate-ca.crt
 */

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <bits/stdc++.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

static std::atomic<bool> g_running{true};
using Byte = uint8_t;
using Bytes = std::vector<Byte>;
Bytes exporterSecret;

// ─── Exception helper
// ─────────────────────────────────────────────────────────

static void throw_ssl_error(const std::string &ctx) {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    throw std::runtime_error(ctx + ": " + buf);
}

static void setExporterBytes(const SSL *ssl, const char *line) {
    (void)ssl;

    std::string s(line);
    auto first_sp = s.find(' ');
    auto second_sp = s.find(' ', first_sp + 1);

    if (first_sp == std::string::npos || second_sp == std::string::npos)
        return;

    std::string label = s.substr(0, first_sp);
    if (label != "EXPORTER_SECRET")
        return;
    std::string secret_hex = s.substr(second_sp + 1);
    if (secret_hex.size() % 2 != 0) {
        std::cerr << "[KeyLog] Malformed hex string (odd length)\n";
        return;
    }

    exporterSecret.resize(secret_hex.size() / 2);
    for (size_t i = 0; i < secret_hex.size(); i += 2) {
        char byte_str[3] = {secret_hex[i], secret_hex[i + 1], '\0'};
        unsigned long byte_val = std::strtoul(byte_str, nullptr, 16);
        exporterSecret[i / 2] = (Byte)byte_val;
    }
}

// ─── SSL_CTX factory
// ──────────────────────────────────────────────────────────

/**
 * @param cert_pem   server/server-chain.pem
 *                   (leaf cert + intermediate CA concatenated — root excluded)
 * @param key_pem    server/server.key  (chmod 600)
 * @param client_ca  root-ca/root-ca.crt
 *                   mTLS is mandatory. The root CA that signed the
 *                   intermediate that signed client.crt.
 */
SSL_CTX *create_server_ctx(const char *cert_pem, const char *key_pem,
                           const char *client_ca) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        throw_ssl_error("SSL_CTX_new");

    // ── Version floor: TLS 1.2 ───────────────────────────────────────────────
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
        throw_ssl_error("set_min_proto_version");

    // Ceiling: library maximum (allows TLS 1.3 when both sides support it).
    if (SSL_CTX_set_max_proto_version(ctx, 0) != 1)
        throw_ssl_error("set_max_proto_version");

    // ── Cipher suite pinning (TLS 1.2) ───────────────────────────────────────
    // ECDHE only (forward secrecy) + AEAD only.
    // Eliminates CBC, static RSA key transport, RC4, 3DES, NULL, export suites.
    if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:"
                                     "ECDHE-RSA-AES256-GCM-SHA384:"
                                     "ECDHE-ECDSA-AES128-GCM-SHA256:"
                                     "ECDHE-RSA-AES128-GCM-SHA256:"
                                     "ECDHE-ECDSA-CHACHA20-POLY1305:"
                                     "ECDHE-RSA-CHACHA20-POLY1305") != 1)
        throw_ssl_error("set_cipher_list");

    // ── TLS 1.3 suites
    // ────────────────────────────────────────────────────────
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:"
                                      "TLS_CHACHA20_POLY1305_SHA256:"
                                      "TLS_AES_128_GCM_SHA256") != 1)
        throw_ssl_error("set_ciphersuites");

    // ── ECDH curve selection
    // ────────────────────────────────────────────────── X25519: fastest,
    // constant-time in OpenSSL, no small-subgroup risk.
    if (SSL_CTX_set1_curves_list(ctx, "X25519:P-256:P-384") != 1)
        throw_ssl_error("set1_curves_list");

    // ── Server certificate chain
    // ────────────────────────────────────────────── Loads the leaf cert AND
    // every intermediate that follows it in the PEM. The full chain is sent in
    // the TLS Certificate message so the client can build the trust path
    // without external fetches.
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_pem) != 1)
        throw_ssl_error("use_certificate_chain_file");

    if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1)
        throw_ssl_error("use_PrivateKey_file");

    // Confirm cert and key are a matched pair — catches argument mistakes
    // at startup rather than at the first handshake.
    if (SSL_CTX_check_private_key(ctx) != 1)
        throw_ssl_error("check_private_key");

    // ── Mutual TLS — MANDATORY
    // ──────────────────────────────────────────────── Load the trust anchor
    // used to verify client certificates.
    if (SSL_CTX_load_verify_locations(ctx, client_ca, nullptr) != 1)
        throw_ssl_error("load_verify_locations (client CA)");

    // SSL_VERIFY_PEER                  — send CertificateRequest to client.
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT  — abort handshake if client sends no
    // cert.
    //   Without the second flag, a client that ignores CertificateRequest
    //   is silently accepted.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       nullptr);

    // ── Verify depth ─────────────────────────────────────────────────────────
    // MUST be 2 for a root → intermediate → leaf chain.
    //   depth 0 = client leaf cert
    //   depth 1 = intermediate CA
    //   depth 2 = root CA (trust anchor)
    // Depth 1 (the old default) stops the walk at the intermediate and never
    // confirms the root is trusted — the chain walk is incomplete.
    SSL_CTX_set_verify_depth(ctx, 2);

    // Tell the client which CA names we accept in the CertificateRequest
    // message — helps clients with multiple certs pick the right one.
    STACK_OF(X509_NAME) *ca_list = SSL_load_client_CA_file(client_ca);
    if (!ca_list)
        throw_ssl_error("SSL_load_client_CA_file");
    SSL_CTX_set_client_CA_list(ctx, ca_list); // ctx takes ownership

    // ── Security options
    // ────────────────────────────────────────────────────── NO_TICKET:
    // stateless session tickets can allow replayed sessions, bypassing
    // per-connection client cert verification on an auth channel.
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

    // NO_COMPRESSION: CRIME attack recovers secrets from TLS-compressed data.
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    // CIPHER_SERVER_PREFERENCE: server's cipher order wins, not the client's.
    // Ensures AES-256-GCM is chosen even if the client prefers AES-128-GCM.
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    SSL_CTX_set_keylog_callback(ctx, setExporterBytes);

    return ctx;
}

// ─── Per-connection handler
// ───────────────────────────────────────────────────

void handle_connection(SSL *ssl, int client_fd, std::string peer_addr) {
    std::cout << "[" << peer_addr << "] Connection accepted\n";

    // ── TLS handshake
    // ─────────────────────────────────────────────────────────
    if (SSL_accept(ssl) != 1) {
        std::cerr << "[" << peer_addr << "] Handshake failed: ";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    std::cout << "[" << peer_addr << "] TLS version : " << SSL_get_version(ssl)
              << "\n";
    std::cout << "[" << peer_addr << "] Cipher      : " << SSL_get_cipher(ssl)
              << "\n";

    // ── Inspect and verify client certificate ────────────────────────────────
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT guarantees a cert is present here,
    // but we check defensively anyway.
    X509 *client_cert = SSL_get_peer_certificate(ssl);
    if (!client_cert) {
        std::cerr << "[" << peer_addr
                  << "] BUG: no client cert after handshake\n";
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    char subject_buf[256] = {};
    X509_NAME_oneline(X509_get_subject_name(client_cert), subject_buf,
                      sizeof(subject_buf));
    std::cout << "[" << peer_addr << "] Client cert : " << subject_buf << "\n";

    // Confirm the full chain was verified (depth 0 → 1 → 2).
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        std::cerr << "[" << peer_addr << "] Client cert verification failed: "
                  << X509_verify_cert_error_string(verify_result) << "\n";
        X509_free(client_cert);
        SSL_free(ssl);
        close(client_fd);
        return;
    }
    std::cout << "[" << peer_addr << "] Client cert verification: OK\n";
    X509_free(client_cert);

    // ── Application data loop (echo — replace with TOTP protocol logic)
    // ─────── CRYPTO_memcmp for constant-time token comparisons.
    // OPENSSL_cleanse to wipe buffers — defeats compiler elision of memset.
    // char buf[4096];
    // while (true) {
    //     int n = SSL_read(ssl, buf, static_cast<int>(sizeof(buf) - 1));
    //
    //     if (n <= 0) {
    //         int err = SSL_get_error(ssl, n);
    //         if (err == SSL_ERROR_ZERO_RETURN)
    //             std::cout << "[" << peer_addr
    //                       << "] Client disconnected cleanly\n";
    //         else
    //             std::cerr << "[" << peer_addr << "] SSL_read error: " << err
    //                       << "\n";
    //         break;
    //     }
    //
    //     buf[n] = '\0';
    //     std::cout << "[" << peer_addr << "] Received (" << n
    //               << " bytes): " << buf << "\n";
    //
    //     int sent = 0;
    //     while (sent < n) {
    //         int w = SSL_write(ssl, buf + sent, n - sent);
    //         if (w <= 0) {
    //             std::cerr << "[" << peer_addr << "] SSL_write error\n";
    //             goto done;
    //         }
    //         sent += w;
    //     }
    //
    //     OPENSSL_cleanse(buf, static_cast<size_t>(n));
    // }

    std::cout << "Exporter Secret: " << std::hex << std::setfill('0');
    for (auto x : exporterSecret)
        std::cout << std::setw(2) << (int)x;
    std::cout << std::dec << std::endl;
    std::string buf =
        "8a2bbe3940bbb4092cc176d91c846cb29c253932c8f34d56431f20ad20d8cdf4";
    int sent = 0;
    while (sent < buf.size()) {
        int w = SSL_write(ssl, buf.data() + sent, buf.size() - sent);
        if (w <= 0) {
            std::cerr << "[" << peer_addr << "] SSL_write error\n";
            goto done;
        }
        sent += w;
    }

done:
    // ── Bidirectional shutdown
    // ──────────────────────────────────────────────── First call sends our
    // close_notify. Return value 0 means peer's close_notify hasn't arrived —
    // call again to wait for it. Skipping leaves the channel open to truncation
    // attacks.
    {
        int ret = SSL_shutdown(ssl);
        if (ret == 0)
            SSL_shutdown(ssl);
    }

    SSL_free(ssl);
    close(client_fd);
    std::cout << "[" << peer_addr << "] Connection closed\n";
}

// ─── TCP listener
// ─────────────────────────────────────────────────────────────

int create_listener(uint16_t port) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0)
        throw std::runtime_error("socket()");

    // Dual-stack: accepts both IPv4-mapped and IPv6 clients on one socket.
    int off = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

    // SO_REUSEADDR: avoids waiting for TIME_WAIT on restart.
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;

    if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
        throw std::runtime_error("bind() on port " + std::to_string(port));

    if (listen(fd, 128) != 0)
        throw std::runtime_error("listen()");

    return fd;
}

// ─── Signal handler
// ───────────────────────────────────────────────────────────

static void on_signal(int) {
    g_running.store(false, std::memory_order_relaxed);
}

// ─── main
// ─────────────────────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <port> <server-chain.pem> <server.key> <root-ca.crt>\n\n"
                  << "  <port>             e.g. 8443\n"
                  << "  <server-chain.pem> server/server-chain.pem\n"
                  << "                     (server.crt + intermediate-ca.crt "
                     "concatenated)\n"
                  << "  <server.key>       server/server.key\n"
                  << "  <root-ca.crt>      root-ca/root-ca.crt\n"
                  << "                     (trust anchor for verifying client "
                     "certs)\n\n"
                  << "Example:\n  " << argv[0]
                  << " 8443 server/server-chain.pem server/server.key "
                     "root-ca/root-ca.crt\n";
        return 1;
    }

    uint16_t port = static_cast<uint16_t>(std::stoi(argv[1]));
    const char *cert_pem = argv[2];
    const char *key_pem = argv[3];
    const char *client_ca = argv[4];

    // Ignore SIGPIPE — handle write errors via SSL_write return values.
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = nullptr;
    int listen_fd = -1;

    try {
        ctx = create_server_ctx(cert_pem, key_pem, client_ca);
        listen_fd = create_listener(port);

        std::cout << "[Server] Listening on port " << port
                  << " (mTLS — client cert required)\n";

        while (g_running.load(std::memory_order_relaxed)) {
            sockaddr_in6 peer_addr{};
            socklen_t peer_len = sizeof(peer_addr);

            int client_fd = accept(
                listen_fd, reinterpret_cast<sockaddr *>(&peer_addr), &peer_len);
            if (client_fd < 0) {
                if (!g_running.load())
                    break;
                std::cerr << "[Server] accept() failed, continuing\n";
                continue;
            }

            char peer_ip[INET6_ADDRSTRLEN] = {};
            inet_ntop(AF_INET6, &peer_addr.sin6_addr, peer_ip, sizeof(peer_ip));
            std::string peer = std::string(peer_ip) + ":" +
                               std::to_string(ntohs(peer_addr.sin6_port));

            SSL *ssl = SSL_new(ctx);
            if (!ssl) {
                std::cerr << "[" << peer << "] SSL_new failed\n";
                close(client_fd);
                continue;
            }

            if (SSL_set_fd(ssl, client_fd) != 1) {
                std::cerr << "[" << peer << "] SSL_set_fd failed\n";
                SSL_free(ssl);
                close(client_fd);
                continue;
            }

            std::thread(handle_connection, ssl, client_fd, peer).detach();
        }

    } catch (const std::exception &e) {
        std::cerr << "[FATAL] " << e.what() << "\n";
        if (listen_fd >= 0)
            close(listen_fd);
        if (ctx)
            SSL_CTX_free(ctx);
        return 1;
    }

    std::cout << "[Server] Shutting down\n";
    close(listen_fd);
    SSL_CTX_free(ctx);
    return 0;
}
