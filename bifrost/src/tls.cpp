/**
 * client.cpp — mTLS client (mutual TLS — both sides authenticate)
 *
 * Changes from the previous version:
 *   1. Replaced SSL_CTX_set_default_verify_paths() with
 *      SSL_CTX_load_verify_locations() pointed at your root CA.
 *      The system CA bundle is irrelevant for a private PKI and would
 *      accept any publicly trusted cert as a valid server cert.
 *
 *   2. Added SSL_CTX_use_certificate_chain_file() +
 * SSL_CTX_use_PrivateKey_file() to load the client cert chain and key. The
 * chain file is client-chain.pem = client.crt + intermediate-ca.crt. Sending
 * only client.crt leaves the server unable to verify the issuer.
 *
 *   3. Added SSL_CTX_set_verify_depth(ctx, 2) — same reasoning as the server.
 *
 *   4. main() updated to connect to localhost:8443 and present the TOTP
 *      auth channel identity instead of example.com.
 *
 * Compile:
 *   g++ -std=c++17 client.cpp -o client -lssl -lcrypto
 *
 * Run:
 *   ./client
 *
 * File layout expected (relative to cwd):
 *
 *   client/client-chain.pem     (client.crt + intermediate-ca.crt concatenated)
 *   client/client.key
 */

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <HKDF.hpp>
#include <TypeDefs.hpp>
#include <bits/stdc++.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <tls.hpp>
#include <utility.hpp>

static Bytes exporterSecret;

// ─── Exception helper
// ─────────────────────────────────────────────────────────

static void throw_ssl_error(const std::string &context) {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    throw std::runtime_error(context + ": " + buf);
}

static void setExporterSecret(const SSL *ssl, const char *line) {
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

SSL_CTX *create_client_ctx(
    const char *ca_cert,      //
    const char *client_chain, // client/client-chain.pem  (leaf + intermediate)
    const char *client_key)   // client/client.key
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        throw_ssl_error("SSL_CTX_new");

    // ── Version floor: TLS 1.2 ───────────────────────────────────────────────
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
        throw_ssl_error("set_min_proto_version");

    if (SSL_CTX_set_max_proto_version(ctx, 0) != 1)
        throw_ssl_error("set_max_proto_version");

    // ── Cipher suite pinning (TLS 1.2) ───────────────────────────────────────
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

    // ── Server certificate verification ──────────────────────────────────────
    // Point at your private root CA, NOT the system store.
    // Using set_default_verify_paths() would accept any cert signed by any
    // publicly trusted CA — an attacker with a Let's Encrypt cert could MITM.
    if (SSL_CTX_load_verify_locations(ctx, ca_cert, nullptr) != 1)
        throw_ssl_error("load_verify_locations (root CA)");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    // ── Verify depth ─────────────────────────────────────────────────────────
    // Must be 2 for root → intermediate → leaf.
    SSL_CTX_set_verify_depth(ctx, 2);

    // ── Client certificate (mTLS)
    // ───────────────────────────────────────────── Load the client certificate
    // chain. The chain file must contain the leaf cert followed by the
    // intermediate CA cert (root is excluded). Using just client.crt here is
    // the most common mTLS mistake — the server receives a leaf cert whose
    // issuer it cannot find, causing error 20 "unable to get local issuer
    // certificate".
    if (SSL_CTX_use_certificate_chain_file(ctx, client_chain) != 1)
        throw_ssl_error("use_certificate_chain_file (client chain)");

    if (SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) != 1)
        throw_ssl_error("use_PrivateKey_file (client key)");

    // Confirm the chain cert and key are a matched pair.
    if (SSL_CTX_check_private_key(ctx) != 1)
        throw_ssl_error("check_private_key (client)");

    // ── ECDH curve selection
    // ──────────────────────────────────────────────────
    if (SSL_CTX_set1_curves_list(ctx, "X25519:P-256:P-384") != 1)
        throw_ssl_error("set1_curves_list");

    // ── Security options
    // ──────────────────────────────────────────────────────
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    // -- Register keylog callback
    SSL_CTX_set_keylog_callback(ctx, setExporterSecret);

    return ctx;
}

// ─── Raw TCP connection
// ───────────────────────────────────────────────────────

int connect_tcp(const std::string &host, uint16_t port) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int err =
        getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);
    if (err != 0)
        throw std::runtime_error(std::string("getaddrinfo: ") +
                                 gai_strerror(err));

    int fd = -1;
    for (addrinfo *p = res; p != nullptr; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0)
        throw std::runtime_error("TCP connect failed: " + host);
    return fd;
}

// ─── TLS handshake + hostname verification
// ────────────────────────────────────

SSL *tls_connect(SSL_CTX *ctx, int tcp_fd, const std::string &hostname) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
        throw_ssl_error("SSL_new");

    // SNI: send the hostname in ClientHello so the server selects the correct
    // certificate when hosting multiple names on one IP.
    if (SSL_set_tlsext_host_name(ssl, hostname.c_str()) != 1)
        throw_ssl_error("SSL_set_tlsext_host_name (SNI)");

    // Hostname verification: enforces that the server cert's SAN matches the
    // hostname we connected to. Without this, any valid CA-signed cert suffices
    // for MITM. X509_VERIFY_PARAM_set1_host checks SAN only — CN is deprecated.
    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(vpm, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (X509_VERIFY_PARAM_set1_host(vpm, hostname.c_str(), hostname.size()) !=
        1)
        throw_ssl_error("X509_VERIFY_PARAM_set1_host");

    if (SSL_set_fd(ssl, tcp_fd) != 1)
        throw_ssl_error("SSL_set_fd");

    if (SSL_connect(ssl) != 1)
        throw_ssl_error("SSL_connect (handshake)");

    std::cout << "[TLS] Version   : " << SSL_get_version(ssl) << "\n";
    std::cout << "[TLS] Cipher    : " << SSL_get_cipher(ssl) << "\n";

    // Post-handshake paranoia check — SSL_connect should have already aborted
    // on a bad chain, but make the failure mode explicit.
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        SSL_free(ssl);
        throw std::runtime_error(
            std::string("Server cert verification failed: ") +
            X509_verify_cert_error_string(verify_result));
    }

    // Print the server's identity for audit logging.
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert) {
        char subject_buf[256] = {};
        X509_NAME_oneline(X509_get_subject_name(server_cert), subject_buf,
                          sizeof(subject_buf));
        std::cout << "[TLS] Server cert: " << subject_buf << "\n";
        X509_free(server_cert);
    }

    return ssl;
}

// ─── Secure send / recv
// ───────────────────────────────────────────────────────

void tls_send(SSL *ssl, const void *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = SSL_write(ssl, static_cast<const char *>(data) + sent,
                          static_cast<int>(len - sent));
        if (n <= 0)
            throw_ssl_error("SSL_write");
        sent += static_cast<size_t>(n);
    }
}

std::string tls_recv(SSL *ssl, size_t max_bytes) {
    std::string buf(max_bytes, '\0');
    int n = SSL_read(ssl, buf.data(), static_cast<int>(max_bytes));
    if (n <= 0)
        throw_ssl_error("SSL_read");
    buf.resize(static_cast<size_t>(n));
    return buf;
}

// ─── Teardown
// ─────────────────────────────────────────────────────────────────

void tls_shutdown(SSL *ssl, int tcp_fd) {
    // Two-phase shutdown: send close_notify, wait for peer's close_notify.
    // Prevents truncation attacks where an attacker closes TCP early.
    int ret = SSL_shutdown(ssl);
    if (ret == 0)
        SSL_shutdown(ssl);

    SSL_free(ssl);
    close(tcp_fd);
}

// ─── main
// ─────────────────────────────────────────────────────────────────────
Bytes fetchPWKey(SSL *ssl, int tcp_fd, std::string serverRegCode) {
    std::string request = "GET " SERVER_REG_PATH + serverRegCode +
                          " HTTP/1.1\r\n"
                          "Host: " +
                          SERVER_HOST +
                          "\r\n"
                          "Connection: close\r\n\r\n";
    std::stringstream requestStream;
    requestStream << "GET " << SERVER_REG_PATH << serverRegCode
                  << " HTTP/1.1\r\n";
    requestStream << "Host: " << SERVER_HOST << "\r\n";
    requestStream << "Connection: close\r\n\r\n";

    tls_send(ssl, request.c_str(), request.length());
    std::string resp = tls_recv(ssl);
    if (!resp.starts_with(SERVER_RESPONSE_PREFIX)) {
        tls_shutdown(ssl, tcp_fd);
        throw std::runtime_error("Server response had invalid prefix");
    }
    return hexToBytes(
        resp.substr(std::string_view(SERVER_RESPONSE_PREFIX).size()));
}

Bytes establishTOTPKey(std::string serverRegCode, size_t totpKeyLen) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
    int fd = -1;
    Bytes totpKey;

    try {
        ctx = create_client_ctx(CA_CERT, BIFROST_CERT_CHAIN, BIFROST_KEY);
        fd = connect_tcp(SERVER_HOST, SERVER_PORT);
        ssl = tls_connect(ctx, fd, SERVER_HOST);

        std::cout << "Exporter Secret: " << std::hex << std::setfill('0');
        for (auto x : exporterSecret)
            std::cout << std::setw(2) << (int)x;
        std::cout << std::dec << std::endl;

        Bytes pwKey = fetchPWKey(ssl, fd, serverRegCode);

        // Perform HKDF
        std::string infoStr = "bifrost-totp-key";
        Bytes info(infoStr.begin(), infoStr.end());
        hkdf_sha256(exporterSecret, pwKey, info, totpKeyLen, totpKey);

        tls_shutdown(ssl, fd);
        ssl = nullptr;
        fd = -1;

    } catch (const std::exception &e) {
        std::cerr << "[FATAL] " << e.what() << "\n";
        if (ssl)
            SSL_free(ssl);
        if (fd >= 0)
            close(fd);
        SSL_CTX_free(ctx);
    }

    SSL_CTX_free(ctx);
    return totpKey;
}
