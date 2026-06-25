#include <cstdint>
#include <limits>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <securebytes.hpp>
#include <totp.hpp>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <KDF.hpp>
#include <KeyStore.hpp>
#include <bifrost.hpp>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <tls.hpp>
#include <utility.hpp>

// ─── Exception helper
// ─────────────────────────────────────────────────────────

void throw_ssl_error(const std::string &context) {
    std::string msg = context;
    unsigned long err;
    bool first = true;
    char buf[256];

    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        msg += first ? ": " : " <- ";
        msg += buf;
        first = false;
    }
    if (first)
        msg += ": (no OpenSSL error queue entry)";

    throw std::runtime_error(msg);
}

// ─── SSL_CTX factory
// ──────────────────────────────────────────────────────────
SSL_CTX *create_client_ctx(const fs::path ca_cert, const fs::path client_chain,
                           const fs::path client_key) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        throw_ssl_error("SSL_CTX_new");

    // ── Version floor: TLS 1.2 ───────────────────────────────────────────────
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
        throw_ssl_error("set_min_proto_version");

    if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1)
        throw_ssl_error("set_max_proto_version");

    // ── Cipher suite pinning (TLS 1.2) ───────────────────────────────────────
    if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:"
                                     "ECDHE-RSA-AES256-GCM-SHA384:"
                                     "ECDHE-ECDSA-AES128-GCM-SHA256:"
                                     "ECDHE-RSA-AES128-GCM-SHA256:"
                                     "ECDHE-ECDSA-CHACHA20-POLY1305:"
                                     "ECDHE-RSA-CHACHA20-POLY1305") != 1)
        throw_ssl_error("set_cipher_list");

    // ── TLS 1.3 suites ───────────────────────────────────────────────────────
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:"
                                      "TLS_CHACHA20_POLY1305_SHA256:"
                                      "TLS_AES_128_GCM_SHA256") != 1)
        throw_ssl_error("set_ciphersuites");

    // ── Server certificate verification ──────────────────────────────────────
    if (SSL_CTX_load_verify_locations(ctx, ca_cert.c_str(), nullptr) != 1)
        throw_ssl_error("load_verify_locations (root CA)");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(ctx, 2);

    // ── Client certificate (mTLS)
    // ─────────────────────────────────────────────
    if (SSL_CTX_use_certificate_chain_file(ctx, client_chain.c_str()) != 1)
        throw_ssl_error("use_certificate_chain_file (client chain)");

    if (SSL_CTX_use_PrivateKey_file(ctx, client_key.c_str(),
                                    SSL_FILETYPE_PEM) != 1)
        throw_ssl_error("use_PrivateKey_file (client key)");

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

SSL *tls_connect(SSL_CTX *ctx, int tcp_fd, const std::string &hostname,
                 ConnContext &connCtx) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
        throw_ssl_error("SSL_new");

    if (SSL_set_tlsext_host_name(ssl, hostname.c_str()) != 1)
        throw_ssl_error("SSL_set_tlsext_host_name (SNI)");

    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(vpm, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

    struct in_addr addr4;
    struct in6_addr addr6;
    bool is_ip = (inet_pton(AF_INET, hostname.c_str(), &addr4) == 1 ||
                  inet_pton(AF_INET6, hostname.c_str(), &addr6) == 1);

    if (is_ip) {
        if (X509_VERIFY_PARAM_set1_ip_asc(vpm, hostname.c_str()) != 1)
            throw_ssl_error("X509_VERIFY_PARAM_set1_ip_asc failed");
    } else if (X509_VERIFY_PARAM_set1_host(vpm, hostname.c_str(),
                                           hostname.size()) != 1)
        throw_ssl_error("X509_VERIFY_PARAM_set1_host");

    if (SSL_set_fd(ssl, tcp_fd) != 1)
        throw_ssl_error("SSL_set_fd");

    if (SSL_connect(ssl) != 1)
        throw_ssl_error("SSL_connect (handshake)");

    std::cout << "[TLS] Version   : " << SSL_get_version(ssl) << "\n";
    std::cout << "[TLS] Cipher    : " << SSL_get_cipher(ssl) << "\n";

    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        SSL_free(ssl);
        throw std::runtime_error(
            std::string("Server cert verification failed: ") +
            X509_verify_cert_error_string(verify_result));
    }

    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert) {
        char subject_buf[256] = {};
        X509_NAME_oneline(X509_get_subject_name(server_cert), subject_buf,
                          sizeof(subject_buf));
        std::cout << "[TLS] Server cert: " << subject_buf << "\n";
        X509_free(server_cert);
    }

    connCtx.exporterSecret.resize(EXPORTER_SECRET_SIZE);
    if (SSL_export_keying_material(
            ssl, connCtx.exporterSecret.data(), EXPORTER_SECRET_SIZE,
            EXPORTER_SECRET_LABEL.data(), EXPORTER_SECRET_LABEL.size(), nullptr,
            0, 0) != 1)
        throw_ssl_error(
            "SSL_export_keying_material failed to extract the exporter secret");

    return ssl;
}

// ─── Secure send / recv
// ───────────────────────────────────────────────────────

void tls_send(SSL *ssl, const void *data, size_t len) {
    if (len > static_cast<size_t>(std::numeric_limits<int>::max()))
        throw std::runtime_error(
            "tls_send: payload exceeds SSL_write's int length limit");

    size_t sent = 0;
    while (sent < len) {
        int chunk = static_cast<int>(std::min(
            len - sent, static_cast<size_t>(std::numeric_limits<int>::max())));
        int n = SSL_write(ssl, static_cast<const char *>(data) + sent, chunk);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            throw_ssl_error("SSL_write failed : " + std::to_string(err));
        }
        sent += static_cast<size_t>(n);
    }
}

std::string tls_recv(SSL *ssl, size_t max_bytes) {
    if (max_bytes > static_cast<size_t>(std::numeric_limits<int>::max()))
        throw std::runtime_error(
            "tls_recv: max_bytes exceeds SSL_read's int length limit");

    std::string buf(max_bytes, '\0');
    int n = SSL_read(ssl, buf.data(), static_cast<int>(max_bytes));
    if (n <= 0) {
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_ZERO_RETURN)
            throw std::runtime_error(
                "SSL_read: peer closed connection (close_notify received)");
        throw_ssl_error("SSL_read failed : " + std::to_string(err));
    }
    buf.resize(static_cast<size_t>(n));
    return buf;
}

// ─── Teardown
// ─────────────────────────────────────────────────────────────────

void tls_shutdown(SSL *ssl, int tcp_fd) {
    int ret = SSL_shutdown(ssl);
    if (ret == 0) {
        ret = SSL_shutdown(ssl);
        if (ret < 0) {
            int err = SSL_get_error(ssl, ret);
            std::cerr << "TLS Shutdown incomplete. SSL error: " << err << "\n";
        }
    }
    SSL_free(ssl);
    close(tcp_fd);
}

// ─── Registration helpers
// ─────────────────────────────────────────────────────

ServerRegData fetchServerRegData(SSL *ssl, int tcp_fd, const std::string &host,
                                 const std::string &path) {
    std::stringstream requestStream;
    requestStream << "GET " << path << " HTTP/1.1\r\n";
    requestStream << "Host: " << host << "\r\n";
    requestStream << "Connection: close\r\n\r\n";
    auto request = requestStream.str();

    tls_send(ssl, request.c_str(), request.length());

    std::string resp = tls_recv(ssl, 4096);

    size_t body_pos = resp.find("\r\n\r\n");
    if (body_pos == std::string::npos) {
        tls_shutdown(ssl, tcp_fd);
        throw std::runtime_error("Server response missing HTTP delimiter");
    }
    std::string body = resp.substr(body_pos + 4);

    auto params = parseURLParams(body, '&', '=');
    if (!params.contains("PW_KEY") || !params.contains("ACC_INFO")) {
        throw std::runtime_error("Server response had missing fields. Body:\n" +
                                 body);
    }

    auto pwkey_bytes = hexToBytes(params["PW_KEY"]);
    SecureBytes pwkey(pwkey_bytes);
    OPENSSL_cleanse(pwkey_bytes.data(), pwkey_bytes.size());
    return {pwkey.clone(), std::string(params["ACC_INFO"])};
}

ConnInfo getConnInfo(const std::string_view &serverArgs) {
    if (!serverArgs.starts_with(BIFROST_PROTOCOL))
        throw std::runtime_error("Trying to connect with an invalid protocol");

    std::string_view urlParams = serverArgs.substr(BIFROST_PROTOCOL.size());
    auto params = parseURLParams(urlParams);
    if (!params.contains("host") || !params.contains("port"))
        throw std::runtime_error("Given URL for registration does not contain "
                                 "required connection information");

    std::string host_raw(params["host"]);
    std::string portstr(params["port"]);

    std::string host, path;
    size_t slash_pos = host_raw.find('/');
    if (slash_pos != std::string::npos) {
        host = host_raw.substr(0, slash_pos);
        path = host_raw.substr(slash_pos);
    } else {
        host = host_raw;
        path = "/";
    }

    auto port_ull = std::stoull(portstr, nullptr, 10);
    if (port_ull > UINT16_MAX)
        throw std::runtime_error("Given URL for registration does not contain "
                                 "a valid port for connection");

    return {host, static_cast<uint16_t>(port_ull), path};
}

Key registerBifrost(const ConnInfo &connInfo) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
    int fd = -1;
    ConnContext connCtx;
    ServerRegData regData;
    Key newKey;

    try {
        ctx = create_client_ctx(Paths::rootCACert(), Paths::certChain(),
                                Paths::privKey());
        fd = connect_tcp(connInfo.host, connInfo.port);
        ssl = tls_connect(ctx, fd, connInfo.host, connCtx);
        // exporterSecret is now populated by tls_connect via
        // SSL_export_keying_material

        // BUG 1+2 FIX: pass connInfo.path so the correct GET path is sent
        regData = fetchServerRegData(ssl, fd, connInfo.host, connInfo.path);

        auto cert = SSL_get0_peer_certificate(ssl);
        newKey = KeyStore::buildKey(cert);
        newKey.accinfo = regData.ACC_INFO;

        // BUG 5 FIX: TOTP_HKDF_INFO is now 16 bytes (no null terminator) —
        // defined via string_view in tls.hpp.  Python passes the same 16 bytes.
        hkdf_sha256(connCtx.exporterSecret, regData.KEY, TOTP_HKDF_INFO,
                    TOTP_KEY_LEN, newKey.secret);

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
        throw std::runtime_error("Could not register bifrost with server");
    }

    SSL_CTX_free(ctx);
    return newKey;
}
