#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <KeyStore.hpp>
#include <TypeDefs.hpp>
#include <bits/stdc++.h>
#include <cstring>
#include <securebytes.hpp>
#include <string>

constexpr char TOTP_HKDF_INFO_[]{"bifrost-totp-key"};
const Bytes TOTP_HKDF_INFO(TOTP_HKDF_INFO_,
                           TOTP_HKDF_INFO_ + sizeof(TOTP_HKDF_INFO_));

struct ConnContext {
        SecureBytes exporterSecret;
};

struct ConnInfo {
        std::string host;
        uint16_t port;
};

struct ServerRegData {
        SecureBytes KEY;
        std::string ACC_INFO;
};

// ─── Exception helper
// ─────────────────────────────────────────────────────────

static void throw_ssl_error(const std::string &context);

static void keylog_callback(const SSL *ssl, const char *line);

// ─── SSL_CTX factory
// ──────────────────────────────────────────────────────────

SSL_CTX *create_client_ctx(
    const char *ca_cert,      //
    const char *client_chain, // client/client-chain.pem  (leaf + intermediate)
    const char *client_key);  // client/client.key

// ─── Raw TCP connection
// ───────────────────────────────────────────────────────

int connect_tcp(const std::string &host, uint16_t port);

// ─── TLS handshake + hostname verification
// ────────────────────────────────────

SSL *tls_connect(SSL_CTX *ctx, int tcp_fd, const std::string &hostname,
                 ConnContext &connCtx);

// ─── Secure send / recv
// ───────────────────────────────────────────────────────

void tls_send(SSL *ssl, const void *data, size_t len);

std::string tls_recv(SSL *ssl, size_t max_bytes = 4096);

// ─── Teardown
// ─────────────────────────────────────────────────────────────────

void tls_shutdown(SSL *ssl, int tcp_fd);

// ─── main
// ─────────────────────────────────────────────────────────────────────
ServerRegData fetchServerRegData(SSL *ssl, int tcp_fd, const std::string host);

ConnInfo getConnInfo(const std::string_view &serverArgs);

Key registerBifrost(const ConnInfo &connInfo);
