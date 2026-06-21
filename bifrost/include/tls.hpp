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

#include <TypeDefs.hpp>
#include <bits/stdc++.h>
#include <cstring>
#include <securebytes.hpp>
#include <string>

#define SERVER_HOST "localhost"
#define SERVER_PORT 8443
#define SERVER_REG_PATH "/signup/"
#define SERVER_RESPONSE_PREFIX "pwKey:"

struct ConnContext {
        SecureBytes exporterSecret;
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

Bytes establishTOTPKey(std::string serverRegCode, size_t totpKeyLen);
