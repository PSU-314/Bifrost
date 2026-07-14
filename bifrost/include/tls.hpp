// mTLS client for Bifrost's registration handshake: builds a hardened
// SSL_CTX (TLS 1.2-1.3, pinned cipher suites, client cert), performs the
// handshake with hostname/IP verification, exports per-connection key
// material via RFC 5705, and drives the HTTP-over-TLS registration exchange
// that yields a new Key from a bifrost-totp:// URL.

#pragma once

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
#include <bifrost.hpp>
#include <cstring>
#include <securebytes.hpp>
#include <string>

// ---------------------------------------------------------------------------
// Protocol / key-derivation constants.
//
// TOTP_HKDF_INFO_STR: the info label fed into HKDF on both this client and
// the Python server.  Defined as string_view so the Bytes initialiser below
// picks up exactly 16 bytes — no hidden null terminator from sizeof(char[]).
//
// EXPORTER_SECRET_LABEL: used with SSL_export_keying_material (RFC 5705 /
// RFC 8446 §7.5).  Both sides call export_keying_material with the same label
// and receive an identical value, unlike the raw EXPORTER_SECRET from the
// keylog which Python cannot access.
// ---------------------------------------------------------------------------
inline constexpr size_t EXPORTER_SECRET_SIZE = 48;
inline constexpr std::string_view TOTP_HKDF_INFO_STR{"bifrost-totp-key"};
inline constexpr std::string_view EXPORTER_SECRET_LABEL{"bifrost-ms"};

// Byte sequence built once at startup, reused for every HKDF call.
inline const Bytes TOTP_HKDF_INFO(TOTP_HKDF_INFO_STR.begin(),
                                  TOTP_HKDF_INFO_STR.end());

// ---------------------------------------------------------------------------
// ConnContext — carries the per-connection exporter secret derived after the
// handshake; passed from tls_connect to registerBifrost.
// ---------------------------------------------------------------------------
struct ConnContext {
        SecureBytes exporterSecret;
};

// ---------------------------------------------------------------------------
// ConnInfo — parsed form of a bifrost-totp:// URL.
// ---------------------------------------------------------------------------
struct ConnInfo {
        std::string host;
        uint16_t port;
        std::string path; // e.g. "/signup/123456"
};

// ---------------------------------------------------------------------------
// ServerRegData — payload returned by the registration endpoint.
// ---------------------------------------------------------------------------
struct ServerRegData {
        SecureBytes KEY;      // server's TOTP seed contribution
        std::string ACC_INFO; // human-readable account identifier
};

// ─── Exception helper ───────────────────────────────────────────────────────
// Drain the OpenSSL error queue and throw a runtime_error with all messages
// chained into one string.
void throw_ssl_error(const std::string &context);

// ─── SSL_CTX factory ────────────────────────────────────────────────────────
// Build a fully configured client context: TLS 1.2–1.3 only, pinned cipher
// suites, server-cert verification against ca_cert, and client cert for mTLS.
SSL_CTX *create_client_ctx(const fs::path &ca_cert,
                           const fs::path &client_chain,
                           const fs::path &client_key);

// ─── Raw TCP connection ─────────────────────────────────────────────────────
int connect_tcp(const std::string &host, uint16_t port);

// ─── TLS handshake + hostname verification ──────────────────────────────────
// Performs the handshake, verifies the server certificate, and populates
// connCtx.exporterSecret via SSL_export_keying_material.
SSL *tls_connect(SSL_CTX *ctx, int tcp_fd, const std::string &hostname,
                 ConnContext &connCtx);

// ─── Secure send / recv ─────────────────────────────────────────────────────
void tls_send(SSL *ssl, const void *data, size_t len);
std::string tls_recv(SSL *ssl, size_t max_bytes = 4096);

// ─── Teardown ───────────────────────────────────────────────────────────────
void tls_shutdown(SSL *ssl, int tcp_fd);

// ─── Registration helpers ───────────────────────────────────────────────────
ServerRegData fetchServerRegData(SSL *ssl, int tcp_fd, const std::string &host,
                                 const std::string &path);

ConnInfo getConnInfo(std::string_view serverArgs);

Key registerBifrost(const ConnInfo &connInfo);
