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

// constexpr char TOTP_HKDF_INFO_[]{"bifrost-totp-key"};
// constexpr char EXPORTER_SECRET_LABEL[]{"EXPORTER_SECRET bifrost-totp v1"};
constexpr size_t EXPORTER_SECRET_SIZE = 48;
// const Bytes TOTP_HKDF_INFO(TOTP_HKDF_INFO_,
//                            TOTP_HKDF_INFO_ + sizeof(TOTP_HKDF_INFO_));

// BUG 5 FIX: Use a Bytes literal (not a char array via sizeof) so there is no
// hidden null terminator.  Both sides now agree on exactly 16 info bytes.
constexpr std::string_view TOTP_HKDF_INFO_STR{"bifrost-totp-key"};
const Bytes TOTP_HKDF_INFO(TOTP_HKDF_INFO_STR.begin(),
                           TOTP_HKDF_INFO_STR.end());

// BUG 6 FIX: Agreed exporter label used by SSL_export_keying_material() on the
// C++ side and conn.export_keying_material() on the Python side.  Both RFC 5705
// (TLS 1.2) and RFC 8446 §7.5 (TLS 1.3) derive the same value given the same
// label, so this is always consistent — unlike the raw EXPORTER_SECRET from the
// keylog, which is an intermediate key-schedule secret that Python cannot
// access.
constexpr std::string_view EXPORTER_SECRET_LABEL{"bifrost-ms"};

struct ConnContext {
        SecureBytes exporterSecret;
};

// BUG 3 FIX: Added 'path' field so getConnInfo can return the full HTTP path
// (/signup/<pin>) for use by fetchServerRegData, instead of discarding it.
struct ConnInfo {
        std::string host;
        uint16_t port;
        std::string path; // e.g. "/signup/123456"
};

struct ServerRegData {
        SecureBytes KEY;
        std::string ACC_INFO;
};

// ─── Exception helper
// ─────────────────────────────────────────────────────────

static void throw_ssl_error(const std::string &context);

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

// ─── Registration helpers
// ─────────────────────────────────────────────────────

// BUG 1+2 FIX: now receives the full path so it can build a correct HTTP GET.
ServerRegData fetchServerRegData(SSL *ssl, int tcp_fd, const std::string &host,
                                 const std::string &path);

ConnInfo getConnInfo(const std::string_view &serverArgs);

Key registerBifrost(const ConnInfo &connInfo);
