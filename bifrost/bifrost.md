Project Path: bifrost

Source Tree:

```txt
bifrost
├── CMakeLists.txt
├── bifrost-authentication.desktop
├── cmake
│   ├── CompilerWarnings.cmake
│   ├── Hardening.cmake
│   └── Sanitizers.cmake
├── include
│   ├── KDF.hpp
│   ├── KeyStore.hpp
│   ├── bifrost.hpp
│   ├── securebytes.hpp
│   ├── terminal-launch.hpp
│   ├── tls.hpp
│   ├── totp.hpp
│   └── utility.hpp
├── install.sh
└── src
    ├── KDF.cpp
    ├── KeyStore.cpp
    ├── bifrost.cpp
    ├── terminal-launch.cpp
    ├── tls.cpp
    ├── totp.cpp
    └── utility.cpp

```

`CMakeLists.txt`:

```txt
cmake_minimum_required(VERSION 3.28)

project(bifrost VERSION 2.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
if (NOT OpenSSL_FOUND)
    message(STATUS "OpenSSL not found on system - fetching OpenSSL")
    include(FetchContent)
    FetchContent_Declare(
        openssl_cmake
        GIT_REPOSITORY https://github.com/janbar/openssl-cmake.git
        GIT_TAG        openssl-3.3.2-cmake
    )
    FetchContent_MakeAvailable(openssl_cmake)
endif()

file(GLOB SOURCES "src/*.cpp")

add_library(bifrost_lib STATIC ${SOURCES_WITHOUT_MAIN})
target_include_directories(bifrost_lib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(bifrost_lib PUBLIC
    OpenSSL::Crypto
    OpenSSL::SSL
)

add_executable(${PROJECT_NAME} src/bifrost.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE bifrost_lib)

# enable_testing()
# add_executable(bifrost_tests ${TEST_SOURCES})
# target_link_libraries(bifrost_tests PRIVATE bifrost_lib GTest::gtest_main)
# include(GoogleTest)
# gtest_discover_tests(bifrost_tests)


```
`bifrost-authentication.desktop`:

```desktop
[Desktop Entry]
Version=1.0
Type=Application
Name=Bifrost Authentication
Exec=<WILL BE CHANGED DURING INSTALLATION>
Icon=utilities-terminal
Terminal=false
NoDisplay=true
MimeType=x-scheme-handler/bifrost-totp;

```
`cmake/CompilerWarnings.cmake`:

```cmake
function(set_project_warnings target)
    target_compile_options(${target} PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion
        -Wshadow -Wnon-virtual-dtor -Wold-style-cast
        $<$<CONFIG:Release>:-O2 -DNDEBUG>
        $<$<CONFIG:Debug>:-g -O0>
    )
endfunction()

```
`cmake/Hardening.cmake`:

```cmake
function(set_security_flags target)
    target_compile_options(${target} PRIVATE
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -fPIE
    )
    target_link_options(${target} PRIVATE
        -pie
        -Wl,-z,relro
        -Wl,-z,now
    )
endfunction()

```
`cmake/Sanitizers.cmake`:

```cmake
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_UBSAN "Enable UBSanitizer" OFF)

function(enable_sanitizers target)
    if(ENABLE_ASAN)
        target_compile_options(${target} PRIVATE -fsanitize=address,leak)
        target_link_options(${target}  PRIVATE -fsanitize=address,leak)
    endif()
    if(ENABLE_UBSAN)
        target_compile_options(${target} PRIVATE -fsanitize=undefined)
        target_link_options(${target}  PRIVATE -fsanitize=undefined)
    endif()
endfunction()

```
`include/KDF.hpp`:

```hpp
#pragma once

#include <bifrost.hpp>
#include <securebytes.hpp>

void hkdf_sha256(const SecureBytes &ikm, const SecureBytes &salt,
                 const Bytes &info, size_t outLen, SecureBytes &okm);
void pbkdf2_sha256(const SecureBytes &password, const SecureBytes &salt,
                   int n_iterations, SecureBytes &derived);

```
`include/KeyStore.hpp`:

```hpp
#pragma once

#include <assert.h>
#include <bifrost.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <securebytes.hpp>
#include <unordered_map>
#include <utility.hpp>
#include <vector>

#define KEY_STORE_ENC_KEY_SIZE 32
#define ENC_BLOB_NONCE_SIZE 12
#define ENC_BLOB_TAG_SIZE 16
#define PBKDF2_N_ITERATIONS 310000
#define PBKDF2_SALT_SIZE 16
const Bytes KEY_STORE_SIGNATURE{0x42, 0x4B, 0x53, 0x4D, 0x00, 0x01, 0x00, 0x02};

struct Key {
        std::string accinfo;
        Bytes fingerprint;
        std::string commonName;
        std::vector<std::string> sans;
        SecureBytes secret;

        Key() = default;
        Key(const Key &) = delete;
        Key &operator=(const Key &) = delete;
        Key(Key &&) noexcept = default;
        Key &operator=(Key &&) noexcept = default;

        ~Key() = default;

        size_t size() const;
        Bytes serialize() const;
        static Key deserialize(const Bytes &data);
};

struct EncryptedBlob {
        uint8_t version = 1;
        Bytes nonce;
        Bytes ciphertext;
        Bytes tag;

        size_t size() const;
        Bytes serialize() const;
        static EncryptedBlob deserialize(const Bytes &data);
};

class KeyStore {
    private:
        static SecureBytes _encryptionKey;
        static SecureBytes _salt;
        static std::unordered_map<Bytes, Key, BytesHash> _store;

    public:
        static void init(std::string &password);
        static size_t size();
        static Bytes computeFingerprint(X509 *cert);
        static std::string extractCN(X509_NAME *name);
        static std::vector<std::string> extractSANs(X509 *cert);
        static Key buildKey(X509 *cert);

        static void store(X509 *cert, const std::string &accinfo,
                          SecureBytes &&secret);
        static void store(Key &key);

        static Bytes getUKID(const Key &key);
        static const Key *lookupByUKID(const Bytes &UKID);
        static std::vector<const Key *> lookupByFG(const Bytes &fingerprint);
        static std::vector<const Key *> lookupByCN(const std::string &cn);
        static std::vector<const Key *>
        lookupByAccInfo(const std::string &accinfo);

        static std::vector<const Key *> getAllKeys();

        static void erase(const Bytes &UKID);
        static Bytes serialize();
        static void deserialize(const Bytes &data);
        static EncryptedBlob encryptStore();
        static void decryptStore(const EncryptedBlob &blob);
        static void saveStore();
        static void loadStore();
};

```
`include/bifrost.hpp`:

```hpp
#pragma once

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <vector>

#if defined(_WIN32)
#include <shlobj.h>
#include <windows.h>
#endif

namespace fs = std::filesystem;

using Byte = uint8_t;
using Bytes = std::vector<Byte>;

#define DEFAULT_KEYFILE "totp-secrets.keys"
#define APP_DIR_NAME "bifrost"
#define CERTS_DIR_NAME "certs"

#define ROOT_CA_CERT "root-ca.crt"
#define BIFROST_CERT_CHAIN "bifrost-chain.pem"
#define BIFROST_KEY "bifrost.key"

const std::string BIFROST_PROTOCOL = "bifrost-totp://";

class Paths {
    private:
        inline static std::string _keyfile;

        static std::string getEnvVar(const char *name) {
            const char *val = std::getenv(name);
            if (!val)
                throw std::runtime_error(
                    std::string("Required environment variable not set: ") +
                    name);
            return std::string(val);
        }

    public:
        static void init() {
            auto cnfgdir = configDir();
            auto crtdir = certsDir();
            if (!fs::exists(cnfgdir))
                fs::create_directories(cnfgdir);
            if (!fs::exists(crtdir) || !fs::exists(rootCACert()) ||
                !fs::exists(certChain()) || !fs::exists(privKey()))
                throw std::runtime_error("Missing Certs");

            _keyfile = DEFAULT_KEYFILE;
        }

        static fs::path homeDir() {
#if defined(_WIN32)
            return fs::path(getEnvVar("USERPROFILE"));
#else
            return fs::path(getEnvVar("HOME"));
#endif
        }

        static fs::path configDir() {
#if defined(_WIN32)
            // %APPDATA%\bifrost  (e.g. C:\Users\name\AppData\Roaming\bifrost)
            return fs::path(getEnvVar("APPDATA")) / APP_DIR_NAME;
#elif defined(__APPLE__)
            // ~/Library/Application Support/bifrost
            return homeDir() / "Library/Application Support" / APP_DIR_NAME;
#else
            // ~/.config/bifrost  (XDG convention)
            const char *xdg = std::getenv("XDG_CONFIG_HOME");
            if (xdg && *xdg)
                return fs::path(xdg) / APP_DIR_NAME;
            return homeDir() / ".config" / APP_DIR_NAME;
#endif
        }

        static void setKeyfile(const std::string &file) { _keyfile = file; }
        static fs::path keyfile() { return configDir() / _keyfile; }
        static fs::path certsDir() { return configDir() / CERTS_DIR_NAME; }
        static fs::path rootCACert() { return certsDir() / ROOT_CA_CERT; }
        static fs::path certChain() { return certsDir() / BIFROST_CERT_CHAIN; }
        static fs::path privKey() { return certsDir() / BIFROST_KEY; }
};

```
`include/securebytes.hpp`:

```hpp
#pragma once

#include <bifrost.hpp>
#include <cstddef>
#include <memory>
#include <openssl/crypto.h>

template <typename T> struct SecureAllocator : std::allocator<T> {
        using Base = std::allocator<T>;

        template <typename U> struct rebind {
                using other = SecureAllocator<U>;
        };

        SecureAllocator() noexcept = default;

        template <typename U>
        SecureAllocator(const SecureAllocator<U> &) noexcept {}

        void deallocate(T *p, size_t n) {
            if (p && n > 0)
                OPENSSL_cleanse(p, n * sizeof(T));
            Base::deallocate(p, n);
        }
};
template <typename T, typename U>
bool operator==(const SecureAllocator<T> &,
                const SecureAllocator<U> &) noexcept {
    return true;
}
template <typename T, typename U>
bool operator!=(const SecureAllocator<T> &,
                const SecureAllocator<U> &) noexcept {
    return false;
}

template <typename T> using SecureVector = std::vector<T, SecureAllocator<T>>;

class SecureBytes {
    private:
        SecureVector<Byte> _data;

    public:
        SecureBytes() = default;
        explicit SecureBytes(size_t size)
            : _data(size) {}
        SecureBytes(const uint8_t *ptr, size_t len)
            : _data(ptr, ptr + len) {}
        SecureBytes(const Bytes &data)
            : _data(data.begin(), data.end()) {}

        SecureBytes(const SecureBytes &) = delete;
        SecureBytes &operator=(const SecureBytes &) = delete;

        SecureBytes(SecureBytes &&other) noexcept
            : _data(std::move(other._data)) {}

        SecureBytes &operator=(SecureBytes &&other) noexcept {
            if (this != &other) {
                cleanse();
                _data = std::move(other._data);
            }
            return *this;
        }

        ~SecureBytes() { cleanse(); }

        Byte *data() { return _data.data(); }
        const Byte *data() const { return _data.data(); }
        size_t size() const { return _data.size(); }
        bool empty() const { return _data.empty(); }
        void resize(size_t n) { _data.resize(n); }

        SecureBytes clone() const {
            return SecureBytes(_data.data(), _data.size());
        }

        SecureVector<Byte>::iterator begin() { return _data.begin(); }
        SecureVector<Byte>::iterator end() { return _data.end(); }
        SecureVector<Byte>::const_iterator begin() const {
            return _data.begin();
        }
        SecureVector<Byte>::const_iterator end() const { return _data.end(); }

        void cleanse() {
            if (!_data.empty())
                OPENSSL_cleanse(_data.data(), _data.size());
        }
};

```
`include/terminal-launch.hpp`:

```hpp
#pragma once

#include <string>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <unistd.h>
#endif

const std::string SENTINEL_FLAG = "--__in_terminal__";

// ---------------------------------------------------------------------
// Resolve the path to the currently running executable.
// ---------------------------------------------------------------------
std::string getSelfPath();

// ---------------------------------------------------------------------
// Single-quote-escape a string for safe embedding inside a 'sh -c' arg.
// Standard technique: close quote, insert escaped quote, reopen quote.
// ---------------------------------------------------------------------
std::string shQuote(const std::string &s);

// ---------------------------------------------------------------------
// Launch the current executable inside a visible terminal window,
// re-invoking it with SENTINEL_FLAG + the original argv forwarded.
// ---------------------------------------------------------------------
void launchInTerminal(const std::string &selfPath, int argc, char **argv);

```
`include/tls.hpp`:

```hpp
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

```
`include/totp.hpp`:

```hpp
#pragma once
#include <bifrost.hpp>
#include <securebytes.hpp>
#include <utility.hpp>

#define TIME_WINDOW 30
#define OTP_SIZE 6
#define TOTP_KEY_LEN 32
#define TOTP_DIGEST_SIZE 20

struct TOTP {
        int otp, validity;

        TOTP(int otp, int validity)
            : otp(otp),
              validity(validity) {}
};

Bytes generate_hmac_sha1(const SecureBytes &key, const Bytes &msg);
uint32_t genSample(const SecureBytes &key, std::time_t time);
TOTP generateOTP(const SecureBytes &key);

```
`include/utility.hpp`:

```hpp
#pragma once

#include <bifrost.hpp>
#include <functional>
#include <iostream>
#include <string_view>
#include <unordered_map>

struct BytesHash {
        std::size_t operator()(const Bytes &bytes) const {
            std::string_view sv(reinterpret_cast<const char *>(bytes.data()),
                                bytes.size());
            return std::hash<std::string_view>{}(sv);
        }
};

int hexNibble(char c) noexcept;
void printBytes(std::ostream &stream, const Bytes &bytes, bool shorten = true);
Bytes hexToBytes(std::string_view hex);
std::string bytesToHex(const Bytes &bytes);
Bytes timeToBytes(const std::time_t time);

void writeu32(Bytes &out, uint32_t v);
uint32_t readu32(const Byte *p);
Bytes readField(const Bytes &data, size_t &offset);

void writeAtomic(const fs::path &path, const Bytes &data,
                 uint32_t perms = 0644);
Bytes readAtomic(const fs::path &path);

[[nodiscard]] std::unordered_map<std::string_view, std::string_view>
parseURLParams(const std::string_view url, const char kvDelim = '&',
               const char valDelim = '=');

```
`install.sh`:

```sh
#!/usr/bin/env bash
#
# install.sh — Build and install Bifrost (user-local, no sudo required)
#
# What this does:
#   1. Configures and builds the project with CMake (Release, out-of-source in build/)
#   2. Installs the resulting binary to ~/.local/bin
#   3. Installs the .desktop file to ~/.local/share/applications
#   4. Refreshes the desktop database and registers the bifrost-totp:// scheme
#
# Usage:
#   ./install.sh            # build + install
#   ./install.sh --clean    # wipe build/ first, then build + install
#   ./install.sh --uninstall # remove installed files

set -euo pipefail

# ---- Configuration (edit these to match your repo) -------------------------
PROJECT_NAME="bifrost"
BINARY_NAME="bifrost"          # CMake target / output binary name
DESKTOP_FILE_NAME="bifrost-authentication.desktop"
MIME_SCHEME="x-scheme-handler/bifrost-totp"
BUILD_DIR="build"
BUILD_TYPE="Release"
# ------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_BIN_DIR="$HOME/.local/bin"
INSTALL_DESKTOP_DIR="$HOME/.local/share/applications"
CONFIG_DIR="$HOME/.config/bifrost"

echo "SCRIPT_DIR: $SCRIPT_DIR"

log()  { echo -e "\033[1;34m[install]\033[0m $*"; }
err()  { echo -e "\033[1;31m[error]\033[0m $*" >&2; }

# ---- Uninstall path ----------------------------------------------------
if [[ "${1:-}" == "--uninstall" ]]; then
    log "Removing installed binary, desktop file, configs, and protocol registration..."
    rm -f "$INSTALL_BIN_DIR/$BINARY_NAME"
    rm -f "$INSTALL_DESKTOP_DIR/$DESKTOP_FILE_NAME"
    rm -rf "$CONFIG_DIR"
    update-desktop-database "$INSTALL_DESKTOP_DIR" 2>/dev/null || true
    log "Uninstalled. (xdg-mime default association is left as-is; another app may need to claim the scheme.)"
    exit 0
fi

# ---- Optional clean ------------------------------------------------------
if [[ "${1:-}" == "--clean" ]]; then
    log "Cleaning previous build directory..."
    rm -rf "$SCRIPT_DIR/$BUILD_DIR"
fi

# ---- Sanity checks ---------------------------------------------------------
command -v cmake >/dev/null 2>&1 || { err "cmake not found. Install it first (sudo pacman -S cmake)."; exit 1; }
command -v xdg-mime >/dev/null 2>&1 || { err "xdg-mime not found. Install it first (sudo pacman -S xdg-utils)."; exit 1; }

if [[ ! -f "$SCRIPT_DIR/CMakeLists.txt" ]]; then
    err "No CMakeLists.txt found in $SCRIPT_DIR. Run this script from the project root."
    exit 1
fi

if [[ ! -f "$SCRIPT_DIR/$DESKTOP_FILE_NAME" ]]; then
    err "Desktop file '$DESKTOP_FILE_NAME' not found in $SCRIPT_DIR. Adjust DESKTOP_FILE_NAME at the top of this script."
    exit 1
fi

# ---- Build -------------------------------------------------------------
log "Configuring CMake build ($BUILD_TYPE) in $BUILD_DIR/ ..."
cmake -S "$SCRIPT_DIR" -B "$SCRIPT_DIR/$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE"

log "Building $PROJECT_NAME..."
cmake --build "$SCRIPT_DIR/$BUILD_DIR" --parallel "$(nproc)"

BUILT_BINARY="$SCRIPT_DIR/$BUILD_DIR/$BINARY_NAME"
if [[ ! -f "$BUILT_BINARY" ]]; then
    err "Expected built binary at $BUILT_BINARY but it wasn't found."
    err "Check that BINARY_NAME matches your CMake target's output name."
    exit 1
fi

# ---- Install binary ---------------------------------------------------
log "Installing binary to $INSTALL_BIN_DIR ..."
mkdir -p "$INSTALL_BIN_DIR"
install -m 755 "$BUILT_BINARY" "$INSTALL_BIN_DIR/$BINARY_NAME"

# ---- Install certificates ---------------------------------------------
log "Installing certificates to $CONFIG_DIR/certs ..."

install -d -m 744 "$CONFIG_DIR/certs"

for cert in "$SCRIPT_DIR/certs/"*.crt "$SCRIPT_DIR/certs/"*.pem; do
    if [[ -f "$cert" ]]; then
        install -m 444 "$cert" "$CONFIG_DIR/certs/"
    fi
done

for key in "$SCRIPT_DIR/certs/"*.key; do
    if [[ -f "$key" ]]; then
        install -m 400 "$key" "$CONFIG_DIR/certs/"
    fi
done

# ---- Install desktop file (with path rewritten to the installed binary) ---
log "Installing desktop file to $INSTALL_DESKTOP_DIR ..."
mkdir -p "$INSTALL_DESKTOP_DIR"

# Rewrite the Exec= line so it points at the installed binary location,
# regardless of what path was hardcoded in the source .desktop file.
sed -e "s|^Exec=.*|Exec=$INSTALL_BIN_DIR/$BINARY_NAME %u|" \
    "$SCRIPT_DIR/$DESKTOP_FILE_NAME" > "$INSTALL_DESKTOP_DIR/$DESKTOP_FILE_NAME"

chmod 644 "$INSTALL_DESKTOP_DIR/$DESKTOP_FILE_NAME"

# ---- Validate desktop file (best-effort) -------------------------------
if command -v desktop-file-validate >/dev/null 2>&1; then
    log "Validating desktop file..."
    desktop-file-validate "$INSTALL_DESKTOP_DIR/$DESKTOP_FILE_NAME" || true
fi

# ---- Refresh desktop database and register protocol -----------------------
log "Refreshing desktop database..."
update-desktop-database "$INSTALL_DESKTOP_DIR" 2>/dev/null || true

log "Registering $MIME_SCHEME -> $DESKTOP_FILE_NAME as default handler..."
xdg-mime default "$DESKTOP_FILE_NAME" "$MIME_SCHEME"

log "Done."
echo
echo "  Binary:       $INSTALL_BIN_DIR/$BINARY_NAME"
echo "  Desktop file: $INSTALL_DESKTOP_DIR/$DESKTOP_FILE_NAME"
echo "  Protocol:     $MIME_SCHEME"
echo
echo "Test with:  xdg-open 'bifrost-totp://test'"
echo "Uninstall:  ./install.sh --uninstall"

```
`src/KDF.cpp`:

```cpp
#include <KDF.hpp>
#include <bifrost.hpp>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/sha.h>
#include <stdexcept>

void hkdf_sha256(const SecureBytes &ikm, const SecureBytes &salt,
                 const Bytes &info, size_t outLen, SecureBytes &okm) {
    okm.resize(outLen);

    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) {
        throw std::runtime_error("Failed to fetch HKDF implementation");
    }

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) {
        throw std::runtime_error("Failed to create KDF context");
    }

    OSSL_PARAM params[5];
    size_t i = 0;

    char md_name[] = "SHA256";
    params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                   md_name, sizeof(md_name));
    params[i++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<uint8_t *>(ikm.data()), ikm.size());
    params[i++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, const_cast<uint8_t *>(salt.data()), salt.size());
    params[i++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, const_cast<uint8_t *>(info.data()), info.size());
    params[i++] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, okm.data(), okm.size(), params) <= 0) {
        EVP_KDF_CTX_free(ctx);
        throw std::runtime_error("HKDF key derivation failed");
    }

    EVP_KDF_CTX_free(ctx);
}

void pbkdf2_sha256(const SecureBytes &password, const SecureBytes &salt,
                   const int n_iterations, SecureBytes &derived) {
    derived.resize(SHA256_DIGEST_LENGTH);
    if (PKCS5_PBKDF2_HMAC((const char *)password.data(), (int)password.size(),
                          salt.data(), (int)salt.size(), n_iterations,
                          EVP_sha256(), (int)derived.size(),
                          derived.data()) != 1)
        throw std::runtime_error("PBKDF2 Failed");
}

```
`src/KeyStore.cpp`:

```cpp
#include "bifrost.hpp"
#include <KDF.hpp>
#include <KeyStore.hpp>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <ranges>
#include <securebytes.hpp>
#include <stdexcept>
#include <utility.hpp>

size_t Key::size() const {
    size_t s = 4 + accinfo.size() + 4 + fingerprint.size() + 4 +
               commonName.size() + 4 + secret.size() + 4;
    for (const auto &san : sans)
        s += 4 + san.size();
    return s;
}

Bytes Key::serialize() const {
    Bytes data;
    data.reserve(size());

    writeu32(data, static_cast<uint32_t>(accinfo.size()));
    data.insert(data.end(), accinfo.begin(), accinfo.end());

    writeu32(data, static_cast<uint32_t>(fingerprint.size()));
    data.insert(data.end(), fingerprint.begin(), fingerprint.end());

    writeu32(data, static_cast<uint32_t>(commonName.size()));
    data.insert(data.end(), commonName.begin(), commonName.end());

    writeu32(data, static_cast<uint32_t>(sans.size()));
    for (const auto &san : sans) {
        writeu32(data, static_cast<uint32_t>(san.size()));
        data.insert(data.end(), san.begin(), san.end());
    }

    writeu32(data, static_cast<uint32_t>(secret.size()));
    data.insert(data.end(), secret.begin(), secret.end());

    return data;
}

Key Key::deserialize(const Bytes &data) {
    size_t offset = 0;
    Key key;

    Bytes accinfo = readField(data, offset);
    key.accinfo.assign(accinfo.begin(), accinfo.end());
    key.fingerprint = readField(data, offset);
    Bytes cn = readField(data, offset);
    key.commonName.assign(cn.begin(), cn.end());

    if (offset + 4 > data.size())
        throw std::runtime_error("Truncated SAN count");
    uint32_t sanCount = readu32(data.data() + offset);
    offset += 4;

    constexpr uint32_t MaxSansCount = 1000;
    if (sanCount > MaxSansCount)
        throw std::runtime_error("Implausible SAN count");

    key.sans.reserve(sanCount);
    for (uint32_t i = 0; i < sanCount; i++) {
        Bytes san = readField(data, offset);
        key.sans.emplace_back(san.begin(), san.end());
    }

    key.secret = readField(data, offset);

    if (offset != data.size())
        throw std::runtime_error("Trailing bytes after deserialization");

    return key;
}

// ========================================================================================

size_t EncryptedBlob::size() const {
    //     version            cipherSize
    return 1 + nonce.size() + 4 + ciphertext.size() + tag.size();
}

Bytes EncryptedBlob::serialize() const {
    Bytes out;
    out.reserve(4 + size());

    out.push_back(version);
    out.insert(out.end(), nonce.begin(), nonce.end());

    uint32_t cipherSize = ciphertext.size();
    writeu32(out, cipherSize);
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());

    out.insert(out.end(), tag.begin(), tag.end());

    return out;
}

EncryptedBlob EncryptedBlob::deserialize(const Bytes &data) {
    EncryptedBlob blob;
    constexpr size_t headerSize =
        1 + ENC_BLOB_NONCE_SIZE + 4 + ENC_BLOB_TAG_SIZE;

    if (data.empty())
        throw std::runtime_error("Could not deserialize blob: empty data");
    blob.version = data[0];
    if (blob.version != 1)
        throw std::runtime_error(
            "Could not deserialize blob: unsupported version");
    if (data.size() < headerSize)
        throw std::runtime_error("Could not deserialize blob");

    blob.nonce =
        Bytes(data.begin() + 1, data.begin() + 1 + ENC_BLOB_NONCE_SIZE);
    uint32_t cipherSize = readu32(data.data() + 1 + ENC_BLOB_NONCE_SIZE);

    if (cipherSize > data.size() - headerSize)
        throw std::runtime_error("cipherSize exceeds available buffer");
    if (data.size() != headerSize + cipherSize)
        throw std::runtime_error(
            "Could not deserialize blob: cipherSize exceeds available buffer");

    auto cipherStart = data.begin() + 1 + ENC_BLOB_NONCE_SIZE + 4;
    blob.ciphertext = Bytes(cipherStart, cipherStart + cipherSize);
    blob.tag = Bytes(cipherStart + cipherSize, data.end());

    return blob;
}

// ========================================================================================

SecureBytes KeyStore::_encryptionKey;
SecureBytes KeyStore::_salt;
std::unordered_map<Bytes, Key, BytesHash> KeyStore::_store;

void KeyStore::init(std::string &password) {
    SecureBytes passwd((const Byte *)password.data(), password.size());

    _salt.resize(PBKDF2_SALT_SIZE);
    bool keyfileExists = fs::exists(Paths::keyfile());

    if (keyfileExists) {
        std::ifstream keyfile(Paths::keyfile(), std::ios::binary);
        keyfile.read((char *)_salt.data(), PBKDF2_SALT_SIZE);
    } else
        RAND_bytes(_salt.data(), PBKDF2_SALT_SIZE);

    pbkdf2_sha256(passwd, _salt, PBKDF2_N_ITERATIONS, _encryptionKey);
    OPENSSL_cleanse(password.data(), password.size());

    if (keyfileExists)
        loadStore();
}

size_t KeyStore::size() {
    size_t s = 4;
    for (const auto &[fp, key] : _store)
        s += 4 + key.size();
    return s;
}

Bytes KeyStore::computeFingerprint(X509 *cert) {
    unsigned char *der;
    int derLen = i2d_X509(cert, &der);
    if (derLen < 0 || !der)
        throw std::runtime_error("Failed to DER-encode certificate");

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx || EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, der, derLen) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest, &digestLen) != 1) {
        if (mdctx)
            EVP_MD_CTX_free(mdctx);
        OPENSSL_free(der);
        throw std::runtime_error("Failed to compute certificate fingerprint");
    }
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(der);
    return Bytes(digest, digest + digestLen);
}

std::string KeyStore::extractCN(X509_NAME *name) {
    int len = X509_NAME_get_text_by_NID(name, NID_commonName, nullptr, 0);
    if (len < 0)
        return "";
    std::string buf(static_cast<size_t>(len) + 1, '\0');
    int written = X509_NAME_get_text_by_NID(name, NID_commonName, buf.data(),
                                            static_cast<int>(buf.size()));
    if (written < 0)
        return "";
    buf.resize(static_cast<size_t>(written));
    return buf;
}

std::vector<std::string> KeyStore::extractSANs(X509 *cert) {
    std::vector<std::string> result;
    GENERAL_NAMES *gens = static_cast<GENERAL_NAMES *>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (!gens)
        return result;

    for (int i = 0; i < sk_GENERAL_NAME_num(gens); ++i) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(gens, i);
        if (gen->type == GEN_DNS) {
            ASN1_STRING *dns = gen->d.dNSName;
            result.emplace_back(
                reinterpret_cast<const char *>(ASN1_STRING_get0_data(dns)),
                ASN1_STRING_length(dns));
        }
    }
    GENERAL_NAMES_free(gens);
    return result;
}

Key KeyStore::buildKey(X509 *cert) {
    Key key;

    key.fingerprint = computeFingerprint(cert);
    key.commonName = extractCN(X509_get_subject_name(cert));
    key.sans = extractSANs(cert);

    return key;
}

void KeyStore::store(X509 *cert, const std::string &accinfo,
                     SecureBytes &&secret) {
    Key key = buildKey(cert);
    key.secret = std::move(secret);
    key.accinfo = accinfo;
    Bytes ukid = getUKID(key);
    _store[ukid] = std::move(key);
}

void KeyStore::store(Key &key) {
    Bytes ukid = getUKID(key);
    _store[ukid] = std::move(key);
}

Bytes KeyStore::getUKID(const Key &key) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx || EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, key.accinfo.c_str(), key.accinfo.size()) != 1 ||
        EVP_DigestUpdate(mdctx, key.fingerprint.data(),
                         key.fingerprint.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest, &digestLen) != 1) {
        if (mdctx)
            EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to compute UKID");
    }
    EVP_MD_CTX_free(mdctx);
    return Bytes(digest, digest + digestLen);
}

const Key *KeyStore::lookupByUKID(const Bytes &UKID) {
    auto itr = _store.find(UKID);
    return itr != _store.end() ? &itr->second : nullptr;
}

std::vector<const Key *> KeyStore::lookupByFG(const Bytes &fingerprint) {
    std::vector<const Key *> matches;
    for (auto &[ukid, key] : _store) {
        if (CRYPTO_memcmp(key.fingerprint.data(), fingerprint.data(),
                          fingerprint.size()) == 0)
            matches.push_back(&key);
    }
    return matches;
}

std::vector<const Key *> KeyStore::lookupByCN(const std::string &cn) {
    std::vector<const Key *> matches;
    for (auto &[fp, key] : _store) {
        if (key.commonName == cn)
            matches.push_back(&key);
    }
    return matches;
}

std::vector<const Key *> KeyStore::lookupByAccInfo(const std::string &accinfo) {
    std::vector<const Key *> matches;
    for (auto &[fp, key] : _store) {
        if (key.accinfo == accinfo)
            matches.push_back(&key);
    }
    return matches;
}

std::vector<const Key *> KeyStore::getAllKeys() {
    std::vector<const Key *> keys;
    for (const auto &[fp, key] : _store)
        keys.push_back(&key);
    return keys;
}

void KeyStore::erase(const Bytes &UKID) {
    auto it = _store.find(UKID);
    if (it != _store.end())
        _store.erase(it);
}

Bytes KeyStore::serialize() {
    Bytes out;
    out.reserve(size());

    writeu32(out, _store.size());

    for (const auto &[fp, key] : _store) {
        Bytes k = key.serialize();
        uint32_t keySize = key.size();
        writeu32(out, keySize);
        out.insert(out.end(), k.begin(), k.end());
    }

    return out;
}

void KeyStore::deserialize(const Bytes &data) {
    _store.clear();

    if (data.size() < 4)
        throw std::runtime_error("Truncated KeyStore data: missing key count");
    uint32_t nKeys = readu32(data.data());
    size_t offset = 4;
    for (uint32_t i = 0; i < nKeys; i++) {
        if (data.size() < 4 + offset)
            throw std::runtime_error(
                "Truncated KeyStore: missing key size field");
        uint32_t keySize = readu32(data.data() + offset);
        if (data.size() < offset + 4 + keySize)
            throw std::runtime_error(
                "Cannot deserialize KeyStore: invalid data given");
        Key k = Key::deserialize(Bytes(data.begin() + offset + 4,
                                       data.begin() + offset + 4 + keySize));
        offset += 4 + keySize;
        Bytes ukid = getUKID(k);
        _store[ukid] = std::move(k);
    }
    if (offset != data.size())
        throw std::runtime_error(
            "Trailing bytes after KeyStore deserialization");
}

EncryptedBlob KeyStore::encryptStore() {
    EncryptedBlob blob;
    blob.nonce.resize(ENC_BLOB_NONCE_SIZE);
    if (RAND_bytes(blob.nonce.data(), ENC_BLOB_NONCE_SIZE) != 1)
        throw std::runtime_error("RAND_bytes failed to generate nonce");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           _encryptionKey.data(), blob.nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    blob.ciphertext.resize(KEY_STORE_SIGNATURE.size() + size());
    Bytes plaintext, storeSerial = serialize();
    plaintext.reserve(KEY_STORE_SIGNATURE.size() + size());
    plaintext.insert(plaintext.end(), KEY_STORE_SIGNATURE.begin(),
                     KEY_STORE_SIGNATURE.end());
    plaintext.insert(plaintext.end(), storeSerial.begin(), storeSerial.end());

    int outlen, finallen;
    if (EVP_EncryptUpdate(ctx, blob.ciphertext.data(), &outlen,
                          plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    if (EVP_EncryptFinal_ex(ctx, blob.ciphertext.data() + outlen, &finallen) !=
        1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    blob.tag.resize(ENC_BLOB_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ENC_BLOB_TAG_SIZE,
                            blob.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    return blob;
}

void KeyStore::decryptStore(const EncryptedBlob &blob) {
    if (blob.nonce.size() != ENC_BLOB_NONCE_SIZE)
        throw std::runtime_error("Invalid nonce size in encrypted blob");
    if (blob.tag.size() != ENC_BLOB_TAG_SIZE)
        throw std::runtime_error("Invalid tag size in encrypted blob");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("Failed to create cipher context");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           _encryptionKey.data(), blob.nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    Bytes plaintext(blob.ciphertext.size());
    int outlen = 0, finallen = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen,
                          blob.ciphertext.data(),
                          static_cast<int>(blob.ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(blob.tag.size()),
                            const_cast<uint8_t *>(blob.tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set GCM tag");
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &finallen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw std::runtime_error(
            "Decryption failed: authentication tag mismatch "
            "(data corrupted, tampered, or wrong key)");
    }

    plaintext.resize(outlen + finallen);

    if (plaintext.size() < KEY_STORE_SIGNATURE.size() ||
        CRYPTO_memcmp(plaintext.data(), KEY_STORE_SIGNATURE.data(),
                      KEY_STORE_SIGNATURE.size()) != 0) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw std::runtime_error(
            "Decrypted data missing expected store signature");
    }

    Bytes serialized(plaintext.begin() + KEY_STORE_SIGNATURE.size(),
                     plaintext.end());

    OPENSSL_cleanse(plaintext.data(), plaintext.size());

    deserialize(serialized);
}

void KeyStore::saveStore() {
    EncryptedBlob eb = encryptStore();
    Bytes ebSerial = eb.serialize();
    Bytes storeData;
    storeData.reserve(PBKDF2_SALT_SIZE + ebSerial.size());
    storeData.insert(storeData.end(), _salt.begin(), _salt.end());
    storeData.insert(storeData.end(), ebSerial.begin(), ebSerial.end());
    writeAtomic(Paths::keyfile(), storeData);
}

void KeyStore::loadStore() {
    Bytes storeData = readAtomic(Paths::keyfile());
    Bytes ebSerial(storeData.begin() + PBKDF2_SALT_SIZE, storeData.end());
    EncryptedBlob eb = EncryptedBlob::deserialize(ebSerial);
    decryptStore(eb);
}

```
`src/bifrost.cpp`:

```cpp
#include <KeyStore.hpp>
#include <algorithm>
#include <bifrost.hpp>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <iomanip>
#include <ios>
#include <iostream>
#include <limits>
#include <openssl/sha.h>
#include <securebytes.hpp>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <terminal-launch.hpp>
#include <tls.hpp>
#include <totp.hpp>
#include <unistd.h>
#include <utility.hpp>

namespace fs = std::filesystem;

void printProgressBar(float percentage, int totalLen) {
    percentage = std::clamp(percentage, 0.0f, 1.0f);
    std::cout << "[";
    int nFilled = static_cast<int>(percentage * totalLen);
    for (int i = 0; i < nFilled; i++)
        std::cout << "#";
    for (int i = 0; i < totalLen - nFilled; i++)
        std::cout << "-";
    std::cout << "]";
}

void unlockBifrost() {
    Bytes encKey;
    if (fs::exists(Paths::keyfile()))
        std::cout << "Enter Bifrost password: ";
    else
        std::cout << "Setup Bifrost password: ";

    std::string passwd;
    std::cin >> passwd;

    try {
        KeyStore::init(passwd);
    } catch (const std::runtime_error &e) {
        std::cerr << "Incorrect password! KeyStore Decryption failed\n"
                  << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {
    bool inTerminal =
        (argc > 1 && std::strcmp(argv[1], SENTINEL_FLAG.c_str()) == 0);

    if (!inTerminal) {
        std::string selfPath;
        try {
            selfPath = getSelfPath();
        } catch (const std::exception &e) {
            std::fprintf(stderr, "%s\n", e.what());
            return EXIT_FAILURE;
        }

#if defined(_WIN32)
        launchInTerminal(selfPath, argc, argv);
        return EXIT_SUCCESS;
#else
        pid_t pid = fork();
        if (pid == -1) {
            std::perror("fork failed");
            return EXIT_FAILURE;
        }
        if (pid == 0)
            launchInTerminal(selfPath, argc, argv);
        return EXIT_SUCCESS;
#endif
    }

    Paths::init();
    unlockBifrost();
    std::cout << "\n";

    // Bytes fg = hexToBytes(
    //     "1d5b3b8ab3ef69cc680d105be88aec702125b7eba47e58ac630e2277b35be03a");
    // Key k;
    // k.accinfo = "ntronyx";
    // k.fingerprint = fg;
    // k.commonName = "test2";
    // k.sans.push_back("san3");
    // k.sans.push_back("san4");
    // k.secret = SecureBytes(hexToBytes("a615e4c7ab8ac4530ff1160f138c881b"));
    // KeyStore::store(k);
    // KeyStore::saveStore();
    // return 0;

    if (argc > 2) {
        ConnInfo connInfo = getConnInfo(argv[2]);
        std::cout << "Connecting to\nHost: " << connInfo.host
                  << "\nPort: " << connInfo.port << "\n"
                  << std::endl;
        auto key = registerBifrost(connInfo);
        KeyStore::store(key);
        KeyStore::saveStore();
        std::cout << "\n\n Press Enter to continue...";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
    }

    auto keys = KeyStore::getAllKeys();

    while (true) {
        std::cout << "\033[2J\033[1;1H" << std::flush;
        std::cout << "Current Keys: " << std::endl;
        for (auto key : keys) {
            std::cout << "Account: " << key->accinfo << "\n";
            std::cout << "    Server CN: " << key->commonName << "\n";
            std::cout << "    fingerprint: ";
            printBytes(std::cout, key->fingerprint);
            std::cout << "\n    SANs: ";
            for (auto s : key->sans)
                std::cout << s << " ";
            std::cout << std::endl;
            auto [otp, validity] = generateOTP(key->secret);
            std::cout << "    TOTP: " << std::setfill('0')
                      << std::setw(OTP_SIZE) << otp << std::endl;
            std::cout << "    Validity: " << validity << "s\n    ";
            printProgressBar((float)validity / TIME_WINDOW, 30);
            std::cout << std::endl << std::endl;
        }
        std::cout << std::endl;
        usleep(500000);
    }
}

```
`src/terminal-launch.cpp`:

```cpp
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <terminal-launch.hpp>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <unistd.h>
#endif

// ---------------------------------------------------------------------
// Resolve the path to the currently running executable.
// ---------------------------------------------------------------------
std::string getSelfPath() {
#if defined(_WIN32)
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (len == 0 || len == MAX_PATH)
        throw std::runtime_error(
            "GetModuleFileNameA failed to resolve self path");
    return std::string(buf, len);

#elif defined(__APPLE__)
    char buf[4096];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) != 0)
        throw std::runtime_error("_NSGetExecutablePath buffer too small");
    return std::string(buf);

#else
    char buf[4096];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len == -1) {
        std::perror("readlink(/proc/self/exe) failed");
        throw std::runtime_error("readlink failed to resolve self path");
    }
    buf[len] = 0;
    return std::string(buf);
#endif
}

// ---------------------------------------------------------------------
// Single-quote-escape a string for safe embedding inside a 'sh -c' arg.
// Standard technique: close quote, insert escaped quote, reopen quote.
// ---------------------------------------------------------------------
std::string shQuote(const std::string &s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'')
            out += "'\\''";
        else
            out.push_back(c);
    }
    out += "'";
    return out;
}

// ---------------------------------------------------------------------
// Launch the current executable inside a visible terminal window,
// re-invoking it with SENTINEL_FLAG + the original argv forwarded.
// ---------------------------------------------------------------------
void launchInTerminal(const std::string &selfPath, int argc, char **argv) {
#if defined(_WIN32)
    // Build: cmd /K ""selfPath" --__in_terminal__ "arg1" "arg2" ..."
    std::string inner = "\"" + selfPath + "\" " + SENTINEL_FLAG;
    for (int i = 1; i < argc; i++)
        inner += " \"" + std::string(argv[i]) + "\"";

    std::string cmdLine = "cmd.exe /K \"" + inner + "\"";

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    if (!CreateProcessA(
            nullptr,
            cmdLine.data(), // mutable buffer required by CreateProcessA
            nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &si,
            &pi)) {
        std::fprintf(stderr,
                     "Failed to launch terminal (CreateProcess error %lu)\n",
                     GetLastError());
        exit(EXIT_FAILURE);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    exit(EXIT_SUCCESS);

#elif defined(__APPLE__)
    // Build a properly-quoted shell command, then drive Terminal.app via
    // AppleScript.
    std::string shellCmd = shQuote(selfPath) + " " + SENTINEL_FLAG;
    for (int i = 1; i < argc; i++)
        shellCmd += " " + shQuote(argv[i]);

    // Escape for embedding inside the AppleScript double-quoted string.
    std::string escaped;
    for (char c : shellCmd) {
        if (c == '\\' || c == '"')
            escaped.push_back('\\');
        escaped.push_back(c);
    }

    std::string osa =
        "tell application \"Terminal\" to do script \"" + escaped + "\"";

    execlp("osascript", "osascript", "-e", osa.c_str(), (char *)nullptr);
    std::perror("Failed to exec osascript");
    exit(EXIT_FAILURE);

#else
    // Linux/BSD: properly quote each arg, try a list of terminal emulators
    // in order, falling back if the first choice isn't installed.
    std::string innerCmd = shQuote(selfPath) + " " + SENTINEL_FLAG;
    for (int i = 1; i < argc; i++)
        innerCmd += " " + shQuote(argv[i]);
    innerCmd += "; exec bash";

    static const char *terminals[] = {
        "x-terminal-emulator", "gnome-terminal", "konsole",    "xfce4-terminal",
        "alacritty",           "kitty",          "terminator", "xterm"};

    for (const char *term : terminals) {
        std::string sep = (std::strcmp(term, "gnome-terminal") == 0 ||
                           std::strcmp(term, "terminator") == 0)
                              ? "--"
                              : "-e";

        // Separate argv entries: term, sep, "bash", "-c", innerCmd
        execlp(term, term, sep.c_str(), "bash", "-c", innerCmd.c_str(),
               (char *)nullptr);
        // execlp only returns on failure — try the next terminal
    }

    std::perror("Failed to exec any terminal emulator");
    exit(EXIT_FAILURE);
#endif
}

```
`src/tls.cpp`:

```cpp
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

static void throw_ssl_error(const std::string &context) {
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

```
`src/totp.cpp`:

```cpp
#include <math.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <securebytes.hpp>
#include <stdexcept>
#include <totp.hpp>
#include <utility.hpp>

// TODO:
// SECURITY ISSUE: SHA1 is deprecated. Consider using SHA256
Bytes generate_hmac_sha1(const SecureBytes &key, const Bytes &msg) {
    Bytes hash(TOTP_DIGEST_SIZE);
    unsigned int len = 0;

    if (!HMAC(EVP_sha1(), key.data(), key.size(),
              reinterpret_cast<const unsigned char *>(msg.data()), msg.size(),
              hash.data(), &len))
        throw std::runtime_error("HMAC-SHA1 computaion failed");
    if (len != TOTP_DIGEST_SIZE)
        throw std::runtime_error("Unexpected HMAC-SHA1 output length");

    return hash;
}

uint32_t genSample(const SecureBytes &key, std::time_t time) {
    Bytes hash = generate_hmac_sha1(key, timeToBytes(time));
    Byte offset = hash.back() & 0x0F;
    int32_t sample = (hash[offset] << 24) | (hash[offset + 1] << 16) |
                     (hash[offset + 2] << 8) | hash[offset + 3];
    sample &= 0x7FFFFFFF;
    return sample;
}

TOTP generateOTP(const SecureBytes &key) {
    std::time_t epoch = std::time(nullptr);
    std::time_t curtime = epoch / TIME_WINDOW;

    int otp = genSample(key, curtime) % (uint32_t)std::pow(10, OTP_SIZE);
    int validity = TIME_WINDOW - epoch % TIME_WINDOW;
    return {otp, validity};
}

```
`src/utility.cpp`:

```cpp
#include <bifrost.hpp>
#include <fcntl.h>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <utility.hpp>
using namespace fs;

int hexNibble(char c) noexcept {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

void printBytes(std::ostream &stream, const Bytes &bytes, bool shorten) {
    if (bytes.size() == 0)
        return;
    stream << "[" << bytes.size() << "]: ";
    if (shorten) {
        for (size_t i = 0; i < 4; i++)
            stream << std::hex << ((bytes[i] & 0xF0) >> 4) << (bytes[i] & 0x0F);
        stream << std::dec << "..[" << bytes.size() - 8 << "]..";
        for (size_t i = bytes.size() - 4; i < bytes.size(); i++)
            stream << std::hex << ((bytes[i] & 0xF0) >> 4) << (bytes[i] & 0x0F);
    } else {
        for (Byte b : bytes)
            stream << std::hex << ((b & 0xF0) >> 4) << (b & 0x0F);
    }
    stream << std::dec;
}

Bytes hexToBytes(std::string_view hex) {
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex.remove_prefix(2);
    }

    if (hex.size() % 2 != 0)
        throw std::runtime_error("Given hex string has odd number of literals");

    Bytes bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        int high_nibble = hexNibble(hex[i]);
        int low_nibble = hexNibble(hex[i + 1]);

        if (high_nibble == -1 || low_nibble == -1)
            throw std::runtime_error("Given hex string has invalid characters");

        bytes.push_back(static_cast<uint8_t>((high_nibble << 4) | low_nibble));
    }

    return bytes;
}

std::string bytesToHex(const Bytes &bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (Byte b : bytes)
        ss << std::setw(2) << static_cast<int>(b);
    return ss.str();
}

Bytes timeToBytes(const std::time_t time) {
    Bytes bytes(8);
    uint64_t t = static_cast<uint64_t>(time);
    for (int b = 7; b >= 0; b--) {
        bytes[b] = static_cast<Byte>(t & 0xFF);
        t >>= 8;
    }

    return bytes;
}

void writeu32(Bytes &out, uint32_t v) {
    out.push_back(static_cast<Byte>(v & 0xFF));
    out.push_back(static_cast<Byte>((v >> 8) & 0xFF));
    out.push_back(static_cast<Byte>((v >> 16) & 0xFF));
    out.push_back(static_cast<Byte>((v >> 24) & 0xFF));
}

uint32_t readu32(const Byte *p) {
    return static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1] << 8) |
           static_cast<uint32_t>(p[2] << 16) |
           static_cast<uint32_t>(p[3] << 24);
}

Bytes readField(const Bytes &data, size_t &offset) {
    if (offset + 4 > data.size())
        throw std::runtime_error("Truncated length prefix");
    uint32_t len = readu32(data.data() + offset);
    offset += 4;

    if (len > data.size() - offset)
        throw std::runtime_error("Field length exceeds remaining buffer");

    Bytes field(data.begin() + offset, data.begin() + offset + len);
    offset += len;
    return field;
}

void writeAtomic(const fs::path &path, const Bytes &data, uint32_t perms) {
    fs::path tmp(path.string() + ".tmp");

    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, perms);
    if (fd < 0)
        throw std::runtime_error("Failed to open tmp file for atomic write: " +
                                 tmp.string());

    ssize_t written = ::write(fd, data.data(), data.size());
    if (written < 0 || static_cast<size_t>(written) != data.size()) {
        ::close(fd);
        throw std::runtime_error(
            "Failed to write to tmp file for atomic write");
    }

    if (::fsync(fd) != 0) {
        ::close(fd);
        throw std::runtime_error("fsync failed on tmp file");
    }
    ::close(fd);

    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec)
        throw std::runtime_error("Atomic rename failed");

    int dirfd = ::open(path.parent_path().c_str(), O_RDONLY);
    if (dirfd >= 0) {
        ::fsync(dirfd);
        ::close(dirfd);
    }
}

Bytes readAtomic(const fs::path &path) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0)
        throw std::runtime_error("Failed to open file for atomic read: " +
                                 path.string());

    std::error_code ec;
    uintmax_t size = fs::file_size(path, ec);
    if (ec) {
        ::close(fd);
        throw std::runtime_error("Failed to stat file for atomic read: " +
                                 path.string());
    }

    Bytes data;
    if (size > 0)
        data.resize(static_cast<size_t>(size));

    size_t total = 0;
    while (total < data.size()) {
        ssize_t n = ::read(fd, data.data() + total, data.size() - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            ::close(fd);
            throw std::runtime_error("Failed to read file for atomic read: " +
                                     path.string());
        }
        if (n == 0)
            break; // file shrank concurrently; stop at actual EOF
        total += static_cast<size_t>(n);
    }
    data.resize(total);

    ::close(fd);
    return data;
}

[[nodiscard]] std::unordered_map<std::string_view, std::string_view>
parseURLParams(const std::string_view url, const char kvDelim,
               const char valDelim) {
    std::unordered_map<std::string_view, std::string_view> params;
    size_t pos = 0;
    const size_t size = url.size();

    while (pos < size) {
        size_t nextPair = url.find(kvDelim, pos);
        if (nextPair == std::string_view::npos)
            nextPair = size;

        std::string_view segment = url.substr(pos, nextPair - pos);
        size_t eqPos = segment.find(valDelim);
        if (eqPos != std::string_view::npos)
            params[segment.substr(0, eqPos)] = segment.substr(eqPos + 1);
        else if (!segment.empty())
            params[segment] = {};

        pos = nextPair + 1;
    }
    return params;
}

```