// Core shared types and filesystem-path resolution for Bifrost. Defines the
// Byte/Bytes aliases used throughout the codebase, the well-known filenames
// under Bifrost's config directory, and the Paths helper that resolves them
// to full, platform-appropriate paths (XDG on Linux, Application Support on
// macOS, %APPDATA% on Windows).

#pragma once

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#include <shlobj.h>
#include <windows.h>
#endif

namespace fs = std::filesystem;

using Byte = uint8_t;
using Bytes = std::vector<Byte>;

inline constexpr std::string_view APP_DIR_NAME{"bifrost"};
inline constexpr std::string_view CERTS_DIR_NAME{"certs"};
inline constexpr std::string_view DEFAULT_KEYFILE{"totp-secrets.keys"};
inline constexpr std::string_view ROOT_CA_CERT{"root-ca.crt"};
inline constexpr std::string_view BIFROST_CERT_CHAIN{"bifrost-chain.pem"};
inline constexpr std::string_view BIFROST_KEY{"bifrost.key"};
inline constexpr std::string_view BIFROST_PROTOCOL{"bifrost-totp://"};

// ---------------------------------------------------------------------------
// Paths — static helper that resolves all well-known filesystem locations.
// Path components are constexpr string_views; std::filesystem's operator/
// joins them into full paths.
// ---------------------------------------------------------------------------
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
            if (!fs::exists(certsDir()) || !fs::exists(rootCACert()) ||
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
