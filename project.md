Project Path: bifrost

Source Tree: 
```
bifrost
├── CMakeLists.txt
├── bifrost-authentication.desktop.in
├── cmake
│   ├── CompilerWarnings.cmake
│   └── Hardening.cmake
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
├── src
│   ├── CMakeLists.txt
│   ├── KDF.cpp
│   ├── KeyStore.cpp
│   ├── bifrost.cpp
│   ├── terminal-launch.cpp
│   ├── tls.cpp
│   ├── totp.cpp
│   └── utility.cpp
└── tests
    ├── CMakeLists.txt
    ├── test_framework.hpp
    ├── test_kdf.cpp
    ├── test_totp.cpp
    └── test_utility.cpp

```

`CMakeLists.txt`:

   1 | cmake_minimum_required(VERSION 3.28)
   2 | 
   3 | project(bifrost VERSION 2.0 LANGUAGES CXX)
   4 | 
   5 | set(CMAKE_CXX_STANDARD 20)
   6 | set(CMAKE_CXX_STANDARD_REQUIRED ON)
   7 | set(CMAKE_CXX_EXTENSIONS OFF)
   8 | set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
   9 | 
  10 | find_package(Threads REQUIRED)
  11 | find_package(OpenSSL 3.0 REQUIRED)
  12 | 
  13 | include(CheckIPOSupported)
  14 | check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
  15 | 
  16 | list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
  17 | include(CompilerWarnings)
  18 | include(Hardening)
  19 | 
  20 | include(GNUInstallDirs)
  21 | 
  22 | 
  23 | option(BIFROST_BUILD_TESTS "Build the Bifrost test suite" ON)
  24 | if (BIFROST_BUILD_TESTS)
  25 |     enable_testing()
  26 | endif()
  27 | 
  28 | add_subdirectory(src)
  29 | 
  30 | if (BIFROST_BUILD_TESTS)
  31 |     add_subdirectory(tests)
  32 | endif()
  33 | 
  

`bifrost-authentication.desktop.in`:

   1 | [Desktop Entry]
   2 | Version=2.0
   3 | Type=Application
   4 | Name=Bifrost Authentication
   5 | Exec=@CMAKE_INSTALL_PREFIX@/@CMAKE_INSTALL_BINDIR@/bifrost %u
   6 | Icon=utilities-terminal
   7 | Terminal=false
   8 | NoDisplay=true
   9 | MimeType=x-scheme-handler/bifrost-totp;
  

`cmake/CompilerWarnings.cmake`:

   1 | function(set_project_warnings target)
   2 |     target_compile_options(${target} PRIVATE
   3 |         -Wall
   4 |         -Wextra
   5 |         -Wpedantic
   6 |         -Wconversion
   7 |         -Wshadow
   8 |         -Wformat=2
   9 |         -Wundef
  10 |         -Wnon-virtual-dtor
  11 |         -Wold-style-cast
  12 |         -Wcast-align
  13 |         -Woverloaded-virtual
  14 |     )
  15 | endfunction()
  

`cmake/Hardening.cmake`:

   1 | option(ENABLE_SANITIZERS "Enable ASAN and UBSAN for debugging" OFF)
   2 | 
   3 | function(set_security_flags target)
   4 |     get_target_property(_type ${target} TYPE)
   5 | 
   6 |     # -fPIC for libraries, -fPIE for executables.
   7 |     if(_type STREQUAL "EXECUTABLE")
   8 |         set(_pie_flag -fPIE)
   9 |     else()
  10 |         set(_pie_flag -fPIC)
  11 |     endif()
  12 | 
  13 |     target_compile_options(${target} PRIVATE
  14 |         ${_pie_flag}
  15 |         -fstack-protector-strong
  16 |         # -D_FORTIFY_SOURCE=3 requires glibc >= 2.35 and optimisation enabled;
  17 |         # use =2 as the portable baseline. _FORTIFY_SOURCE has no effect without
  18 |         # at least -O1, so guard it to non-Debug configurations only.
  19 |         $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>
  20 |         -D_GLIBCXX_ASSERTIONS
  21 |         # -fstack-clash-protection: GCC and Clang >= 11 on Linux/x86; not
  22 |         # supported on Apple Clang before Xcode 15 or on ARM macOS.
  23 |         $<$<AND:$<NOT:$<PLATFORM_ID:Darwin>>,$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>>:-fstack-clash-protection>
  24 |     )
  25 | 
  26 |     # Linker hardening: apply only to executables.
  27 |     # -Wl,-z,* are GNU ld / lld-on-Linux flags; they are unknown to Apple ld64.
  28 |     if(_type STREQUAL "EXECUTABLE")
  29 |         if(APPLE)
  30 |             target_link_options(${target} PRIVATE
  31 |                 # BIND_NOW equivalent on Mach-O: resolve all symbols at load.
  32 |                 -Wl,-bind_at_load
  33 |                 # PIE: required for ASLR participation on macOS.
  34 |                 -Wl,-pie
  35 |             )
  36 |         else()
  37 |             # Linux/GNU: full RELRO + BIND_NOW + NX stack + PIE.
  38 |             target_link_options(${target} PRIVATE
  39 |                 -pie
  40 |                 -Wl,-z,relro
  41 |                 -Wl,-z,now
  42 |                 -Wl,-z,noexecstack
  43 |             )
  44 |         endif()
  45 |     endif()
  46 | 
  47 |     # Sanitizers: debug builds only. Guard with a real CMake boolean, not a
  48 |     # generator expression inside if() (which always evaluates truthy as a
  49 |     # non-empty string).
  50 |     if(ENABLE_SANITIZERS)
  51 |         target_compile_options(${target} PRIVATE
  52 |             $<$<CONFIG:Debug>:-fsanitize=address,undefined>
  53 |             $<$<CONFIG:Debug>:-fno-omit-frame-pointer>
  54 |         )
  55 |         target_link_options(${target} PRIVATE
  56 |             $<$<CONFIG:Debug>:-fsanitize=address,undefined>
  57 |         )
  58 |     endif()
  59 | endfunction()
  

`include/KDF.hpp`:

   1 | #pragma once
   2 | 
   3 | #include <bifrost.hpp>
   4 | #include <securebytes.hpp>
   5 | 
   6 | // HKDF-SHA256: Extract-then-Expand per RFC 5869.
   7 | // ikm  — input keying material (the source secret)
   8 | // salt — optional random value; improves security when ikm has low entropy
   9 | // info — context/application-specific binding string
  10 | // okm  — output buffer; resized to outLen bytes before returning
  11 | void hkdf_sha256(const SecureBytes &ikm, const SecureBytes &salt,
  12 |                  const Bytes &info, size_t outLen, SecureBytes &okm);
  13 | // PBKDF2-SHA256: password-based key derivation per RFC 2898 §5.2.
  14 | // n_iterations should be >= 310 000 (OWASP 2023 recommendation for SHA-256).
  15 | // derived — output buffer; resized to SHA256_DIGEST_LENGTH (32) bytes.
  16 | void pbkdf2_sha256(const SecureBytes &password, const SecureBytes &salt,
  17 |                    int n_iterations, SecureBytes &derived);
  

`include/KeyStore.hpp`:

   1 | #pragma once
   2 | 
   3 | #include <bifrost.hpp>
   4 | #include <cassert>
   5 | #include <cstddef>
   6 | #include <cstdint>
   7 | #include <cstring>
   8 | #include <openssl/bio.h>
   9 | #include <openssl/evp.h>
  10 | #include <openssl/obj_mac.h>
  11 | #include <openssl/pem.h>
  12 | #include <openssl/rand.h>
  13 | #include <openssl/sha.h>
  14 | #include <openssl/x509.h>
  15 | #include <openssl/x509v3.h>
  16 | #include <securebytes.hpp>
  17 | #include <string>
  18 | #include <unordered_map>
  19 | #include <utility.hpp>
  20 | #include <vector>
  21 | 
  22 | // ---------------------------------------------------------------------------
  23 | // Encryption constants — typed so the compiler enforces units at call
  24 | // sites.
  25 | // ---------------------------------------------------------------------------
  26 | inline constexpr size_t KEY_STORE_ENC_KEY_SIZE = 32;
  27 | inline constexpr size_t ENC_BLOB_NONCE_SIZE = 12; // AES-GCM 96-bit nonce
  28 | inline constexpr size_t ENC_BLOB_TAG_SIZE = 16;   // AES-GCM 128-bit tag
  29 | inline constexpr int PBKDF2_N_ITERATIONS = 600'000;
  30 | inline constexpr size_t PBKDF2_SALT_SIZE = 16;
  31 | inline constexpr uint32_t MAX_SANS_COUNT = 1000;
  32 | inline constexpr uint32_t MAX_KEY_COUNT = 1000;
  33 | 
  34 | // ---------------------------------------------------------------------------
  35 | // Key — holds everything we need to generate and display a TOTP for one
  36 | // registered account.  Non-copyable because it owns a SecureBytes secret.
  37 | // ---------------------------------------------------------------------------
  38 | struct Key {
  39 |         std::string accinfo;
  40 |         Bytes fingerprint; // = SHA(Server X509 Certificate)
  41 |         std::string commonName;
  42 |         std::vector<std::string> sans;
  43 |         SecureBytes secret;
  44 | 
  45 |         Key() = default;
  46 |         Key(const Key &) = delete;
  47 |         Key &operator=(const Key &) = delete;
  48 |         Key(Key &&) noexcept = default;
  49 |         Key &operator=(Key &&) noexcept = default;
  50 |         ~Key() = default;
  51 | 
  52 |         // Serialisation: length-prefixed TLV format.
  53 |         size_t size() const;
  54 |         Bytes serialize() const;
  55 |         static Key deserialize(const Bytes &data);
  56 | };
  57 | 
  58 | // ---------------------------------------------------------------------------
  59 | // EncryptedBlob — the on-disk envelope for an AES-256-GCM-encrypted KeyStore.
  60 | // Layout: [version:1][nonce:12][cipherSize:4][ciphertext:N][tag:16]
  61 | // ---------------------------------------------------------------------------
  62 | struct EncryptedBlob {
  63 |         uint8_t version{1};
  64 |         Bytes nonce;
  65 |         Bytes ciphertext;
  66 |         Bytes tag;
  67 | 
  68 |         size_t size() const;
  69 |         Bytes serialize() const;
  70 |         static EncryptedBlob deserialize(const Bytes &data);
  71 | };
  72 | 
  73 | // ---------------------------------------------------------------------------
  74 | // KeyStore — static singleton that owns all registered Keys in memory and on
  75 | // disk.  Indexed by UKID (SHA-256 of accinfo || fingerprint).
  76 | // ---------------------------------------------------------------------------
  77 | class KeyStore {
  78 |         static SecureBytes _encryptionKey;
  79 |         static SecureBytes _salt;
  80 |         static std::unordered_map<Bytes, Key, BytesHash> _store;
  81 |         static bool _initialized;
  82 |         static bool _exitHooksInstalled;
  83 | 
  84 |         static void installExitHooks();
  85 | 
  86 |     public:
  87 |         // Initialise from the password: derive the encryption key, then load
  88 |         // and decrypt the on-disk store if it already exists.
  89 |         static void init(std::string &password);
  90 |         static void deinit() noexcept;
  91 | 
  92 |         // Number of entries currently held in memory.
  93 |         static size_t size();
  94 | 
  95 |         // ── Certificate helpers
  96 |         // ──────────────────────────────────────────────────
  97 |         static Bytes computeFingerprint(X509 *cert);
  98 |         static std::string extractCN(X509_NAME *name);
  99 |         static std::vector<std::string> extractSANs(X509 *cert);
 100 | 
 101 |         // Populate fingerprint / CN / SANs from a certificate (no secret or
 102 |         // accinfo; callers fill those in before calling store()).
 103 |         static Key buildKey(X509 *cert);
 104 | 
 105 |         // ── Mutation
 106 |         // ─────────────────────────────────────────────────────────────
 107 |         static void store(X509 *cert, const std::string &accinfo,
 108 |                           SecureBytes &&secret);
 109 |         // Takes ownership of key via move; existing entries with the same UKID
 110 |         // are overwritten.
 111 |         static void store(Key &key);
 112 |         static void erase(const Bytes &ukid);
 113 | 
 114 |         // ── Key identifiers
 115 |         // ────────────────────────────────────────────────────── UKID =
 116 |         // SHA-256(accinfo || fingerprint) — stable, unique per registration.
 117 |         static Bytes getUKID(const Key &key);
 118 | 
 119 |         // ── Lookup
 120 |         // ───────────────────────────────────────────────────────────────
 121 |         static const Key *lookupByUKID(const Bytes &ukid);
 122 |         static std::vector<const Key *> lookupByFG(const Bytes &fingerprint);
 123 |         static std::vector<const Key *> lookupByCN(const std::string &cn);
 124 |         static std::vector<const Key *>
 125 |         lookupByAccInfo(const std::string &accinfo);
 126 |         static std::vector<const Key *> getAllKeys();
 127 | 
 128 |         // ── Persistence
 129 |         // ──────────────────────────────────────────────────────────
 130 |         static Bytes serialize();
 131 |         static void deserialize(const Bytes &data);
 132 |         static EncryptedBlob encryptStore();
 133 |         static void decryptStore(const EncryptedBlob &blob);
 134 |         // Layout: [PBKDF2_SALT_SIZE] + [EncryptedBlob]
 135 |         static void saveStore();
 136 |         static void loadStore();
 137 | };
  

`include/bifrost.hpp`:

   1 | #pragma once
   2 | 
   3 | #include <cstdint>
   4 | #include <cstdlib>
   5 | #include <filesystem>
   6 | #include <stdexcept>
   7 | #include <string_view>
   8 | #include <vector>
   9 | 
  10 | #if defined(_WIN32)
  11 | #include <shlobj.h>
  12 | #include <windows.h>
  13 | #endif
  14 | 
  15 | namespace fs = std::filesystem;
  16 | 
  17 | using Byte = uint8_t;
  18 | using Bytes = std::vector<Byte>;
  19 | 
  20 | inline constexpr std::string_view APP_DIR_NAME{"bifrost"};
  21 | inline constexpr std::string_view CERTS_DIR_NAME{"certs"};
  22 | inline constexpr std::string_view DEFAULT_KEYFILE{"totp-secrets.keys"};
  23 | inline constexpr std::string_view ROOT_CA_CERT{"root-ca.crt"};
  24 | inline constexpr std::string_view BIFROST_CERT_CHAIN{"bifrost-chain.pem"};
  25 | inline constexpr std::string_view BIFROST_KEY{"bifrost.key"};
  26 | inline constexpr std::string_view BIFROST_PROTOCOL{"bifrost-totp://"};
  27 | 
  28 | // ---------------------------------------------------------------------------
  29 | // Paths — static helper that resolves all well-known filesystem locations.
  30 | // Converted macros to constexpr string_views; operator/ handles the join.
  31 | // ---------------------------------------------------------------------------
  32 | class Paths {
  33 |     private:
  34 |         inline static std::string _keyfile;
  35 | 
  36 |         static std::string getEnvVar(const char *name) {
  37 |             const char *val = std::getenv(name);
  38 |             if (!val)
  39 |                 throw std::runtime_error(
  40 |                     std::string("Required environment variable not set: ") +
  41 |                     name);
  42 |             return std::string(val);
  43 |         }
  44 | 
  45 |     public:
  46 |         static void init() {
  47 |             if (!fs::exists(certsDir()) || !fs::exists(rootCACert()) ||
  48 |                 !fs::exists(certChain()) || !fs::exists(privKey()))
  49 |                 throw std::runtime_error("Missing Certs");
  50 | 
  51 |             _keyfile = DEFAULT_KEYFILE;
  52 |         }
  53 | 
  54 |         static fs::path homeDir() {
  55 | #if defined(_WIN32)
  56 |             return fs::path(getEnvVar("USERPROFILE"));
  57 | #else
  58 |             return fs::path(getEnvVar("HOME"));
  59 | #endif
  60 |         }
  61 | 
  62 |         static fs::path configDir() {
  63 | #if defined(_WIN32)
  64 |             // %APPDATA%\bifrost  (e.g. C:\Users\name\AppData\Roaming\bifrost)
  65 |             return fs::path(getEnvVar("APPDATA")) / APP_DIR_NAME;
  66 | #elif defined(__APPLE__)
  67 |             // ~/Library/Application Support/bifrost
  68 |             return homeDir() / "Library/Application Support" / APP_DIR_NAME;
  69 | #else
  70 |             // ~/.config/bifrost  (XDG convention)
  71 |             const char *xdg = std::getenv("XDG_CONFIG_HOME");
  72 |             if (xdg && *xdg)
  73 |                 return fs::path(xdg) / APP_DIR_NAME;
  74 |             return homeDir() / ".config" / APP_DIR_NAME;
  75 | #endif
  76 |         }
  77 | 
  78 |         static void setKeyfile(const std::string &file) { _keyfile = file; }
  79 |         static fs::path keyfile() { return configDir() / _keyfile; }
  80 |         static fs::path certsDir() { return configDir() / CERTS_DIR_NAME; }
  81 |         static fs::path rootCACert() { return certsDir() / ROOT_CA_CERT; }
  82 |         static fs::path certChain() { return certsDir() / BIFROST_CERT_CHAIN; }
  83 |         static fs::path privKey() { return certsDir() / BIFROST_KEY; }
  84 | };
  

`include/securebytes.hpp`:

   1 | #pragma once
   2 | 
   3 | #include <bifrost.hpp>
   4 | #include <cstddef>
   5 | #include <memory>
   6 | #include <openssl/crypto.h>
   7 | 
   8 | // ---------------------------------------------------------------------------
   9 | // SecureAllocator — wraps std::allocator so every deallocation calls
  10 | // OPENSSL_cleanse first, preventing secrets from lingering on the heap after
  11 | // a vector is freed or reallocated.
  12 | // ---------------------------------------------------------------------------
  13 | template <typename T> struct SecureAllocator : std::allocator<T> {
  14 |         using Base = std::allocator<T>;
  15 | 
  16 |         // Required by the standard allocator protocol so containers can rebind
  17 |         // the allocator to their internal node/value types.
  18 |         template <typename U> struct rebind {
  19 |                 using other = SecureAllocator<U>;
  20 |         };
  21 | 
  22 |         SecureAllocator() noexcept = default;
  23 | 
  24 |         template <typename U>
  25 |         SecureAllocator(const SecureAllocator<U> &) noexcept {}
  26 | 
  27 |         void deallocate(T *p, size_t n) {
  28 |             if (p && n > 0)
  29 |                 OPENSSL_cleanse(p, n * sizeof(T));
  30 |             Base::deallocate(p, n);
  31 |         }
  32 | };
  33 | 
  34 | // Two SecureAllocators are always considered equal (they carry no state),
  35 | // which allows container move/swap to work without reallocating.
  36 | template <typename T, typename U>
  37 | bool operator==(const SecureAllocator<T> &,
  38 |                 const SecureAllocator<U> &) noexcept {
  39 |     return true;
  40 | }
  41 | template <typename T, typename U>
  42 | bool operator!=(const SecureAllocator<T> &,
  43 |                 const SecureAllocator<U> &) noexcept {
  44 |     return false;
  45 | }
  46 | 
  47 | template <typename T> using SecureVector = std::vector<T, SecureAllocator<T>>;
  48 | 
  49 | // ---------------------------------------------------------------------------
  50 | // SecureBytes — a non-copyable byte buffer whose storage is wiped by
  51 | // OPENSSL_cleanse both in the allocator's deallocate path and explicitly in
  52 | // cleanse() / the destructor.  Use clone() when a deliberate copy is needed.
  53 | // ---------------------------------------------------------------------------
  54 | class SecureBytes {
  55 |         SecureVector<Byte> _data;
  56 | 
  57 |     public:
  58 |         SecureBytes() = default;
  59 | 
  60 |         explicit SecureBytes(size_t size)
  61 |             : _data(size) {}
  62 | 
  63 |         SecureBytes(const uint8_t *ptr, size_t len)
  64 |             : _data(ptr, ptr + len) {}
  65 | 
  66 |         // Implicit conversion from plain Bytes; avoids requiring callers to
  67 |         // spell out the iterator range every time.
  68 |         SecureBytes(const Bytes &data)
  69 |             : _data(data.begin(), data.end()) {} // NOLINT(*-explicit-*)
  70 | 
  71 |         // Non-copyable: copying a secret should be a conscious, named act.
  72 |         SecureBytes(const SecureBytes &) = delete;
  73 |         SecureBytes &operator=(const SecureBytes &) = delete;
  74 | 
  75 |         SecureBytes(SecureBytes &&other) noexcept
  76 |             : _data(std::move(other._data)) {}
  77 | 
  78 |         SecureBytes &operator=(SecureBytes &&other) noexcept {
  79 |             if (this != &other) {
  80 |                 cleanse();
  81 |                 _data = std::move(other._data);
  82 |             }
  83 |             return *this;
  84 |         }
  85 | 
  86 |         // cleanse() is called here and in SecureAllocator::deallocate; the
  87 |         // double wipe is harmless and ensures the bytes are always zeroed even
  88 |         // if the allocator path is somehow skipped (e.g. small-buffer
  89 |         // optimisation).
  90 |         ~SecureBytes() { cleanse(); }
  91 | 
  92 |         Byte *data() { return _data.data(); }
  93 |         const Byte *data() const { return _data.data(); }
  94 |         size_t size() const { return _data.size(); }
  95 |         bool empty() const { return _data.empty(); }
  96 |         void resize(size_t n) { _data.resize(n); }
  97 | 
  98 |         // Named copy constructor — makes intentional duplication explicit at
  99 |         // the call site without relying on a deleted copy constructor.
 100 |         SecureBytes clone() const {
 101 |             return SecureBytes(_data.data(), _data.size());
 102 |         }
 103 | 
 104 |         SecureVector<Byte>::iterator begin() { return _data.begin(); }
 105 |         SecureVector<Byte>::iterator end() { return _data.end(); }
 106 |         SecureVector<Byte>::const_iterator begin() const {
 107 |             return _data.begin();
 108 |         }
 109 |         SecureVector<Byte>::const_iterator end() const { return _data.end(); }
 110 | 
 111 |         // May be called at any point to eagerly wipe memory before the object
 112 |         // is destroyed (e.g. immediately after a key is no longer needed).
 113 |         void cleanse() {
 114 |             if (!_data.empty())
 115 |                 OPENSSL_cleanse(_data.data(), _data.size());
 116 |         }
 117 | };
  

`include/terminal-launch.hpp`:

   1 | #pragma once
   2 | 
   3 | #include <string>
   4 | #include <string_view>
   5 | 
   6 | #if defined(_WIN32)
   7 | #include <windows.h>
   8 | #elif defined(__APPLE__)
   9 | #include <mach-o/dyld.h>
  10 | #include <unistd.h>
  11 | #else
  12 | #include <unistd.h>
  13 | #endif
  14 | 
  15 | // Checked by main() to detect re-entry after terminal launch.
  16 | // Defined as string_view rather than a C-string macro so SENTINEL_FLAG.c_str()
  17 | // at the call site is explicit and string comparisons work without strlen.
  18 | inline constexpr std::string_view SENTINEL_FLAG{"--__in_terminal__"};
  19 | 
  20 | // Resolve the absolute path of the currently running executable.
  21 | // Throws std::runtime_error on failure (platform API error or buffer too
  22 | // small).
  23 | std::string getSelfPath();
  24 | 
  25 | // Single-quote–escape a string for safe embedding inside a POSIX 'sh -c' arg.
  26 | // Technique: close quote, emit escaped quote, reopen quote.
  27 | std::string shQuote(const std::string &s);
  28 | 
  29 | // Re-launch the current process inside a visible terminal window, passing
  30 | // SENTINEL_FLAG as argv[1] followed by the original arguments.
  31 | // Never returns on success (execlp / CreateProcess + exit).
  32 | void launchInTerminal(const std::string &selfPath, int argc, char **argv);
  

`include/tls.hpp`:

   1 | #pragma once
   2 | 
   3 | #include <openssl/crypto.h>
   4 | #include <openssl/err.h>
   5 | #include <openssl/ssl.h>
   6 | #include <openssl/x509v3.h>
   7 | 
   8 | #include <arpa/inet.h>
   9 | #include <netdb.h>
  10 | #include <netinet/in.h>
  11 | #include <sys/socket.h>
  12 | #include <unistd.h>
  13 | 
  14 | #include <KeyStore.hpp>
  15 | #include <bifrost.hpp>
  16 | #include <cstring>
  17 | #include <securebytes.hpp>
  18 | #include <string>
  19 | 
  20 | // ---------------------------------------------------------------------------
  21 | // Protocol / key-derivation constants.
  22 | //
  23 | // TOTP_HKDF_INFO_STR: the info label fed into HKDF on both this client and
  24 | // the Python server.  Defined as string_view so the Bytes initialiser below
  25 | // picks up exactly 16 bytes — no hidden null terminator from sizeof(char[]).
  26 | //
  27 | // EXPORTER_SECRET_LABEL: used with SSL_export_keying_material (RFC 5705 /
  28 | // RFC 8446 §7.5).  Both sides call export_keying_material with the same label
  29 | // and receive an identical value, unlike the raw EXPORTER_SECRET from the
  30 | // keylog which Python cannot access.
  31 | // ---------------------------------------------------------------------------
  32 | inline constexpr size_t EXPORTER_SECRET_SIZE = 48;
  33 | inline constexpr std::string_view TOTP_HKDF_INFO_STR{"bifrost-totp-key"};
  34 | inline constexpr std::string_view EXPORTER_SECRET_LABEL{"bifrost-ms"};
  35 | 
  36 | // Byte sequence built once at startup, reused for every HKDF call.
  37 | inline const Bytes TOTP_HKDF_INFO(TOTP_HKDF_INFO_STR.begin(),
  38 |                                   TOTP_HKDF_INFO_STR.end());
  39 | 
  40 | // ---------------------------------------------------------------------------
  41 | // ConnContext — carries the per-connection exporter secret derived after the
  42 | // handshake; passed from tls_connect to registerBifrost.
  43 | // ---------------------------------------------------------------------------
  44 | struct ConnContext {
  45 |         SecureBytes exporterSecret;
  46 | };
  47 | 
  48 | // ---------------------------------------------------------------------------
  49 | // ConnInfo — parsed form of a bifrost-totp:// URL.
  50 | // ---------------------------------------------------------------------------
  51 | struct ConnInfo {
  52 |         std::string host;
  53 |         uint16_t port;
  54 |         std::string path; // e.g. "/signup/123456"
  55 | };
  56 | 
  57 | // ---------------------------------------------------------------------------
  58 | // ServerRegData — payload returned by the registration endpoint.
  59 | // ---------------------------------------------------------------------------
  60 | struct ServerRegData {
  61 |         SecureBytes KEY;      // server's TOTP seed contribution
  62 |         std::string ACC_INFO; // human-readable account identifier
  63 | };
  64 | 
  65 | // ─── Exception helper ───────────────────────────────────────────────────────
  66 | // Drain the OpenSSL error queue and throw a runtime_error with all messages
  67 | // chained into one string.
  68 | void throw_ssl_error(const std::string &context);
  69 | 
  70 | // ─── SSL_CTX factory ────────────────────────────────────────────────────────
  71 | // Build a fully configured client context: TLS 1.2–1.3 only, pinned cipher
  72 | // suites, server-cert verification against ca_cert, and client cert for mTLS.
  73 | SSL_CTX *create_client_ctx(const fs::path &ca_cert,
  74 |                            const fs::path &client_chain,
  75 |                            const fs::path &client_key);
  76 | 
  77 | // ─── Raw TCP connection ─────────────────────────────────────────────────────
  78 | int connect_tcp(const std::string &host, uint16_t port);
  79 | 
  80 | // ─── TLS handshake + hostname verification ──────────────────────────────────
  81 | // Performs the handshake, verifies the server certificate, and populates
  82 | // connCtx.exporterSecret via SSL_export_keying_material.
  83 | SSL *tls_connect(SSL_CTX *ctx, int tcp_fd, const std::string &hostname,
  84 |                  ConnContext &connCtx);
  85 | 
  86 | // ─── Secure send / recv ─────────────────────────────────────────────────────
  87 | void tls_send(SSL *ssl, const void *data, size_t len);
  88 | std::string tls_recv(SSL *ssl, size_t max_bytes = 4096);
  89 | 
  90 | // ─── Teardown ───────────────────────────────────────────────────────────────
  91 | void tls_shutdown(SSL *ssl, int tcp_fd);
  92 | 
  93 | // ─── Registration helpers ───────────────────────────────────────────────────
  94 | ServerRegData fetchServerRegData(SSL *ssl, int tcp_fd, const std::string &host,
  95 |                                  const std::string &path);
  96 | 
  97 | ConnInfo getConnInfo(std::string_view serverArgs);
  98 | 
  99 | Key registerBifrost(const ConnInfo &connInfo);
  

`include/totp.hpp`:

   1 | #pragma once
   2 | 
   3 | #include <bifrost.hpp>
   4 | #include <cstdint>
   5 | #include <ctime>
   6 | #include <securebytes.hpp>
   7 | #include <utility.hpp>
   8 | 
   9 | // TOTP parameters matching RFC 6238 defaults used by the Bifrost server.
  10 | // Converted from macros to typed constants to avoid preprocessor pollution and
  11 | // to let the compiler enforce types at call sites.
  12 | inline constexpr int TIME_WINDOW = 30;      // seconds per TOTP step
  13 | inline constexpr int OTP_SIZE = 6;          // decimal digits
  14 | inline constexpr int TOTP_KEY_LEN = 32;     // bytes; output of HKDF step
  15 | inline constexpr int TOTP_DIGEST_SIZE = 32; // HMAC-SHA256 output length
  16 | 
  17 | // TODO: SECURITY — SHA-1 is cryptographically weak; migrate to TOTP-SHA256
  18 | // (HMAC-SHA256, TOTP_DIGEST_SIZE = 32) once the server supports it.
  19 | // Both sides must switch simultaneously to avoid interoperability breakage.
  20 | 
  21 | struct TOTP {
  22 |         uint32_t otp;      // OTP_SIZE-digit code
  23 |         uint32_t validity; // seconds remaining in the current TIME_WINDOW
  24 | };
  25 | 
  26 | // Internal: compute HMAC-SHA256(key, msg).  Exposed for unit testing.
  27 | Bytes generate_hmac_sha256(const SecureBytes &key, const Bytes &msg);
  28 | 
  29 | // Internal: derive the truncated 31-bit sample for a given counter value.
  30 | uint32_t genSample(const SecureBytes &key, std::time_t timeStep);
  31 | 
  32 | // Generate a TOTP code from the stored secret using the current wall clock.
  33 | TOTP generateOTP(const SecureBytes &key);
  

`include/utility.hpp`:

   1 | #pragma once
   2 | 
   3 | #include <bifrost.hpp>
   4 | #include <functional>
   5 | #include <iostream>
   6 | #include <string_view>
   7 | #include <unordered_map>
   8 | 
   9 | // ---------------------------------------------------------------------------
  10 | // BytesHash — FNV/std hash over Bytes via string_view, used by KeyStore's
  11 | // unordered_map.  Reinterpret-cast is safe because Byte is unsigned char.
  12 | // ---------------------------------------------------------------------------
  13 | struct BytesHash {
  14 |         std::size_t operator()(const Bytes &bytes) const noexcept {
  15 |             std::string_view sv(reinterpret_cast<const char *>(bytes.data()),
  16 |                                 bytes.size());
  17 |             return std::hash<std::string_view>{}(sv);
  18 |         }
  19 | };
  20 | 
  21 | // Hex helpers
  22 | int hexNibble(char c) noexcept;
  23 | void printBytes(std::ostream &stream, const Bytes &bytes, bool shorten = true);
  24 | Bytes hexToBytes(std::string_view hex);
  25 | std::string bytesToHex(const Bytes &bytes);
  26 | 
  27 | // TOTP time encoding: big-endian 8-byte counter per RFC 6238 / HOTP spec.
  28 | Bytes timeToBytes(std::time_t time);
  29 | 
  30 | // Little-endian uint32 read/write used by the KeyStore serialisation format.
  31 | void writeu32(Bytes &out, uint32_t v);
  32 | uint32_t readu32(const Byte *p);
  33 | 
  34 | // Length-prefixed field reader used by Key and EncryptedBlob deserialisation.
  35 | Bytes readField(const Bytes &data, size_t &offset);
  36 | 
  37 | // Atomic file I/O: write goes through a .tmp + rename to avoid partial writes;
  38 | // read retries on EINTR and handles files that shrink between stat and read.
  39 | void writeAtomic(const fs::path &path, const Bytes &data,
  40 |                  uint32_t perms = 0644);
  41 | Bytes readAtomic(const fs::path &path);
  42 | 
  43 | // URL query-string parser.  Returns string_view slices into the input; the
  44 | // caller must keep the input alive for the lifetime of the returned map.
  45 | // [[nodiscard]] because silently discarding the result is always a mistake.
  46 | [[nodiscard]]
  47 | std::unordered_map<std::string_view, std::string_view>
  48 | parseURLParams(std::string_view url, char kvDelim = '&', char valDelim = '=');
  

`install.sh`:

   1 | #!/usr/bin/env bash
   2 | #
   3 | # install.sh — Build, test, and install Bifrost (user-local, no sudo required)
   4 | #
   5 | # What this does:
   6 | #   1. Configures and builds the project with CMake (Release, out-of-source in build/)
   7 | #   2. Runs the CTest suite and ABORTS before installing if any test fails
   8 | #   3. Installs the resulting binary to ~/.local/bin
   9 | #   4. Installs the .desktop file to ~/.local/share/applications
  10 | #   5. Refreshes the desktop database and registers the bifrost-totp:// scheme
  11 | #
  12 | # Usage:
  13 | #   ./install.sh                    # build + test + install
  14 | #   ./install.sh --skip-tests       # build + install, skip tests (not recommended)
  15 | #   ./install.sh --clean            # wipe build/ first, then build + test + install
  16 | #   ./install.sh --uninstall        # remove installed files
  17 | 
  18 | set -euo pipefail
  19 | 
  20 | # ---- Configuration (edit these to match your repo) -------------------------
  21 | PROJECT_NAME="bifrost"
  22 | BINARY_NAME="bifrost"          # CMake target / output binary name
  23 | DESKTOP_FILE_NAME="bifrost-authentication.desktop"
  24 | MIME_SCHEME="x-scheme-handler/bifrost-totp"
  25 | BUILD_DIR="build"
  26 | BUILD_TYPE="Release"
  27 | RUN_TESTS=1                    # default on; --skip-tests turns it off
  28 | # ------------------------------------------------------------------------
  29 | 
  30 | SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  31 | INSTALL_PREFIX="$HOME/.local"
  32 | INSTALL_BIN_DIR="$INSTALL_PREFIX/bin"
  33 | INSTALL_DESKTOP_DIR="$INSTALL_PREFIX/share/applications"
  34 | CONFIG_DIR="$HOME/.config/$PROJECT_NAME"
  35 | 
  36 | OS="$(uname -s)"
  37 | 
  38 | log()  { echo -e "\033[1;34m[install]\033[0m $*"; }
  39 | err()  { echo -e "\033[1;31m[error]\033[0m $*" >&2; }
  40 | 
  41 | # ---- System Dependency Check -------------------------------------------
  42 | command -v cmake >/dev/null 2>&1 || { err "cmake not found."; exit 1; }
  43 | command -v pkg-config >/dev/null 2>&1 || { err "pkg-config not found."; exit 1; }
  44 | 
  45 | # ---- Uninstall path ----------------------------------------------------
  46 | if [[ "${1:-}" == "--uninstall" ]]; then
  47 |     log "Removing installed binary, desktop file, configs, and protocol registration..."
  48 |     rm -f "$INSTALL_BIN_DIR/$BINARY_NAME"
  49 |     rm -f "$INSTALL_DESKTOP_DIR/$DESKTOP_FILE_NAME"
  50 |     rm -rf "$CONFIG_DIR"
  51 |     if [[ "$OS" == "Linux" ]]; then
  52 |         update-desktop-database "$INSTALL_DESKTOP_DIR" 2>/dev/null || true
  53 |     fi
  54 |     log "Uninstalled successfully."
  55 |     exit 0
  56 | fi
  57 | 
  58 | # ---- Argument parsing ----------------------------------------------------
  59 | # NOTE: this remains simple positional parsing, matching the original
  60 | # script's style. It intentionally does NOT support combining --clean and
  61 | # --skip-tests in one invocation (e.g. "./install.sh --clean --skip-tests"
  62 | # will only honor --clean). If you need combinable flags, replace this block
  63 | # with a `while getopts` or manual `while [[ $# -gt 0 ]]` loop that shifts
  64 | # through all arguments instead of only inspecting "$1".
  65 | if [[ "${1:-}" == "--clean" ]]; then
  66 |     log "Cleaning previous build directory..."
  67 |     rm -rf "$SCRIPT_DIR/$BUILD_DIR"
  68 | fi
  69 | 
  70 | if [[ "${1:-}" == "--skip-tests" ]]; then
  71 |     RUN_TESTS=0
  72 |     log "Skipping test suite (--skip-tests passed)."
  73 | fi
  74 | 
  75 | # ── Parallel job count (cross-platform) ──────────────────────────────────────
  76 | if [[ "$OS" == "Darwin" ]]; then
  77 |     JOBS="$(sysctl -n hw.logicalcpu)"
  78 | else
  79 |     JOBS="$(nproc)"
  80 | fi
  81 | 
  82 | # ---- Configure -------------------------------------------------------------
  83 | log "Configuring CMake build ($BUILD_TYPE)..."
  84 | BIFROST_BUILD_TESTS_FLAG="OFF"
  85 | if [[ $RUN_TESTS -eq 1 ]]; then
  86 |     BIFROST_BUILD_TESTS_FLAG="ON"
  87 | fi
  88 | 
  89 | cmake -S "$SCRIPT_DIR" -B "$SCRIPT_DIR/$BUILD_DIR" \
  90 |     -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
  91 |     -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
  92 |     -DBIFROST_BUILD_TESTS="$BIFROST_BUILD_TESTS_FLAG"
  93 | 
  94 | # ---- Build -------------------------------------------------------------
  95 | log "Building $PROJECT_NAME..."
  96 | cmake --build "$SCRIPT_DIR/$BUILD_DIR" --parallel "$JOBS"
  97 | 
  98 | # ---- Test ----------------------------------------------------------------
  99 | # This is the step that satisfies "perform tests, then continue to
 100 | # installation": ctest's exit code is checked explicitly (relying on `set -e`
 101 | # alone would not reliably short-circuit here since this runs inside a
 102 | # conditional), and a non-zero exit aborts BEFORE `cmake --install` runs.
 103 | if [[ $RUN_TESTS -eq 1 ]]; then
 104 |     log "Running test suite..."
 105 |     if ! ctest --test-dir "$SCRIPT_DIR/$BUILD_DIR" --output-on-failure -j "$JOBS"; then
 106 |         err "Tests failed. Aborting install."
 107 |         err "Re-run with --skip-tests to bypass verification (not recommended)."
 108 |         exit 1
 109 |     fi
 110 |     log "All tests passed."
 111 | fi
 112 | 
 113 | BUILT_BINARY="$SCRIPT_DIR/$BUILD_DIR/src/$BINARY_NAME"
 114 | if [[ ! -f "$BUILT_BINARY" ]]; then
 115 |     err "Expected built binary at $BUILT_BINARY but it wasn't found."
 116 |     err "Check that BINARY_NAME matches your CMake target's output name."
 117 |     exit 1
 118 | fi
 119 | 
 120 | log "Installing $PROJECT_NAME (Binaries & Desktop file)"
 121 | cmake --install "$SCRIPT_DIR/$BUILD_DIR"
 122 | 
 123 | # ---- Install certificates ---------------------------------------------
 124 | log "Installing certificates to $CONFIG_DIR/certs ..."
 125 | install -d -m 700 "$CONFIG_DIR/certs"
 126 | 
 127 | for cert in "$SCRIPT_DIR/certs/"*.crt "$SCRIPT_DIR/certs/"*.pem; do
 128 |     if [[ -f "$cert" ]]; then
 129 |         install -m 444 "$cert" "$CONFIG_DIR/certs/"
 130 |     fi
 131 | done
 132 | 
 133 | for key in "$SCRIPT_DIR/certs/"*.key; do
 134 |     if [[ -f "$key" ]]; then
 135 |         install -m 400 "$key" "$CONFIG_DIR/certs/"
 136 |     fi
 137 | done
 138 | 
 139 | # ── Register MIME / URL scheme ────────────────────────────────────────────────
 140 | if [[ "$OS" == "Linux" ]]; then
 141 |     log "Refreshing desktop database..."
 142 |     update-desktop-database "$INSTALL_DESKTOP_DIR" 2>/dev/null || true
 143 | 
 144 |     log "Registering $MIME_SCHEME -> $DESKTOP_FILE_NAME ..."
 145 |     xdg-mime default "$DESKTOP_FILE_NAME" "$MIME_SCHEME"
 146 | elif [[ "$OS" == "Darwin" ]]; then
 147 |     # macOS URL scheme registration requires an app bundle with Info.plist
 148 |     # CFBundleURLTypes. A plain binary cannot register URL schemes on macOS
 149 |     # without going through LaunchServices. No automated registration is
 150 |     # possible here; instruct the user.
 151 |     log "macOS: URL scheme registration requires an app bundle."
 152 |     log "Add 'bifrost-totp' to CFBundleURLTypes in your Info.plist and run:"
 153 |     log "  /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f <YourApp.app>"
 154 | fi
 155 | 
 156 | log "Done."
 157 | echo
 158 | echo "  Binary  : $INSTALL_BIN_DIR/$BINARY_NAME"
 159 | echo "  Desktop : $INSTALL_DESKTOP_DIR/$DESKTOP_FILE_NAME  (Linux)"
 160 | echo "  Protocol: $MIME_SCHEME  (Linux)"
 161 | echo
 162 | echo "Test (Linux): xdg-open 'bifrost-totp://test'"
 163 | echo "Uninstall   : ./install.sh --uninstall"
  

`src/CMakeLists.txt`:

   1 | # Explicit source listing - NO GLOBBING
   2 | set(BIFROST_LIB_SOURCES
   3 |     KDF.cpp
   4 |     KeyStore.cpp
   5 |     terminal-launch.cpp
   6 |     tls.cpp
   7 |     totp.cpp
   8 |     utility.cpp
   9 | )
  10 | 
  11 | # Core Library Target
  12 | add_library(bifrost_lib STATIC ${BIFROST_LIB_SOURCES})
  13 | add_library(bifrost::lib ALIAS bifrost_lib)
  14 | 
  15 | # Include directories
  16 | target_include_directories(bifrost_lib PUBLIC
  17 |     $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
  18 |     $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  19 | )
  20 | 
  21 | # Dependencies
  22 | target_link_libraries(bifrost_lib
  23 |     PUBLIC OpenSSL::Crypto Threads::Threads
  24 |     PRIVATE OpenSSL::SSL
  25 | )
  26 | 
  27 | # Apply Hardening and Warnings
  28 | set_project_warnings(bifrost_lib)
  29 | set_security_flags(bifrost_lib)
  30 | 
  31 | # ---------------------------------------------------------
  32 | # Executable Target
  33 | # ---------------------------------------------------------
  34 | add_executable(${PROJECT_NAME} bifrost.cpp)
  35 | target_link_libraries(${PROJECT_NAME} PRIVATE bifrost::lib)
  36 | 
  37 | # Apply Hardening and Warnings to binary
  38 | set_project_warnings(${PROJECT_NAME})
  39 | set_security_flags(${PROJECT_NAME})
  40 | if(ipo_supported)
  41 |     set_property(TARGET ${PROJECT_NAME} PROPERTY
  42 |         INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
  43 |     set_property(TARGET ${PROJECT_NAME} PROPERTY
  44 |         INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE)
  45 | endif()
  46 | 
  47 | # ---------------------------------------------------------
  48 | # Installation Rules
  49 | # ---------------------------------------------------------
  50 | # 1. Install the binary
  51 | install(TARGETS ${PROJECT_NAME}
  52 |     RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  53 | )
  54 | 
  55 | # install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/
  56 | #     DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bifrost
  57 | #     FILES_MATCHING PATTERN "*.hpp"
  58 | # )
  59 | 
  60 | # 2. Configure and install the desktop file
  61 | # This injects the exact install prefix into the Exec line
  62 | configure_file(
  63 |     ${CMAKE_SOURCE_DIR}/bifrost-authentication.desktop.in
  64 |     ${CMAKE_CURRENT_BINARY_DIR}/bifrost-authentication.desktop
  65 |     @ONLY
  66 | )
  67 | 
  68 | install(FILES ${CMAKE_CURRENT_BINARY_DIR}/bifrost-authentication.desktop
  69 |     DESTINATION ${CMAKE_INSTALL_DATADIR}/applications
  70 | )
  

`src/KDF.cpp`:

   1 | #include <KDF.hpp>
   2 | #include <bifrost.hpp>
   3 | #include <openssl/core_names.h>
   4 | #include <openssl/evp.h>
   5 | #include <openssl/kdf.h>
   6 | #include <openssl/params.h>
   7 | #include <openssl/sha.h>
   8 | #include <stdexcept>
   9 | 
  10 | namespace {
  11 | 
  12 | // A single static byte used only as a non-null placeholder address for
  13 | // zero-length OSSL_PARAM octet strings. Its VALUE is never read — OpenSSL
  14 | // is told data_size = 0 for these params, so it must not (and per the docs,
  15 | // does not) dereference this pointer. Only its non-null-ness matters.
  16 | Byte g_empty_octet_sentinel = 0;
  17 | 
  18 | // Returns a pointer suitable for OSSL_PARAM_construct_octet_string: the
  19 | // buffer's real data pointer if non-empty, or the sentinel above if empty.
  20 | // Never returns nullptr, regardless of what SecureBytes::data() /
  21 | // Bytes::data() return for a zero-length buffer.
  22 | inline Byte *ossl_safe_data(const SecureBytes &b) {
  23 |     return b.empty() ? &g_empty_octet_sentinel : const_cast<Byte *>(b.data());
  24 | }
  25 | 
  26 | inline Byte *ossl_safe_data(const Bytes &b) {
  27 |     return b.empty() ? &g_empty_octet_sentinel : const_cast<Byte *>(b.data());
  28 | }
  29 | 
  30 | } // namespace
  31 | 
  32 | // ---------------------------------------------------------------------------
  33 | // HKDF-SHA256  (RFC 5869)
  34 | // ---------------------------------------------------------------------------
  35 | // Uses the OpenSSL 3.x EVP_KDF API.  EVP_KDF_free is called right after
  36 | // EVP_KDF_CTX_new; the context holds its own reference so freeing the
  37 | // algorithm handle early is safe and keeps resource cleanup simple.
  38 | void hkdf_sha256(const SecureBytes &ikm, const SecureBytes &salt,
  39 |                  const Bytes &info, size_t outLen, SecureBytes &okm) {
  40 |     okm.resize(outLen);
  41 | 
  42 |     EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
  43 |     if (!kdf)
  44 |         throw std::runtime_error("hkdf_sha256: failed to fetch HKDF provider");
  45 | 
  46 |     EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
  47 |     EVP_KDF_free(kdf); // context holds its own ref; safe to release early
  48 |     if (!ctx)
  49 |         throw std::runtime_error("hkdf_sha256: failed to create KDF context");
  50 | 
  51 |     // OSSL_PARAM_construct_* takes non-const pointers for legacy reasons; the
  52 |     // values are only read, not written.
  53 |     char md_name[] = "SHA256";
  54 |     OSSL_PARAM params[5];
  55 |     size_t i = 0;
  56 |     params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
  57 |                                                    md_name, sizeof(md_name));
  58 |     params[i++] = OSSL_PARAM_construct_octet_string(
  59 |         OSSL_KDF_PARAM_KEY, ossl_safe_data(ikm), ikm.size());
  60 |     params[i++] = OSSL_PARAM_construct_octet_string(
  61 |         OSSL_KDF_PARAM_SALT, ossl_safe_data(salt), salt.size());
  62 |     params[i++] = OSSL_PARAM_construct_octet_string(
  63 |         OSSL_KDF_PARAM_INFO, ossl_safe_data(info), info.size());
  64 |     params[i++] = OSSL_PARAM_construct_end();
  65 | 
  66 |     if (EVP_KDF_derive(ctx, okm.data(), okm.size(), params) <= 0) {
  67 |         EVP_KDF_CTX_free(ctx);
  68 |         throw std::runtime_error("hkdf_sha256: key derivation failed");
  69 |     }
  70 |     EVP_KDF_CTX_free(ctx);
  71 | }
  72 | 
  73 | // ---------------------------------------------------------------------------
  74 | // PBKDF2-SHA256  (RFC 2898 §5.2)
  75 | // ---------------------------------------------------------------------------
  76 | // Output is always SHA256_DIGEST_LENGTH (32) bytes; the caller receives the
  77 | // result via the out-parameter pattern used throughout KDF.hpp.
  78 | void pbkdf2_sha256(const SecureBytes &password, const SecureBytes &salt,
  79 |                    const int n_iterations, SecureBytes &derived) {
  80 |     derived.resize(SHA256_DIGEST_LENGTH);
  81 | 
  82 |     if (PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(password.data()),
  83 |                           static_cast<int>(password.size()), salt.data(),
  84 |                           static_cast<int>(salt.size()), n_iterations,
  85 |                           EVP_sha256(), static_cast<int>(derived.size()),
  86 |                           derived.data()) != 1)
  87 |         throw std::runtime_error("pbkdf2_sha256: derivation failed");
  88 | }
  

`src/KeyStore.cpp`:

   1 | #include "bifrost.hpp"
   2 | #include <KDF.hpp>
   3 | #include <KeyStore.hpp>
   4 | #include <cassert>
   5 | #include <csignal>
   6 | #include <cstdint>
   7 | #include <cstdlib>
   8 | #include <exception>
   9 | #include <filesystem>
  10 | #include <fstream>
  11 | #include <openssl/crypto.h>
  12 | #include <openssl/evp.h>
  13 | #include <openssl/rand.h>
  14 | #include <ranges>
  15 | #include <securebytes.hpp>
  16 | #include <stdexcept>
  17 | #include <string>
  18 | #include <utility.hpp>
  19 | 
  20 | // ---------------------------------------------------------------------------
  21 | // Static member definitions
  22 | // ---------------------------------------------------------------------------
  23 | SecureBytes KeyStore::_encryptionKey;
  24 | SecureBytes KeyStore::_salt;
  25 | std::unordered_map<Bytes, Key, BytesHash> KeyStore::_store;
  26 | bool KeyStore::_initialized = false;
  27 | bool KeyStore::_exitHooksInstalled = false;
  28 | 
  29 | // ---------------------------------------------------------------------------
  30 | // Key serialisation  (length-prefixed TLV, little-endian uint32 lengths)
  31 | // ---------------------------------------------------------------------------
  32 | 
  33 | size_t Key::size() const {
  34 |     // Each field: 4-byte length prefix + payload.
  35 |     size_t s = (4 + accinfo.size()) + (4 + fingerprint.size()) +
  36 |                (4 + commonName.size()) + 4 + // SAN count
  37 |                (4 + secret.size());
  38 |     for (const auto &san : sans)
  39 |         s += 4 + san.size();
  40 |     return s;
  41 | }
  42 | 
  43 | Bytes Key::serialize() const {
  44 |     Bytes data;
  45 |     data.reserve(size());
  46 | 
  47 |     auto appendStr = [&](const std::string &s) {
  48 |         writeu32(data, static_cast<uint32_t>(s.size()));
  49 |         data.insert(data.end(), s.begin(), s.end());
  50 |     };
  51 |     auto appendBytes = [&](const Bytes &b) {
  52 |         writeu32(data, static_cast<uint32_t>(b.size()));
  53 |         data.insert(data.end(), b.begin(), b.end());
  54 |     };
  55 | 
  56 |     appendStr(accinfo);
  57 |     appendBytes(fingerprint);
  58 |     appendStr(commonName);
  59 | 
  60 |     writeu32(data, static_cast<uint32_t>(sans.size()));
  61 |     for (const auto &san : sans)
  62 |         appendStr(san);
  63 | 
  64 |     // Secret is last; SecureBytes iterators yield Byte values.
  65 |     writeu32(data, static_cast<uint32_t>(secret.size()));
  66 |     data.insert(data.end(), secret.begin(), secret.end());
  67 | 
  68 |     return data;
  69 | }
  70 | 
  71 | Key Key::deserialize(const Bytes &data) {
  72 |     size_t offset = 0;
  73 |     Key key;
  74 | 
  75 |     // Helper that reads a field and converts it to std::string.
  76 |     auto readStr = [&]() -> std::string {
  77 |         Bytes b = readField(data, offset);
  78 |         return std::string(b.begin(), b.end());
  79 |     };
  80 | 
  81 |     key.accinfo = readStr();
  82 |     key.fingerprint = readField(data, offset);
  83 |     key.commonName = readStr();
  84 | 
  85 |     if (offset + 4 > data.size())
  86 |         throw std::runtime_error("Key::deserialize: truncated SAN count");
  87 |     uint32_t sanCount = readu32(data.data() + offset);
  88 |     offset += 4;
  89 | 
  90 |     // Guard against pathological inputs before reserving / looping.
  91 |     if (sanCount > MAX_SANS_COUNT)
  92 |         throw std::runtime_error("Key::deserialize: implausible SAN count");
  93 | 
  94 |     key.sans.reserve(sanCount);
  95 |     for (uint32_t i = 0; i < sanCount; ++i) {
  96 |         Bytes san = readField(data, offset);
  97 |         key.sans.emplace_back(san.begin(), san.end());
  98 |     }
  99 | 
 100 |     key.secret = readField(data, offset);
 101 | 
 102 |     if (offset != data.size())
 103 |         throw std::runtime_error("Key::deserialize: trailing bytes after end");
 104 | 
 105 |     return key;
 106 | }
 107 | 
 108 | // ---------------------------------------------------------------------------
 109 | // EncryptedBlob serialisation
 110 | // Layout: [version:1][nonce:12][cipherSize:4][ciphertext:N][tag:16]
 111 | // ---------------------------------------------------------------------------
 112 | 
 113 | size_t EncryptedBlob::size() const {
 114 |     //        version      nonce              cipherSize     ciphertext tag
 115 |     return 1 + nonce.size() + 4 + ciphertext.size() + tag.size();
 116 | }
 117 | 
 118 | Bytes EncryptedBlob::serialize() const {
 119 |     Bytes out;
 120 |     out.reserve(size());
 121 | 
 122 |     out.push_back(version);
 123 |     out.insert(out.end(), nonce.begin(), nonce.end());
 124 | 
 125 |     writeu32(out, static_cast<uint32_t>(ciphertext.size()));
 126 |     out.insert(out.end(), ciphertext.begin(), ciphertext.end());
 127 |     out.insert(out.end(), tag.begin(), tag.end());
 128 | 
 129 |     return out;
 130 | }
 131 | 
 132 | EncryptedBlob EncryptedBlob::deserialize(const Bytes &data) {
 133 |     // Minimum size: 1 (version) + 12 (nonce) + 4 (cipherSize) + 16 (tag).
 134 |     constexpr size_t headerSize =
 135 |         1 + ENC_BLOB_NONCE_SIZE + 4 + ENC_BLOB_TAG_SIZE;
 136 | 
 137 |     if (data.empty())
 138 |         throw std::runtime_error("EncryptedBlob::deserialize: empty data");
 139 | 
 140 |     EncryptedBlob blob;
 141 |     blob.version = data[0];
 142 |     if (blob.version != 1)
 143 |         throw std::runtime_error(
 144 |             "EncryptedBlob::deserialize: unsupported version");
 145 |     if (data.size() < headerSize)
 146 |         throw std::runtime_error("EncryptedBlob::deserialize: data too short");
 147 | 
 148 |     blob.nonce =
 149 |         Bytes(data.begin() + 1,
 150 |               data.begin() + 1 + static_cast<ptrdiff_t>(ENC_BLOB_NONCE_SIZE));
 151 | 
 152 |     uint32_t cipherSize = readu32(data.data() + 1 + ENC_BLOB_NONCE_SIZE);
 153 | 
 154 |     // Both checks are needed: the first catches overflow, the second catches
 155 |     // trailing bytes which indicate a corrupt or truncated file.
 156 |     if (cipherSize > data.size() - headerSize)
 157 |         throw std::runtime_error(
 158 |             "EncryptedBlob::deserialize: cipherSize overflows buffer");
 159 |     if (data.size() != headerSize + cipherSize)
 160 |         throw std::runtime_error(
 161 |             "EncryptedBlob::deserialize: unexpected trailing bytes");
 162 | 
 163 |     auto cipherStart =
 164 |         data.begin() + 1 + static_cast<ptrdiff_t>(ENC_BLOB_NONCE_SIZE) + 4;
 165 |     blob.ciphertext =
 166 |         Bytes(cipherStart, cipherStart + static_cast<ptrdiff_t>(cipherSize));
 167 |     blob.tag =
 168 |         Bytes(cipherStart + static_cast<ptrdiff_t>(cipherSize), data.end());
 169 | 
 170 |     return blob;
 171 | }
 172 | 
 173 | // ---------------------------------------------------------------------------
 174 | // KeyStore — initialisation
 175 | // ---------------------------------------------------------------------------
 176 | 
 177 | // KeyStore exit hooks for safe and clean exit
 178 | extern "C" void KeyStoreSignalExitHandler(int sig) {
 179 |     KeyStore::deinit();
 180 |     std::signal(sig, SIG_DFL);
 181 |     std::raise(sig);
 182 | }
 183 | 
 184 | void KeyStoreTerminateHandler() {
 185 |     KeyStore::deinit();
 186 |     std::abort();
 187 | }
 188 | 
 189 | void KeyStore::installExitHooks() {
 190 |     if (_exitHooksInstalled)
 191 |         return;
 192 |     std::signal(SIGINT, KeyStoreSignalExitHandler);
 193 |     std::signal(SIGTERM, KeyStoreSignalExitHandler);
 194 |     std::set_terminate(KeyStoreTerminateHandler);
 195 |     _exitHooksInstalled = true;
 196 | }
 197 | 
 198 | void KeyStore::init(std::string &password) {
 199 |     if (_initialized)
 200 |         throw std::runtime_error("Trying to re-initialize the KeyStore");
 201 |     installExitHooks();
 202 | 
 203 |     // Wrap the password in SecureBytes immediately so it is wiped on exit.
 204 |     SecureBytes passwd(reinterpret_cast<const Byte *>(password.data()),
 205 |                        password.size());
 206 |     // Wipe the caller's plaintext password now that the key is derived.
 207 |     OPENSSL_cleanse(password.data(), password.size());
 208 | 
 209 |     _salt.resize(PBKDF2_SALT_SIZE);
 210 |     bool keyfileExists = fs::exists(Paths::keyfile());
 211 | 
 212 |     if (keyfileExists) {
 213 |         // Read the salt that was stored at the front of the existing keyfile.
 214 |         std::ifstream kf(Paths::keyfile(), std::ios::binary);
 215 |         kf.read(reinterpret_cast<char *>(_salt.data()),
 216 |                 static_cast<std::streamsize>(PBKDF2_SALT_SIZE));
 217 |         if (static_cast<size_t>(kf.gcount()) != PBKDF2_SALT_SIZE) {
 218 |             _salt.cleanse();
 219 |             throw std::runtime_error("KeyStore::init: corrupted keyfile");
 220 |         }
 221 |     } else {
 222 |         // First run — generate a fresh random salt.
 223 |         if (RAND_bytes(_salt.data(), static_cast<int>(PBKDF2_SALT_SIZE)) != 1) {
 224 |             _salt.cleanse();
 225 |             throw std::runtime_error("KeyStore::init: RAND_bytes failed");
 226 |         }
 227 |     }
 228 | 
 229 |     pbkdf2_sha256(passwd, _salt, PBKDF2_N_ITERATIONS, _encryptionKey);
 230 |     _initialized = true;
 231 | 
 232 |     if (keyfileExists)
 233 |         loadStore();
 234 | }
 235 | 
 236 | void KeyStore::deinit() noexcept {
 237 |     static bool inProgress = false;
 238 |     if (inProgress)
 239 |         return;
 240 |     inProgress = true;
 241 | 
 242 |     _encryptionKey.cleanse();
 243 |     _salt.cleanse();
 244 |     for (auto &[ukid, key] : _store)
 245 |         key.secret.cleanse();
 246 |     _store.clear();
 247 | 
 248 |     _initialized = false;
 249 |     inProgress = false;
 250 | }
 251 | 
 252 | // ---------------------------------------------------------------------------
 253 | // Size (bytes that serialize() would produce, excluding the outer salt field)
 254 | // ---------------------------------------------------------------------------
 255 | size_t KeyStore::size() {
 256 |     if (!_initialized)
 257 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 258 |     size_t s = 4; // key count
 259 |     for (const auto &[fp, key] : _store)
 260 |         s += 4 + key.size();
 261 |     return s;
 262 | }
 263 | 
 264 | // ---------------------------------------------------------------------------
 265 | // Certificate helpers
 266 | // ---------------------------------------------------------------------------
 267 | 
 268 | Bytes KeyStore::computeFingerprint(X509 *cert) {
 269 |     // DER-encode the full certificate, then SHA-256 hash it.
 270 |     unsigned char *der = nullptr;
 271 |     int derLen = i2d_X509(cert, &der);
 272 |     if (derLen < 0 || !der)
 273 |         throw std::runtime_error("computeFingerprint: DER encoding failed");
 274 | 
 275 |     unsigned char digest[EVP_MAX_MD_SIZE];
 276 |     unsigned int digestLen = 0;
 277 |     EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
 278 | 
 279 |     if (!mdctx || EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
 280 |         EVP_DigestUpdate(mdctx, der, static_cast<size_t>(derLen)) != 1 ||
 281 |         EVP_DigestFinal_ex(mdctx, digest, &digestLen) != 1) {
 282 |         if (mdctx)
 283 |             EVP_MD_CTX_free(mdctx);
 284 |         OPENSSL_free(der);
 285 |         throw std::runtime_error("computeFingerprint: digest failed");
 286 |     }
 287 |     EVP_MD_CTX_free(mdctx);
 288 |     OPENSSL_free(der);
 289 | 
 290 |     return Bytes(digest, digest + digestLen);
 291 | }
 292 | 
 293 | std::string KeyStore::extractCN(X509_NAME *name) {
 294 |     // Query length first, then allocate exactly the right buffer.
 295 |     int len = X509_NAME_get_text_by_NID(name, NID_commonName, nullptr, 0);
 296 |     if (len < 0)
 297 |         return "";
 298 | 
 299 |     std::string buf(static_cast<size_t>(len) + 1, '\0');
 300 |     int written = X509_NAME_get_text_by_NID(name, NID_commonName, buf.data(),
 301 |                                             static_cast<int>(buf.size()));
 302 |     if (written < 0)
 303 |         return "";
 304 | 
 305 |     buf.resize(static_cast<size_t>(written));
 306 |     return buf;
 307 | }
 308 | 
 309 | std::vector<std::string> KeyStore::extractSANs(X509 *cert) {
 310 |     std::vector<std::string> result;
 311 | 
 312 |     auto *gens = static_cast<GENERAL_NAMES *>(
 313 |         X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
 314 |     if (!gens)
 315 |         return result;
 316 | 
 317 |     for (int i = 0; i < sk_GENERAL_NAME_num(gens); ++i) {
 318 |         GENERAL_NAME *gen = sk_GENERAL_NAME_value(gens, i);
 319 |         if (gen->type == GEN_DNS) {
 320 |             ASN1_STRING *dns = gen->d.dNSName;
 321 |             result.emplace_back(
 322 |                 reinterpret_cast<const char *>(ASN1_STRING_get0_data(dns)),
 323 |                 static_cast<size_t>(ASN1_STRING_length(dns)));
 324 |         }
 325 |     }
 326 |     GENERAL_NAMES_free(gens);
 327 |     return result;
 328 | }
 329 | 
 330 | Key KeyStore::buildKey(X509 *cert) {
 331 |     Key key;
 332 |     key.fingerprint = computeFingerprint(cert);
 333 |     key.commonName = extractCN(X509_get_subject_name(cert));
 334 |     key.sans = extractSANs(cert);
 335 |     return key;
 336 | }
 337 | 
 338 | // ---------------------------------------------------------------------------
 339 | // Mutation
 340 | // ---------------------------------------------------------------------------
 341 | 
 342 | void KeyStore::store(X509 *cert, const std::string &accinfo,
 343 |                      SecureBytes &&secret) {
 344 |     if (!_initialized)
 345 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 346 |     Key key = buildKey(cert);
 347 |     key.secret = std::move(secret);
 348 |     key.accinfo = accinfo;
 349 |     Bytes ukid = getUKID(key);
 350 |     _store[ukid] = std::move(key);
 351 | }
 352 | 
 353 | // Moves key into the store; caller should not use key after this call.
 354 | void KeyStore::store(Key &key) {
 355 |     if (!_initialized)
 356 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 357 |     Bytes ukid = getUKID(key);
 358 |     _store[ukid] = std::move(key);
 359 | }
 360 | 
 361 | void KeyStore::erase(const Bytes &ukid) {
 362 |     if (!_initialized)
 363 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 364 |     // find-then-erase avoids a second lookup compared to _store.erase(ukid).
 365 |     auto it = _store.find(ukid);
 366 |     if (it != _store.end())
 367 |         _store.erase(it);
 368 | }
 369 | 
 370 | // ---------------------------------------------------------------------------
 371 | // Key identifiers
 372 | // ---------------------------------------------------------------------------
 373 | 
 374 | // UKID = SHA-256(accinfo + "$" + fingerprint) — stable and unique per
 375 | // registration.
 376 | Bytes KeyStore::getUKID(const Key &key) {
 377 |     unsigned char digest[EVP_MAX_MD_SIZE];
 378 |     unsigned int digestLen = 0;
 379 |     EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
 380 |     const std::string delimiter = "$";
 381 | 
 382 |     if (!mdctx || EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
 383 |         EVP_DigestUpdate(mdctx, key.accinfo.c_str(), key.accinfo.size()) != 1 ||
 384 |         EVP_DigestUpdate(mdctx, delimiter.c_str(), delimiter.size()) != 1 ||
 385 |         EVP_DigestUpdate(mdctx, key.fingerprint.data(),
 386 |                          key.fingerprint.size()) != 1 ||
 387 |         EVP_DigestFinal_ex(mdctx, digest, &digestLen) != 1) {
 388 |         if (mdctx)
 389 |             EVP_MD_CTX_free(mdctx);
 390 |         throw std::runtime_error("getUKID: SHA-256 computation failed");
 391 |     }
 392 |     EVP_MD_CTX_free(mdctx);
 393 |     return Bytes(digest, digest + digestLen);
 394 | }
 395 | 
 396 | // ---------------------------------------------------------------------------
 397 | // Lookup
 398 | // ---------------------------------------------------------------------------
 399 | 
 400 | const Key *KeyStore::lookupByUKID(const Bytes &ukid) {
 401 |     if (!_initialized)
 402 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 403 |     auto it = _store.find(ukid);
 404 |     return it != _store.end() ? &it->second : nullptr;
 405 | }
 406 | 
 407 | std::vector<const Key *> KeyStore::lookupByFG(const Bytes &fingerprint) {
 408 |     if (!_initialized)
 409 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 410 |     std::vector<const Key *> matches;
 411 |     for (const auto &[ukid, key] : _store) {
 412 |         // Use CRYPTO_memcmp to avoid timing side-channels even though
 413 |         // fingerprints are not secret; it's a cheap habit here.
 414 |         if (key.fingerprint.size() == fingerprint.size() &&
 415 |             CRYPTO_memcmp(key.fingerprint.data(), fingerprint.data(),
 416 |                           fingerprint.size()) == 0)
 417 |             matches.push_back(&key);
 418 |     }
 419 |     return matches;
 420 | }
 421 | 
 422 | std::vector<const Key *> KeyStore::lookupByCN(const std::string &cn) {
 423 |     if (!_initialized)
 424 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 425 |     std::vector<const Key *> matches;
 426 |     for (const auto &[ukid, key] : _store)
 427 |         if (key.commonName == cn)
 428 |             matches.push_back(&key);
 429 |     return matches;
 430 | }
 431 | 
 432 | std::vector<const Key *> KeyStore::lookupByAccInfo(const std::string &accinfo) {
 433 |     if (!_initialized)
 434 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 435 |     std::vector<const Key *> matches;
 436 |     for (const auto &[ukid, key] : _store)
 437 |         if (key.accinfo == accinfo)
 438 |             matches.push_back(&key);
 439 |     return matches;
 440 | }
 441 | 
 442 | std::vector<const Key *> KeyStore::getAllKeys() {
 443 |     if (!_initialized)
 444 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 445 |     std::vector<const Key *> keys;
 446 |     keys.reserve(_store.size());
 447 |     for (const auto &[ukid, key] : _store)
 448 |         keys.push_back(&key);
 449 |     return keys;
 450 | }
 451 | 
 452 | // ---------------------------------------------------------------------------
 453 | // Encryption / decryption  (AES-256-GCM)
 454 | // ---------------------------------------------------------------------------
 455 | 
 456 | EncryptedBlob KeyStore::encryptStore() {
 457 |     if (!_initialized)
 458 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 459 |     EncryptedBlob blob;
 460 |     blob.nonce.resize(ENC_BLOB_NONCE_SIZE);
 461 |     if (RAND_bytes(blob.nonce.data(), static_cast<int>(ENC_BLOB_NONCE_SIZE)) !=
 462 |         1)
 463 |         throw std::runtime_error("encryptStore: RAND_bytes failed");
 464 | 
 465 |     EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
 466 |     if (!ctx)
 467 |         throw std::runtime_error("encryptStore: EVP_CIPHER_CTX_new failed");
 468 | 
 469 |     if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
 470 |                            _encryptionKey.data(), blob.nonce.data()) != 1) {
 471 |         EVP_CIPHER_CTX_free(ctx);
 472 |         throw std::runtime_error("encryptStore: EVP_EncryptInit_ex failed");
 473 |     }
 474 | 
 475 |     // Prepend the magic signature so we can detect a wrong password on decrypt.
 476 |     Bytes storeSerial = serialize();
 477 |     Bytes plaintext;
 478 |     plaintext.reserve(storeSerial.size());
 479 |     plaintext.insert(plaintext.end(), storeSerial.begin(), storeSerial.end());
 480 | 
 481 |     blob.ciphertext.resize(plaintext.size()); // GCM produces no expansion
 482 | 
 483 |     int outlen = 0, finallen = 0;
 484 |     if (EVP_EncryptUpdate(ctx, blob.ciphertext.data(), &outlen,
 485 |                           plaintext.data(),
 486 |                           static_cast<int>(plaintext.size())) != 1) {
 487 |         EVP_CIPHER_CTX_free(ctx);
 488 |         throw std::runtime_error("encryptStore: EVP_EncryptUpdate failed");
 489 |     }
 490 |     if (EVP_EncryptFinal_ex(ctx, blob.ciphertext.data() + outlen, &finallen) !=
 491 |         1) {
 492 |         EVP_CIPHER_CTX_free(ctx);
 493 |         throw std::runtime_error("encryptStore: EVP_EncryptFinal_ex failed");
 494 |     }
 495 | 
 496 |     blob.tag.resize(ENC_BLOB_TAG_SIZE);
 497 |     if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
 498 |                             static_cast<int>(ENC_BLOB_TAG_SIZE),
 499 |                             blob.tag.data()) != 1) {
 500 |         EVP_CIPHER_CTX_free(ctx);
 501 |         throw std::runtime_error("encryptStore: GCM tag extraction failed");
 502 |     }
 503 |     EVP_CIPHER_CTX_free(ctx);
 504 |     return blob;
 505 | }
 506 | 
 507 | void KeyStore::decryptStore(const EncryptedBlob &blob) {
 508 |     if (!_initialized)
 509 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 510 |     if (blob.nonce.size() != ENC_BLOB_NONCE_SIZE)
 511 |         throw std::runtime_error("decryptStore: invalid nonce size");
 512 |     if (blob.tag.size() != ENC_BLOB_TAG_SIZE)
 513 |         throw std::runtime_error("decryptStore: invalid tag size");
 514 | 
 515 |     EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
 516 |     if (!ctx)
 517 |         throw std::runtime_error("decryptStore: EVP_CIPHER_CTX_new failed");
 518 | 
 519 |     if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
 520 |                            _encryptionKey.data(), blob.nonce.data()) != 1) {
 521 |         EVP_CIPHER_CTX_free(ctx);
 522 |         throw std::runtime_error("decryptStore: EVP_DecryptInit_ex failed");
 523 |     }
 524 | 
 525 |     Bytes plaintext(blob.ciphertext.size());
 526 |     int outlen = 0, finallen = 0;
 527 | 
 528 |     if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen,
 529 |                           blob.ciphertext.data(),
 530 |                           static_cast<int>(blob.ciphertext.size())) != 1) {
 531 |         EVP_CIPHER_CTX_free(ctx);
 532 |         throw std::runtime_error("decryptStore: EVP_DecryptUpdate failed");
 533 |     }
 534 | 
 535 |     // Set the expected GCM authentication tag before calling Final.
 536 |     if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
 537 |                             static_cast<int>(blob.tag.size()),
 538 |                             const_cast<Byte *>(blob.tag.data())) != 1) {
 539 |         EVP_CIPHER_CTX_free(ctx);
 540 |         throw std::runtime_error("decryptStore: failed to set GCM tag");
 541 |     }
 542 | 
 543 |     int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &finallen);
 544 |     EVP_CIPHER_CTX_free(ctx);
 545 | 
 546 |     if (ret <= 0) {
 547 |         OPENSSL_cleanse(plaintext.data(), plaintext.size());
 548 |         throw std::runtime_error("decryptStore: authentication tag mismatch — "
 549 |                                  "data corrupted, tampered, or wrong key");
 550 |     }
 551 | 
 552 |     plaintext.resize(static_cast<size_t>(outlen + finallen));
 553 | 
 554 |     Bytes serialized(plaintext.begin(), plaintext.end());
 555 |     OPENSSL_cleanse(plaintext.data(), plaintext.size());
 556 | 
 557 |     deserialize(serialized);
 558 | }
 559 | 
 560 | // ---------------------------------------------------------------------------
 561 | // Serialisation (unencrypted, in-memory only — always goes through encrypt)
 562 | // ---------------------------------------------------------------------------
 563 | 
 564 | Bytes KeyStore::serialize() {
 565 |     if (!_initialized)
 566 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 567 |     Bytes out;
 568 |     out.reserve(size());
 569 | 
 570 |     writeu32(out, static_cast<uint32_t>(_store.size()));
 571 |     for (const auto &[ukid, key] : _store) {
 572 |         Bytes k = key.serialize();
 573 |         writeu32(out, static_cast<uint32_t>(k.size()));
 574 |         out.insert(out.end(), k.begin(), k.end());
 575 |     }
 576 |     return out;
 577 | }
 578 | 
 579 | void KeyStore::deserialize(const Bytes &data) {
 580 |     if (!_initialized)
 581 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 582 |     _store.clear();
 583 | 
 584 |     if (data.size() < 4)
 585 |         throw std::runtime_error("KeyStore::deserialize: missing key count");
 586 | 
 587 |     uint32_t nKeys = readu32(data.data());
 588 |     if (nKeys > MAX_KEY_COUNT)
 589 |         throw std::runtime_error("implausible number of keys!");
 590 |     size_t offset = 4;
 591 | 
 592 |     for (uint32_t i = 0; i < nKeys; ++i) {
 593 |         if (offset + 4 > data.size())
 594 |             throw std::runtime_error(
 595 |                 "KeyStore::deserialize: truncated key-size field");
 596 | 
 597 |         uint32_t keySize = readu32(data.data() + offset);
 598 |         offset += 4;
 599 | 
 600 |         if (keySize > data.size() - offset)
 601 |             throw std::runtime_error(
 602 |                 "KeyStore::deserialize: key size overflows buffer");
 603 | 
 604 |         Key k = Key::deserialize(
 605 |             Bytes(data.begin() + static_cast<ptrdiff_t>(offset),
 606 |                   data.begin() + static_cast<ptrdiff_t>(offset + keySize)));
 607 |         offset += keySize;
 608 | 
 609 |         Bytes ukid = getUKID(k);
 610 |         _store[ukid] = std::move(k);
 611 |     }
 612 | 
 613 |     if (offset != data.size())
 614 |         throw std::runtime_error("KeyStore::deserialize: trailing bytes");
 615 | }
 616 | 
 617 | // ---------------------------------------------------------------------------
 618 | // Persistence
 619 | // ---------------------------------------------------------------------------
 620 | 
 621 | void KeyStore::saveStore() {
 622 |     if (!_initialized)
 623 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 624 |     EncryptedBlob eb = encryptStore();
 625 |     Bytes ebSerial = eb.serialize();
 626 | 
 627 |     // On-disk layout: [salt:16][encrypted_blob...]
 628 |     Bytes storeData;
 629 |     storeData.reserve(PBKDF2_SALT_SIZE + ebSerial.size());
 630 |     storeData.insert(storeData.end(), _salt.begin(), _salt.end());
 631 |     storeData.insert(storeData.end(), ebSerial.begin(), ebSerial.end());
 632 | 
 633 |     writeAtomic(Paths::keyfile(), storeData, 0600);
 634 | }
 635 | 
 636 | void KeyStore::loadStore() {
 637 |     if (!_initialized)
 638 |         throw std::runtime_error("KeyStore has not been initialized yet!");
 639 |     Bytes storeData = readAtomic(Paths::keyfile());
 640 |     // Skip the salt prefix (already read during init).
 641 |     Bytes ebSerial(storeData.begin() + static_cast<ptrdiff_t>(PBKDF2_SALT_SIZE),
 642 |                    storeData.end());
 643 |     EncryptedBlob eb = EncryptedBlob::deserialize(ebSerial);
 644 |     decryptStore(eb);
 645 | }
  

`src/bifrost.cpp`:

   1 | #include <KeyStore.hpp>
   2 | #include <algorithm>
   3 | #include <bifrost.hpp>
   4 | #include <cstdio>
   5 | #include <cstdlib>
   6 | #include <cstring>
   7 | #include <filesystem>
   8 | #include <iomanip>
   9 | #include <iostream>
  10 | #include <limits>
  11 | #include <securebytes.hpp>
  12 | #include <stdexcept>
  13 | #include <string>
  14 | #include <terminal-launch.hpp>
  15 | #include <tls.hpp>
  16 | #include <totp.hpp>
  17 | #include <unistd.h>
  18 | #include <utility.hpp>
  19 | 
  20 | namespace fs = std::filesystem;
  21 | 
  22 | // ---------------------------------------------------------------------------
  23 | // UI helpers
  24 | // ---------------------------------------------------------------------------
  25 | 
  26 | // Render a simple ASCII progress bar of totalLen characters filled to
  27 | // percentage (0.0–1.0).
  28 | void printProgressBar(float percentage, int totalLen) {
  29 |     percentage = std::clamp(percentage, 0.0f, 1.0f);
  30 |     int nFilled = static_cast<int>(percentage * static_cast<float>(totalLen));
  31 | 
  32 |     std::cout << '[';
  33 |     for (int i = 0; i < nFilled; ++i)
  34 |         std::cout << '#';
  35 |     for (int i = nFilled; i < totalLen; ++i)
  36 |         std::cout << '-';
  37 |     std::cout << ']';
  38 | }
  39 | 
  40 | // ---------------------------------------------------------------------------
  41 | // Password unlock
  42 | // ---------------------------------------------------------------------------
  43 | 
  44 | // Prompt for the Bifrost password, derive the key, and load the store.
  45 | // On failure the error is printed and the process exits — there is no
  46 | // meaningful recovery if we cannot access the key store.
  47 | void unlockBifrost() {
  48 |     if (fs::exists(Paths::keyfile()))
  49 |         std::cout << "Enter Bifrost password: ";
  50 |     else
  51 |         std::cout << "Setup Bifrost password: ";
  52 | 
  53 |     std::string passwd;
  54 |     std::cin >> passwd;
  55 | 
  56 |     try {
  57 |         KeyStore::init(passwd);
  58 |     } catch (const std::runtime_error &e) {
  59 |         std::cerr << "Incorrect password or corrupted keyfile: " << e.what()
  60 |                   << "\n";
  61 |         exit(EXIT_FAILURE);
  62 |     }
  63 | }
  64 | 
  65 | // ---------------------------------------------------------------------------
  66 | // Entry point
  67 | // ---------------------------------------------------------------------------
  68 | 
  69 | int main(int argc, char **argv) {
  70 |     // argv[1] == SENTINEL_FLAG means we were re-launched inside a terminal.
  71 |     bool inTerminal =
  72 |         (argc > 1 && std::strcmp(argv[1], SENTINEL_FLAG.data()) == 0);
  73 | 
  74 |     if (!inTerminal) {
  75 |         // First launch (no terminal): fork a child, let it re-exec inside a
  76 |         // terminal emulator, and exit the parent immediately.  On Windows we
  77 |         // use CreateProcess instead (handled by launchInTerminal).
  78 |         std::string selfPath;
  79 |         try {
  80 |             selfPath = getSelfPath();
  81 |         } catch (const std::exception &e) {
  82 |             std::cerr << e.what() << std::endl;
  83 |             return EXIT_FAILURE;
  84 |         }
  85 | 
  86 | #if defined(_WIN32)
  87 |         launchInTerminal(selfPath, argc, argv);
  88 |         return EXIT_SUCCESS;
  89 | #else
  90 |         pid_t pid = fork();
  91 |         if (pid == -1) {
  92 |             std::perror("fork failed");
  93 |             return EXIT_FAILURE;
  94 |         }
  95 |         if (pid == 0)
  96 |             launchInTerminal(selfPath, argc, argv);
  97 |         // Parent exits; child exec-replaces itself with the terminal emulator.
  98 |         return EXIT_SUCCESS;
  99 | #endif
 100 |     }
 101 | 
 102 |     // ── Initialise paths and unlock the key store ───────────────────────────
 103 |     Paths::init();
 104 |     unlockBifrost();
 105 |     std::cout << "\n";
 106 | 
 107 |     // ── Optional registration via a bifrost-totp:// URL ─────────────────────
 108 |     // argv[1] is SENTINEL_FLAG; the URL is at argv[2] when present.
 109 |     if (argc > 2) {
 110 |         ConnInfo connInfo = getConnInfo(argv[2]);
 111 |         std::cout << "Connecting to\n"
 112 |                   << "  Host: " << connInfo.host << "\n"
 113 |                   << "  Port: " << connInfo.port << "\n\n";
 114 | 
 115 |         Key key = registerBifrost(connInfo);
 116 |         KeyStore::store(key);
 117 |         KeyStore::saveStore();
 118 | 
 119 |         // Pause so the user can read any registration output before the
 120 |         // display loop clears the screen.
 121 |         std::cout << "\n\nPress Enter to continue...";
 122 |         std::cin.clear();
 123 |         std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
 124 |         std::cin.get();
 125 |     }
 126 | 
 127 |     // ── TOTP display loop ───────────────────────────────────────────────────
 128 |     auto keys = KeyStore::getAllKeys();
 129 | 
 130 |     while (true) {
 131 |         // Clear screen and move cursor to top-left (VT100).
 132 |         std::cout << "\033[2J\033[1;1H" << std::flush;
 133 |         std::cout << "Current Keys:\n";
 134 | 
 135 |         for (const auto *key : keys) {
 136 |             std::cout << "Account: " << key->accinfo << "\n";
 137 |             std::cout << "  Server CN   : " << key->commonName << "\n";
 138 |             std::cout << "  Fingerprint : ";
 139 |             printBytes(std::cout, key->fingerprint);
 140 |             std::cout << "\n  SANs        :";
 141 |             for (const auto &s : key->sans)
 142 |                 std::cout << " " << s;
 143 |             std::cout << "\n";
 144 | 
 145 |             auto [otp, validity] = generateOTP(key->secret);
 146 |             std::cout << "  TOTP        : " << std::setfill('0')
 147 |                       << std::setw(OTP_SIZE) << otp << "\n";
 148 |             std::cout << "  Validity    : " << validity << "s  ";
 149 |             printProgressBar(static_cast<float>(validity) / TIME_WINDOW, 30);
 150 |             std::cout << "\n\n";
 151 |         }
 152 | 
 153 |         std::cout << std::endl;
 154 |         usleep(500'000); // refresh twice per second
 155 |     }
 156 | }
  

`src/terminal-launch.cpp`:

   1 | #include <cstdio>
   2 | #include <cstdlib>
   3 | #include <cstring>
   4 | #include <stdexcept>
   5 | #include <string>
   6 | #include <terminal-launch.hpp>
   7 | 
   8 | #if defined(_WIN32)
   9 | #include <windows.h>
  10 | #elif defined(__APPLE__)
  11 | #include <mach-o/dyld.h>
  12 | #include <unistd.h>
  13 | #else
  14 | #include <unistd.h>
  15 | #endif
  16 | 
  17 | // ---------------------------------------------------------------------------
  18 | // getSelfPath
  19 | // ---------------------------------------------------------------------------
  20 | 
  21 | std::string getSelfPath() {
  22 | #if defined(_WIN32)
  23 |     char buf[MAX_PATH];
  24 |     DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
  25 |     if (len == 0 || len == MAX_PATH)
  26 |         throw std::runtime_error("getSelfPath: GetModuleFileNameA failed");
  27 |     return std::string(buf, len);
  28 | 
  29 | #elif defined(__APPLE__)
  30 |     char buf[4096];
  31 |     uint32_t size = sizeof(buf);
  32 |     if (_NSGetExecutablePath(buf, &size) != 0)
  33 |         throw std::runtime_error(
  34 |             "getSelfPath: _NSGetExecutablePath buffer too small");
  35 |     return std::string(buf);
  36 | 
  37 | #else
  38 |     char buf[4096];
  39 |     ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  40 |     if (len == -1) {
  41 |         std::perror("getSelfPath: readlink failed");
  42 |         throw std::runtime_error("getSelfPath: readlink failed");
  43 |     }
  44 |     buf[len] = '\0';
  45 |     return std::string(buf);
  46 | #endif
  47 | }
  48 | 
  49 | // ---------------------------------------------------------------------------
  50 | // shQuote
  51 | // ---------------------------------------------------------------------------
  52 | 
  53 | // Single-quote–escape a string for safe embedding inside a POSIX 'sh -c' arg.
  54 | // Technique: close the quote, emit \', reopen the quote.
  55 | // Example: "it's"  →  'it'\''s'
  56 | std::string shQuote(const std::string &s) {
  57 |     std::string out = "'";
  58 |     for (char c : s) {
  59 |         if (c == '\'')
  60 |             out += "'\\''";
  61 |         else
  62 |             out.push_back(c);
  63 |     }
  64 |     out += "'";
  65 |     return out;
  66 | }
  67 | 
  68 | // ---------------------------------------------------------------------------
  69 | // launchInTerminal
  70 | // ---------------------------------------------------------------------------
  71 | 
  72 | void launchInTerminal(const std::string &selfPath, int argc, char **argv) {
  73 | #if defined(_WIN32)
  74 |     // Build:  cmd.exe /K "<selfPath>" --__in_terminal__ "arg1" "arg2" ...
  75 |     std::string inner = "\"" + selfPath + "\" " + std::string(SENTINEL_FLAG);
  76 |     for (int i = 1; i < argc; ++i)
  77 |         inner += " \"" + std::string(argv[i]) + "\"";
  78 | 
  79 |     std::string cmdLine = "cmd.exe /K \"" + inner + "\"";
  80 | 
  81 |     STARTUPINFOA si{};
  82 |     si.cb = sizeof(si);
  83 |     PROCESS_INFORMATION pi{};
  84 | 
  85 |     if (!CreateProcessA(nullptr, cmdLine.data(), nullptr, nullptr, FALSE,
  86 |                         CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
  87 |         std::fprintf(stderr, "launchInTerminal: CreateProcess error %lu\n",
  88 |                      GetLastError());
  89 |         exit(EXIT_FAILURE);
  90 |     }
  91 |     CloseHandle(pi.hProcess);
  92 |     CloseHandle(pi.hThread);
  93 |     exit(EXIT_SUCCESS);
  94 | 
  95 | #elif defined(__APPLE__)
  96 |     // Drive Terminal.app via AppleScript; execlp replaces this process.
  97 |     std::string shellCmd = shQuote(selfPath) + " " + std::string(SENTINEL_FLAG);
  98 |     for (int i = 1; i < argc; ++i)
  99 |         shellCmd += " " + shQuote(argv[i]);
 100 | 
 101 |     // Escape backslashes and double-quotes for embedding in an AppleScript
 102 |     // double-quoted string literal.
 103 |     std::string escaped;
 104 |     escaped.reserve(shellCmd.size());
 105 |     for (char c : shellCmd) {
 106 |         if (c == '\\' || c == '"')
 107 |             escaped.push_back('\\');
 108 |         escaped.push_back(c);
 109 |     }
 110 | 
 111 |     std::string osa =
 112 |         "tell application \"Terminal\" to do script \"" + escaped + "\"";
 113 | 
 114 |     execlp("osascript", "osascript", "-e", osa.c_str(),
 115 |            static_cast<char *>(nullptr));
 116 |     std::perror("launchInTerminal: exec osascript failed");
 117 |     exit(EXIT_FAILURE);
 118 | 
 119 | #else
 120 |     // Linux / BSD: build a properly-quoted shell command, then try a priority
 121 |     // list of terminal emulators, falling back if the first isn't installed.
 122 |     std::string innerCmd = shQuote(selfPath) + " " + std::string(SENTINEL_FLAG);
 123 |     for (int i = 1; i < argc; ++i)
 124 |         innerCmd += " " + shQuote(argv[i]);
 125 |     innerCmd += "; exec bash"; // keep the terminal open after the process exits
 126 | 
 127 |     // gnome-terminal / terminator use "--" as the separator before the command;
 128 |     // all others use "-e".
 129 |     static const char *terminals[] = {
 130 |         "x-terminal-emulator", "gnome-terminal", "konsole",    "xfce4-terminal",
 131 |         "alacritty",           "kitty",          "terminator", "xterm",
 132 |     };
 133 | 
 134 |     for (const char *term : terminals) {
 135 |         bool uses_dash_dash = (std::strcmp(term, "gnome-terminal") == 0 ||
 136 |                                std::strcmp(term, "terminator") == 0);
 137 |         const char *sep = uses_dash_dash ? "--" : "-e";
 138 | 
 139 |         execlp(term, term, sep, "bash", "-c", innerCmd.c_str(),
 140 |                static_cast<char *>(nullptr));
 141 |         // execlp only returns on failure — try the next candidate.
 142 |     }
 143 | 
 144 |     std::perror("launchInTerminal: no terminal emulator found");
 145 |     exit(EXIT_FAILURE);
 146 | #endif
 147 | }
  

`src/tls.cpp`:

   1 | #include <cstdint>
   2 | #include <limits>
   3 | #include <openssl/crypto.h>
   4 | #include <openssl/err.h>
   5 | #include <openssl/prov_ssl.h>
   6 | #include <openssl/ssl.h>
   7 | #include <openssl/tls1.h>
   8 | #include <openssl/x509_vfy.h>
   9 | #include <openssl/x509v3.h>
  10 | #include <securebytes.hpp>
  11 | #include <totp.hpp>
  12 | 
  13 | #include <arpa/inet.h>
  14 | #include <netdb.h>
  15 | #include <netinet/in.h>
  16 | #include <sys/socket.h>
  17 | #include <unistd.h>
  18 | 
  19 | #include <KDF.hpp>
  20 | #include <KeyStore.hpp>
  21 | #include <bifrost.hpp>
  22 | #include <cstring>
  23 | #include <iostream>
  24 | #include <stdexcept>
  25 | #include <string>
  26 | #include <tls.hpp>
  27 | #include <utility.hpp>
  28 | 
  29 | // ---------------------------------------------------------------------------
  30 | // Exception helper
  31 | // ---------------------------------------------------------------------------
  32 | 
  33 | // Drain the OpenSSL error queue into a single runtime_error message.
  34 | // Entries are chained with " <- " to show the full call stack.
  35 | void throw_ssl_error(const std::string &context) {
  36 |     std::string msg = context;
  37 |     char buf[256];
  38 |     bool first = true;
  39 | 
  40 |     unsigned long err;
  41 |     while ((err = ERR_get_error()) != 0) {
  42 |         ERR_error_string_n(err, buf, sizeof(buf));
  43 |         msg += first ? ": " : " <- ";
  44 |         msg += buf;
  45 |         first = false;
  46 |     }
  47 |     if (first)
  48 |         msg += ": (no OpenSSL error queue entry)";
  49 | 
  50 |     throw std::runtime_error(msg);
  51 | }
  52 | 
  53 | // ---------------------------------------------------------------------------
  54 | // SSL_CTX factory
  55 | // ---------------------------------------------------------------------------
  56 | 
  57 | // Build a fully-hardened client context.  Takes fs::path by const-ref so
  58 | // callers can pass Paths::rootCACert() etc. directly without a decay to char*.
  59 | SSL_CTX *create_client_ctx(const fs::path &ca_cert,
  60 |                            const fs::path &client_chain,
  61 |                            const fs::path &client_key) {
  62 |     SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  63 |     if (!ctx)
  64 |         throw_ssl_error("SSL_CTX_new");
  65 | 
  66 |     // ── Version floor/ceiling: TLS 1.2–1.3 ─────────────────────────────────
  67 |     if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
  68 |         throw_ssl_error("set_min_proto_version");
  69 |     if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1)
  70 |         throw_ssl_error("set_max_proto_version");
  71 | 
  72 |     // ── TLS 1.2 cipher pinning ──────────────────────────────────────────────
  73 |     if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:"
  74 |                                      "ECDHE-RSA-AES256-GCM-SHA384:"
  75 |                                      "ECDHE-ECDSA-AES128-GCM-SHA256:"
  76 |                                      "ECDHE-RSA-AES128-GCM-SHA256:"
  77 |                                      "ECDHE-ECDSA-CHACHA20-POLY1305:"
  78 |                                      "ECDHE-RSA-CHACHA20-POLY1305") != 1)
  79 |         throw_ssl_error("set_cipher_list");
  80 | 
  81 |     // ── TLS 1.3 cipher suites ───────────────────────────────────────────────
  82 |     if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:"
  83 |                                       "TLS_CHACHA20_POLY1305_SHA256:"
  84 |                                       "TLS_AES_128_GCM_SHA256") != 1)
  85 |         throw_ssl_error("set_ciphersuites");
  86 | 
  87 |     // ── Server certificate verification ─────────────────────────────────────
  88 |     if (SSL_CTX_load_verify_locations(ctx, ca_cert.c_str(), nullptr) != 1)
  89 |         throw_ssl_error("load_verify_locations (root CA)");
  90 | 
  91 |     SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
  92 |     SSL_CTX_set_verify_depth(ctx, 2);
  93 | 
  94 |     // ── Client certificate (mTLS) ────────────────────────────────────────────
  95 |     if (SSL_CTX_use_certificate_chain_file(ctx, client_chain.c_str()) != 1)
  96 |         throw_ssl_error("use_certificate_chain_file (client chain)");
  97 | 
  98 |     if (SSL_CTX_use_PrivateKey_file(ctx, client_key.c_str(),
  99 |                                     SSL_FILETYPE_PEM) != 1)
 100 |         throw_ssl_error("use_PrivateKey_file (client key)");
 101 | 
 102 |     if (SSL_CTX_check_private_key(ctx) != 1)
 103 |         throw_ssl_error("check_private_key (client)");
 104 | 
 105 |     // ── ECDH curve selection ─────────────────────────────────────────────────
 106 |     if (SSL_CTX_set1_curves_list(ctx, "X25519:P-256:P-384") != 1)
 107 |         throw_ssl_error("set1_curves_list");
 108 | 
 109 |     // ── Security options ─────────────────────────────────────────────────────
 110 |     // Disable session tickets (stateless resumption) and TLS compression.
 111 |     SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);
 112 |     // Disable caching the master secret for session resumption
 113 |     SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
 114 | 
 115 |     return ctx;
 116 | }
 117 | 
 118 | // ---------------------------------------------------------------------------
 119 | // Raw TCP connection
 120 | // ---------------------------------------------------------------------------
 121 | 
 122 | int connect_tcp(const std::string &host, uint16_t port) {
 123 |     addrinfo hints{}, *res = nullptr;
 124 |     hints.ai_family = AF_UNSPEC;
 125 |     hints.ai_socktype = SOCK_STREAM;
 126 | 
 127 |     int err =
 128 |         getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);
 129 |     if (err != 0)
 130 |         throw std::runtime_error(std::string("getaddrinfo: ") +
 131 |                                  gai_strerror(err));
 132 | 
 133 |     int fd = -1;
 134 |     for (addrinfo *p = res; p != nullptr; p = p->ai_next) {
 135 |         fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
 136 |         if (fd < 0)
 137 |             continue;
 138 |         if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
 139 |             break;
 140 |         close(fd);
 141 |         fd = -1;
 142 |     }
 143 |     freeaddrinfo(res);
 144 | 
 145 |     if (fd < 0)
 146 |         throw std::runtime_error("TCP connect failed: " + host);
 147 |     return fd;
 148 | }
 149 | 
 150 | // ---------------------------------------------------------------------------
 151 | // TLS handshake + hostname verification
 152 | // ---------------------------------------------------------------------------
 153 | 
 154 | SSL *tls_connect(SSL_CTX *ctx, int tcp_fd, const std::string &hostname,
 155 |                  ConnContext &connCtx) {
 156 |     SSL *ssl = SSL_new(ctx);
 157 |     if (!ssl)
 158 |         throw_ssl_error("SSL_new");
 159 | 
 160 |     // SNI extension — tells the server which virtual host we want.
 161 |     if (SSL_set_tlsext_host_name(ssl, hostname.c_str()) != 1)
 162 |         throw_ssl_error("SSL_set_tlsext_host_name (SNI)");
 163 | 
 164 |     // Configure hostname / IP verification before the handshake.
 165 |     X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
 166 |     X509_VERIFY_PARAM_set_hostflags(vpm, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
 167 | 
 168 |     struct in_addr addr4;
 169 |     struct in6_addr addr6;
 170 |     bool is_ip = (inet_pton(AF_INET, hostname.c_str(), &addr4) == 1 ||
 171 |                   inet_pton(AF_INET6, hostname.c_str(), &addr6) == 1);
 172 | 
 173 |     if (is_ip) {
 174 |         if (X509_VERIFY_PARAM_set1_ip_asc(vpm, hostname.c_str()) != 1)
 175 |             throw_ssl_error("X509_VERIFY_PARAM_set1_ip_asc");
 176 |     } else {
 177 |         if (X509_VERIFY_PARAM_set1_host(vpm, hostname.c_str(),
 178 |                                         hostname.size()) != 1)
 179 |             throw_ssl_error("X509_VERIFY_PARAM_set1_host");
 180 |     }
 181 | 
 182 |     if (SSL_set_fd(ssl, tcp_fd) != 1)
 183 |         throw_ssl_error("SSL_set_fd");
 184 | 
 185 |     if (SSL_connect(ssl) != 1)
 186 |         throw_ssl_error("SSL_connect (handshake)");
 187 | 
 188 |     std::cout << "[TLS] Version   : " << SSL_get_version(ssl) << "\n";
 189 |     std::cout << "[TLS] Cipher    : " << SSL_get_cipher(ssl) << "\n";
 190 | 
 191 |     // SSL_connect already runs hostname verification when SSL_VERIFY_PEER is
 192 |     // set; this redundant check is a belt-and-suspenders safeguard.
 193 |     long verify_result = SSL_get_verify_result(ssl);
 194 |     if (verify_result != X509_V_OK) {
 195 |         SSL_free(ssl);
 196 |         throw std::runtime_error(
 197 |             std::string("server cert verification failed: ") +
 198 |             X509_verify_cert_error_string(verify_result));
 199 |     }
 200 | 
 201 |     X509 *server_cert = SSL_get_peer_certificate(ssl);
 202 |     if (server_cert) {
 203 |         char subject_buf[256] = {};
 204 |         X509_NAME_oneline(X509_get_subject_name(server_cert), subject_buf,
 205 |                           sizeof(subject_buf));
 206 |         std::cout << "[TLS] Server cert: " << subject_buf << "\n";
 207 |         X509_free(server_cert);
 208 |     }
 209 | 
 210 |     // Derive the exporter secret via RFC 5705 / RFC 8446 §7.5.  Both client
 211 |     // and server call export_keying_material with the same label and receive
 212 |     // identical material, independent of the TLS version.
 213 |     connCtx.exporterSecret.resize(EXPORTER_SECRET_SIZE);
 214 |     if (SSL_export_keying_material(
 215 |             ssl, connCtx.exporterSecret.data(), EXPORTER_SECRET_SIZE,
 216 |             EXPORTER_SECRET_LABEL.data(), EXPORTER_SECRET_LABEL.size(), nullptr,
 217 |             0, 0) != 1)
 218 |         throw_ssl_error("SSL_export_keying_material");
 219 | 
 220 |     return ssl;
 221 | }
 222 | 
 223 | // ---------------------------------------------------------------------------
 224 | // Secure send / recv
 225 | // ---------------------------------------------------------------------------
 226 | 
 227 | // Loop until all len bytes are sent; handles short SSL_write returns.
 228 | void tls_send(SSL *ssl, const void *data, size_t len) {
 229 |     if (len > static_cast<size_t>(std::numeric_limits<int>::max()))
 230 |         throw std::runtime_error(
 231 |             "tls_send: payload exceeds SSL_write int limit");
 232 | 
 233 |     size_t sent = 0;
 234 |     while (sent < len) {
 235 |         int chunk = static_cast<int>(std::min(
 236 |             len - sent, static_cast<size_t>(std::numeric_limits<int>::max())));
 237 |         int n = SSL_write(ssl, static_cast<const char *>(data) + sent, chunk);
 238 |         if (n <= 0)
 239 |             throw_ssl_error("SSL_write failed: " +
 240 |                             std::to_string(SSL_get_error(ssl, n)));
 241 |         sent += static_cast<size_t>(n);
 242 |     }
 243 | }
 244 | 
 245 | // Single SSL_read up to max_bytes.  Returns only bytes actually received.
 246 | std::string tls_recv(SSL *ssl, size_t max_bytes) {
 247 |     if (max_bytes > static_cast<size_t>(std::numeric_limits<int>::max()))
 248 |         throw std::runtime_error(
 249 |             "tls_recv: max_bytes exceeds SSL_read int limit");
 250 | 
 251 |     std::string buf(max_bytes, '\0');
 252 |     int n = SSL_read(ssl, buf.data(), static_cast<int>(max_bytes));
 253 |     if (n <= 0) {
 254 |         int err = SSL_get_error(ssl, n);
 255 |         if (err == SSL_ERROR_ZERO_RETURN)
 256 |             throw std::runtime_error("SSL_read: peer closed connection");
 257 |         throw_ssl_error("SSL_read failed: " + std::to_string(err));
 258 |     }
 259 |     buf.resize(static_cast<size_t>(n));
 260 |     return buf;
 261 | }
 262 | 
 263 | // ---------------------------------------------------------------------------
 264 | // Teardown
 265 | // ---------------------------------------------------------------------------
 266 | 
 267 | // Two-phase shutdown per RFC 8446 §6.1: send close_notify, wait for peer's.
 268 | // If the second call fails we log a warning but do not throw — the connection
 269 | // is already logically closed.
 270 | void tls_shutdown(SSL *ssl, int tcp_fd) {
 271 |     int ret = SSL_shutdown(ssl);
 272 |     if (ret == 0) {
 273 |         ret = SSL_shutdown(ssl);
 274 |         if (ret < 0) {
 275 |             int err = SSL_get_error(ssl, ret);
 276 |             std::cerr << "[TLS] shutdown incomplete, SSL error: " << err
 277 |                       << "\n";
 278 |         }
 279 |     }
 280 |     SSL_free(ssl);
 281 |     close(tcp_fd);
 282 | }
 283 | 
 284 | // ---------------------------------------------------------------------------
 285 | // Registration helpers
 286 | // ---------------------------------------------------------------------------
 287 | 
 288 | ServerRegData fetchServerRegData(SSL *ssl, int tcp_fd, const std::string &host,
 289 |                                  const std::string &path) {
 290 |     // Build a minimal HTTP/1.1 GET; Connection: close tells the server we
 291 |     // do not want keep-alive so it sends a close_notify after the response.
 292 |     std::string request = "GET " + path +
 293 |                           " HTTP/1.1\r\n"
 294 |                           "Host: " +
 295 |                           host +
 296 |                           "\r\n"
 297 |                           "Connection: close\r\n\r\n";
 298 | 
 299 |     tls_send(ssl, request.c_str(), request.size());
 300 | 
 301 |     std::string resp = tls_recv(ssl, 4096);
 302 | 
 303 |     size_t body_pos = resp.find("\r\n\r\n");
 304 |     if (body_pos == std::string::npos) {
 305 |         tls_shutdown(ssl, tcp_fd);
 306 |         throw std::runtime_error(
 307 |             "fetchServerRegData: missing HTTP header delimiter");
 308 |     }
 309 |     std::string body = resp.substr(body_pos + 4);
 310 | 
 311 |     auto params = parseURLParams(body, '&', '=');
 312 |     if (!params.contains("PW_KEY") || !params.contains("ACC_INFO"))
 313 |         throw std::runtime_error(
 314 |             "fetchServerRegData: missing required fields in body:\n" + body);
 315 | 
 316 |     // Decode the hex-encoded key and wrap it immediately in SecureBytes so
 317 |     // the plain Bytes copy is wiped as soon as it goes out of scope.
 318 |     auto pwkey_bytes = hexToBytes(params["PW_KEY"]);
 319 |     SecureBytes pwkey(pwkey_bytes);
 320 |     OPENSSL_cleanse(pwkey_bytes.data(), pwkey_bytes.size());
 321 |     OPENSSL_cleanse(resp.data(), resp.size());
 322 | 
 323 |     return {pwkey.clone(), std::string(params["ACC_INFO"])};
 324 | }
 325 | 
 326 | ConnInfo getConnInfo(std::string_view serverArgs) {
 327 |     if (!serverArgs.starts_with(BIFROST_PROTOCOL))
 328 |         throw std::runtime_error("getConnInfo: invalid protocol in URL");
 329 | 
 330 |     std::string_view urlParams = serverArgs.substr(BIFROST_PROTOCOL.size());
 331 |     auto params = parseURLParams(urlParams);
 332 | 
 333 |     if (!params.contains("host") || !params.contains("port"))
 334 |         throw std::runtime_error("getConnInfo: URL missing 'host' or 'port'");
 335 | 
 336 |     std::string host_raw(params["host"]);
 337 |     std::string portstr(params["port"]);
 338 | 
 339 |     // The "host" param may carry a path suffix (e.g.
 340 |     // "server.example/signup/42").
 341 |     std::string host, path;
 342 |     size_t slash_pos = host_raw.find('/');
 343 |     if (slash_pos != std::string::npos) {
 344 |         host = host_raw.substr(0, slash_pos);
 345 |         path = host_raw.substr(slash_pos);
 346 |     } else {
 347 |         host = host_raw;
 348 |         path = "/";
 349 |     }
 350 | 
 351 |     auto port_ull = std::stoull(portstr, nullptr, 10);
 352 |     if (port_ull > UINT16_MAX)
 353 |         throw std::runtime_error("getConnInfo: port out of range");
 354 | 
 355 |     return {host, static_cast<uint16_t>(port_ull), path};
 356 | }
 357 | 
 358 | Key registerBifrost(const ConnInfo &connInfo) {
 359 |     // These calls are safe to repeat and have been required since OpenSSL 1.1.0
 360 |     // for builds that don't auto-initialise.
 361 |     SSL_load_error_strings();
 362 |     OpenSSL_add_ssl_algorithms();
 363 | 
 364 |     SSL_CTX *ctx = nullptr;
 365 |     SSL *ssl = nullptr;
 366 |     int fd = -1;
 367 |     ConnContext connCtx;
 368 |     ServerRegData regData;
 369 |     Key newKey;
 370 | 
 371 |     try {
 372 |         ctx = create_client_ctx(Paths::rootCACert(), Paths::certChain(),
 373 |                                 Paths::privKey());
 374 |         fd = connect_tcp(connInfo.host, connInfo.port);
 375 |         ssl = tls_connect(ctx, fd, connInfo.host, connCtx);
 376 |         // connCtx.exporterSecret is now populated by tls_connect.
 377 | 
 378 |         regData = fetchServerRegData(ssl, fd, connInfo.host, connInfo.path);
 379 | 
 380 |         auto *cert = SSL_get0_peer_certificate(ssl);
 381 |         newKey = KeyStore::buildKey(cert);
 382 |         newKey.accinfo = regData.ACC_INFO;
 383 | 
 384 |         // Derive the final TOTP key: HKDF(exporterSecret, serverKey, info).
 385 |         // TOTP_HKDF_INFO is exactly 16 bytes (no null terminator) per tls.hpp.
 386 |         hkdf_sha256(connCtx.exporterSecret, regData.KEY, TOTP_HKDF_INFO,
 387 |                     TOTP_KEY_LEN, newKey.secret);
 388 | 
 389 |         tls_shutdown(ssl, fd);
 390 |         ssl = nullptr;
 391 |         fd = -1;
 392 | 
 393 |     } catch (const std::exception &e) {
 394 |         std::cerr << "[FATAL] " << e.what() << "\n";
 395 |         if (ssl)
 396 |             SSL_free(ssl);
 397 |         if (fd >= 0)
 398 |             close(fd);
 399 |         SSL_CTX_free(ctx);
 400 |         throw std::runtime_error("registerBifrost: registration failed");
 401 |     }
 402 | 
 403 |     SSL_CTX_free(ctx);
 404 |     return newKey;
 405 | }
  

`src/totp.cpp`:

   1 | #include <bifrost.hpp>
   2 | #include <cmath>
   3 | #include <cstdint>
   4 | #include <ctime>
   5 | #include <openssl/evp.h>
   6 | #include <openssl/hmac.h>
   7 | #include <securebytes.hpp>
   8 | #include <stdexcept>
   9 | #include <totp.hpp>
  10 | #include <utility.hpp>
  11 | 
  12 | // Compute HMAC-SHA256(key, msg).  Returns TOTP_DIGEST_SIZE (20) bytes.
  13 | Bytes generate_hmac_sha256(const SecureBytes &key, const Bytes &msg) {
  14 |     Bytes hash(TOTP_DIGEST_SIZE);
  15 |     unsigned int len = 0;
  16 | 
  17 |     if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
  18 |               reinterpret_cast<const unsigned char *>(msg.data()), msg.size(),
  19 |               hash.data(), &len))
  20 |         throw std::runtime_error(
  21 |             "generate_hmac_sha256: HMAC computation failed");
  22 | 
  23 |     if (len != TOTP_DIGEST_SIZE)
  24 |         throw std::runtime_error(
  25 |             "generate_hmac_sha256: unexpected output length");
  26 | 
  27 |     return hash;
  28 | }
  29 | 
  30 | // Dynamic truncation per RFC 4226 §5.3: the last nibble of the hash selects
  31 | // the offset, then four bytes are read and the top bit is masked off to
  32 | // produce a 31-bit unsigned integer.
  33 | uint32_t genSample(const SecureBytes &key, std::time_t timeStep) {
  34 |     Bytes hash = generate_hmac_sha256(key, timeToBytes(timeStep));
  35 |     Byte offset = hash.back() & 0x0F;
  36 | 
  37 |     uint32_t sample = (static_cast<uint32_t>(hash[offset]) << 24) |
  38 |                       (static_cast<uint32_t>(hash[offset + 1]) << 16) |
  39 |                       (static_cast<uint32_t>(hash[offset + 2]) << 8) |
  40 |                       static_cast<uint32_t>(hash[offset + 3]);
  41 | 
  42 |     sample &= 0x7FFF'FFFF; // clear the top bit per RFC 4226
  43 |     return sample;
  44 | }
  45 | 
  46 | // Generate the current TOTP code and how many seconds remain in the window.
  47 | TOTP generateOTP(const SecureBytes &key) {
  48 |     auto epoch = static_cast<uint32_t>(std::time(nullptr));
  49 |     auto curStep = static_cast<uint32_t>(epoch / TIME_WINDOW);
  50 | 
  51 |     // Use std::pow only for the modulus base; the cast to uint32_t is safe
  52 |     // because OTP_SIZE is 6 and 10^6 = 1,000,000 fits comfortably.
  53 |     uint32_t modulus = static_cast<uint32_t>(std::pow(10, OTP_SIZE));
  54 |     uint32_t otp = genSample(key, static_cast<std::time_t>(curStep)) % modulus;
  55 |     uint32_t validity =
  56 |         static_cast<uint32_t>(TIME_WINDOW) - epoch % TIME_WINDOW;
  57 | 
  58 |     return {otp, validity};
  59 | }
  

`src/utility.cpp`:

   1 | #include <bifrost.hpp>
   2 | #include <fcntl.h>
   3 | #include <filesystem>
   4 | #include <iomanip>
   5 | #include <iostream>
   6 | #include <sstream>
   7 | #include <stdexcept>
   8 | #include <string_view>
   9 | #include <sys/stat.h>
  10 | #include <unistd.h>
  11 | #include <unordered_map>
  12 | #include <utility.hpp>
  13 | 
  14 | using namespace fs;
  15 | 
  16 | // ---------------------------------------------------------------------------
  17 | // Hex helpers
  18 | // ---------------------------------------------------------------------------
  19 | 
  20 | // Convert a hex character to its 0–15 nibble value, or -1 on bad input.
  21 | int hexNibble(char c) noexcept {
  22 |     if (c >= '0' && c <= '9')
  23 |         return c - '0';
  24 |     if (c >= 'a' && c <= 'f')
  25 |         return c - 'a' + 10;
  26 |     if (c >= 'A' && c <= 'F')
  27 |         return c - 'A' + 10;
  28 |     return -1;
  29 | }
  30 | 
  31 | void printBytes(std::ostream &stream, const Bytes &bytes, bool shorten) {
  32 |     if (bytes.empty())
  33 |         return;
  34 | 
  35 |     // Format: [total_size]: <hex bytes>
  36 |     stream << "[" << bytes.size() << "]: ";
  37 | 
  38 |     if (shorten) {
  39 |         // Show first 4 and last 4 bytes with an ellipsis in the middle.
  40 |         for (size_t i = 0; i < 4; ++i)
  41 |             stream << std::hex << ((bytes[i] & 0xF0) >> 4) << (bytes[i] & 0x0F);
  42 |         stream << std::dec << "..[" << bytes.size() - 8 << "]..";
  43 |         for (size_t i = bytes.size() - 4; i < bytes.size(); ++i)
  44 |             stream << std::hex << ((bytes[i] & 0xF0) >> 4) << (bytes[i] & 0x0F);
  45 |     } else {
  46 |         for (Byte b : bytes)
  47 |             stream << std::hex << ((b & 0xF0) >> 4) << (b & 0x0F);
  48 |     }
  49 |     stream << std::dec;
  50 | }
  51 | 
  52 | Bytes hexToBytes(std::string_view hex) {
  53 |     // Strip optional "0x" / "0X" prefix.
  54 |     if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
  55 |         hex.remove_prefix(2);
  56 | 
  57 |     if (hex.size() % 2 != 0)
  58 |         throw std::runtime_error("hex string has odd number of characters");
  59 | 
  60 |     Bytes bytes;
  61 |     bytes.reserve(hex.size() / 2);
  62 | 
  63 |     for (size_t i = 0; i < hex.size(); i += 2) {
  64 |         int hi = hexNibble(hex[i]);
  65 |         int lo = hexNibble(hex[i + 1]);
  66 |         if (hi == -1 || lo == -1)
  67 |             throw std::runtime_error("hex string contains invalid character");
  68 |         bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
  69 |     }
  70 |     return bytes;
  71 | }
  72 | 
  73 | std::string bytesToHex(const Bytes &bytes) {
  74 |     std::ostringstream ss;
  75 |     ss << std::hex << std::setfill('0');
  76 |     for (Byte b : bytes)
  77 |         ss << std::setw(2) << static_cast<int>(b);
  78 |     return ss.str();
  79 | }
  80 | 
  81 | // ---------------------------------------------------------------------------
  82 | // TOTP time encoding
  83 | // ---------------------------------------------------------------------------
  84 | 
  85 | // Encode a Unix timestamp as a big-endian 8-byte counter, per RFC 6238.
  86 | Bytes timeToBytes(const std::time_t time) {
  87 |     Bytes bytes(8);
  88 |     uint64_t t = static_cast<uint64_t>(time);
  89 |     // Fill from the least-significant byte upward (index 7 → 0).
  90 |     for (int b = 7; b >= 0; --b) {
  91 |         bytes[static_cast<size_t>(b)] = static_cast<Byte>(t & 0xFF);
  92 |         t >>= 8;
  93 |     }
  94 |     return bytes;
  95 | }
  96 | 
  97 | // ---------------------------------------------------------------------------
  98 | // Binary serialisation helpers (little-endian uint32)
  99 | // ---------------------------------------------------------------------------
 100 | 
 101 | // Append a uint32 as four little-endian bytes.
 102 | void writeu32(Bytes &out, uint32_t v) {
 103 |     out.push_back(static_cast<Byte>(v & 0xFF));
 104 |     out.push_back(static_cast<Byte>((v >> 8) & 0xFF));
 105 |     out.push_back(static_cast<Byte>((v >> 16) & 0xFF));
 106 |     out.push_back(static_cast<Byte>((v >> 24) & 0xFF));
 107 | }
 108 | 
 109 | // Read a little-endian uint32 from an unaligned pointer.
 110 | uint32_t readu32(const Byte *p) {
 111 |     // Shift-and-OR avoids aliasing / alignment UB vs. memcpy-then-ntohl.
 112 |     return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
 113 |            (static_cast<uint32_t>(p[2]) << 16) |
 114 |            (static_cast<uint32_t>(p[3]) << 24);
 115 | }
 116 | 
 117 | // Read a length-prefixed blob [uint32 len][len bytes] from data at offset.
 118 | // Advances offset past the consumed bytes; throws on truncated input.
 119 | Bytes readField(const Bytes &data, size_t &offset) {
 120 |     if (offset + 4 > data.size())
 121 |         throw std::runtime_error("readField: truncated length prefix");
 122 | 
 123 |     uint32_t len = readu32(data.data() + offset);
 124 |     offset += 4;
 125 | 
 126 |     if (len > data.size() - offset)
 127 |         throw std::runtime_error("readField: field length exceeds buffer");
 128 | 
 129 |     Bytes field(data.begin() + static_cast<ptrdiff_t>(offset),
 130 |                 data.begin() + static_cast<ptrdiff_t>(offset + len));
 131 |     offset += len;
 132 |     return field;
 133 | }
 134 | 
 135 | // ---------------------------------------------------------------------------
 136 | // Atomic file I/O
 137 | // ---------------------------------------------------------------------------
 138 | 
 139 | // Write data to path safely: write to a .tmp sibling, fsync, rename.
 140 | // A power failure before the rename leaves the old file intact; after it,
 141 | // the new file is guaranteed complete.  The parent directory is also fsynced
 142 | // so the rename entry is durable.
 143 | void writeAtomic(const fs::path &path, const Bytes &data, uint32_t perms) {
 144 |     fs::path tmp(path.string() + ".tmp");
 145 | 
 146 |     int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC,
 147 |                     static_cast<mode_t>(perms));
 148 |     if (fd < 0)
 149 |         throw std::runtime_error("writeAtomic: open failed for " +
 150 |                                  tmp.string());
 151 | 
 152 |     ssize_t written = ::write(fd, data.data(), data.size());
 153 |     if (written < 0 || static_cast<size_t>(written) != data.size()) {
 154 |         ::close(fd);
 155 |         throw std::runtime_error("writeAtomic: write failed for " +
 156 |                                  tmp.string());
 157 |     }
 158 | 
 159 |     if (::fsync(fd) != 0) {
 160 |         ::close(fd);
 161 |         throw std::runtime_error("writeAtomic: fsync failed for " +
 162 |                                  tmp.string());
 163 |     }
 164 |     ::close(fd);
 165 | 
 166 |     std::error_code ec;
 167 |     fs::rename(tmp, path, ec);
 168 |     if (ec)
 169 |         throw std::runtime_error("writeAtomic: rename failed: " + ec.message());
 170 | 
 171 |     // Fsync the parent directory so the directory entry update is durable.
 172 |     int dirfd = ::open(path.parent_path().c_str(), O_RDONLY);
 173 |     if (dirfd >= 0) {
 174 |         int res = ::fsync(dirfd);
 175 |         ::close(dirfd);
 176 |         if (res != 0)
 177 |             throw std::runtime_error("writeAtomic: fsync failed");
 178 |     } else
 179 |         throw std::runtime_error(
 180 |             "writeAtomic: failed to open parent directory");
 181 | }
 182 | 
 183 | // Read the contents of path into a Bytes buffer.  Retries on EINTR; tolerates
 184 | // a file that shrinks between stat and read (stops at actual EOF).
 185 | Bytes readAtomic(const fs::path &path) {
 186 |     int fd = ::open(path.c_str(), O_RDONLY);
 187 |     if (fd < 0)
 188 |         throw std::runtime_error("readAtomic: open failed for " +
 189 |                                  path.string());
 190 | 
 191 |     std::error_code ec;
 192 |     uintmax_t size = fs::file_size(path, ec);
 193 |     if (ec) {
 194 |         ::close(fd);
 195 |         throw std::runtime_error("readAtomic: stat failed for " +
 196 |                                  path.string());
 197 |     }
 198 | 
 199 |     Bytes data;
 200 |     if (size > 0)
 201 |         data.resize(static_cast<size_t>(size));
 202 | 
 203 |     size_t total = 0;
 204 |     while (total < data.size()) {
 205 |         ssize_t n = ::read(fd, data.data() + total, data.size() - total);
 206 |         if (n < 0) {
 207 |             if (errno == EINTR)
 208 |                 continue;
 209 |             ::close(fd);
 210 |             throw std::runtime_error("readAtomic: read failed for " +
 211 |                                      path.string());
 212 |         }
 213 |         if (n == 0)
 214 |             break; // file shrank concurrently; stop at actual EOF
 215 |         total += static_cast<size_t>(n);
 216 |     }
 217 |     data.resize(total);
 218 | 
 219 |     ::close(fd);
 220 |     return data;
 221 | }
 222 | 
 223 | // ---------------------------------------------------------------------------
 224 | // URL query-string parser
 225 | // ---------------------------------------------------------------------------
 226 | 
 227 | // Split url into key=value pairs separated by kvDelim.  Returns string_view
 228 | // slices into url, so url must remain valid for the lifetime of the result.
 229 | [[nodiscard]]
 230 | std::unordered_map<std::string_view, std::string_view>
 231 | parseURLParams(const std::string_view url, const char kvDelim,
 232 |                const char valDelim) {
 233 |     std::unordered_map<std::string_view, std::string_view> params;
 234 |     size_t pos = 0;
 235 |     size_t size = url.size();
 236 | 
 237 |     while (pos < size) {
 238 |         size_t pairEnd = url.find(kvDelim, pos);
 239 |         if (pairEnd == std::string_view::npos)
 240 |             pairEnd = size;
 241 | 
 242 |         std::string_view segment = url.substr(pos, pairEnd - pos);
 243 |         size_t eqPos = segment.find(valDelim);
 244 | 
 245 |         if (eqPos != std::string_view::npos)
 246 |             params[segment.substr(0, eqPos)] = segment.substr(eqPos + 1);
 247 |         else if (!segment.empty())
 248 |             params[segment] = {}; // key with no value
 249 | 
 250 |         pos = pairEnd + 1;
 251 |     }
 252 |     return params;
 253 | }
  

`tests/CMakeLists.txt`:

   1 | # ---------------------------------------------------------------------------
   2 | # tests/CMakeLists.txt
   3 | #
   4 | # Professional-grade test integration for Bifrost.
   5 | #
   6 | # Design decisions:
   7 | #   • One binary per tested module (test_utility, test_totp, test_kdf,
   8 | #     test_keystore).  Separate binaries mean:
   9 | #       – a crash in one module does not prevent other tests from running,
  10 | #       – CTest reports per-module pass/fail clearly,
  11 | #       – parallel execution via `ctest -j4` is safe (no shared state).
  12 | #   • A single header (test_framework.hpp) provides REGISTER_TEST / EXPECT_*
  13 | #     macros with no external dependencies — no FetchContent, no internet
  14 | #     access required at CI time.
  15 | #   • All test targets inherit the same compiler warnings and hardening flags
  16 | #     as the production library, so sanitiser builds catch test-induced bugs.
  17 | #   • Sanitiser support (ASAN + UBSAN) is wired through the existing
  18 | #     ENABLE_SANITIZERS option — just pass -DENABLE_SANITIZERS=ON.
  19 | #   • CTest labels allow selective runs:
  20 | #       ctest -L unit          # all unit tests
  21 | #       ctest -L kdf           # just KDF tests
  22 | #       ctest --rerun-failed   # re-run only failing tests
  23 | # ---------------------------------------------------------------------------
  24 | 
  25 | cmake_minimum_required(VERSION 3.28)
  26 | 
  27 | # ---------------------------------------------------------------------------
  28 | # Helper: declare one test binary, link it, register it with CTest.
  29 | # ---------------------------------------------------------------------------
  30 | function(bifrost_add_test target source_file labels)
  31 |     add_executable(${target} ${source_file})
  32 | 
  33 |     target_include_directories(${target} PRIVATE
  34 |         ${CMAKE_CURRENT_SOURCE_DIR}   # finds test_framework.hpp
  35 |     )
  36 | 
  37 |     # Link against the library under test.  bifrost::lib already pulls in
  38 |     # OpenSSL::Crypto and Threads::Threads transitively.
  39 |     target_link_libraries(${target} PRIVATE bifrost::lib)
  40 | 
  41 |     # Same hardening and warning flags as production code.
  42 |     set_project_warnings(${target})
  43 |     set_security_flags(${target})
  44 | 
  45 |     # Register with CTest.  The test is named identically to the binary so
  46 |     # `ctest -R test_kdf` selects exactly the KDF binary.
  47 |     add_test(NAME ${target} COMMAND ${target})
  48 | 
  49 |     # A non-zero exit code from the binary is the failure signal.
  50 |     set_tests_properties(${target} PROPERTIES
  51 |         LABELS               "${labels}"
  52 |         TIMEOUT              60          # fail if a test hangs for > 60 s
  53 |         FAIL_REGULAR_EXPRESSION "^$"    # empty output is never a reason to fail
  54 |     )
  55 | endfunction()
  56 | 
  57 | # ---------------------------------------------------------------------------
  58 | # Test binaries
  59 | # ---------------------------------------------------------------------------
  60 | 
  61 | # utility.cpp: hex helpers, timeToBytes, writeu32/readu32, readField,
  62 | # parseURLParams.  No OpenSSL crypto calls — fastest test to run.
  63 | bifrost_add_test(test_utility  test_utility.cpp  "unit;utility")
  64 | 
  65 | # totp.cpp: HMAC-SHA1 (RFC 2202 vectors), genSample (RFC 6238 Appendix B),
  66 | # generateOTP (wall-clock integration).
  67 | bifrost_add_test(test_totp     test_totp.cpp     "unit;totp")
  68 | 
  69 | # KDF.cpp: HKDF-SHA256 (RFC 5869 Appendix A), PBKDF2-SHA256 (RFC 6070).
  70 | bifrost_add_test(test_kdf      test_kdf.cpp      "unit;kdf")
  71 | 
  72 | # KeyStore.cpp: Key/EncryptedBlob serde, UKID, in-memory mutations,
  73 | # AES-256-GCM encrypt/decrypt round-trip.
  74 | # bifrost_add_test(test_keystore test_keystore.cpp "unit;keystore")
  

`tests/test_framework.hpp`:

   1 | // ---------------------------------------------------------------------------
   2 | // test_framework.hpp — minimal, dependency-free unit test framework for
   3 | // Bifrost's test suite.
   4 | //
   5 | // This header implements the macro contract already assumed by
   6 | // test_keystore.cpp, test_utility.cpp, test_kdf.cpp, and test_totp.cpp:
   7 | //
   8 | //   REGISTER_TEST("module.behavior.case") {
   9 | //       ... test body ...
  10 | //   }
  11 | //   END_TEST
  12 | //
  13 | //   EXPECT_TRUE(expr)
  14 | //   EXPECT_EQ(actual, expected)
  15 | //   EXPECT_BYTES_EQ(actual, expected)      // Bytes / byte-range comparison
  16 | //   EXPECT_THROWS_MSG(expr, "substring")   // expr must throw; if substring
  17 | //                                          // is non-empty, what() must
  18 | //                                          // contain it
  19 | //   EXPECT_NO_THROW(expr)
  20 | //
  21 | //   BIFROST_TEST_MAIN()                    // expands to main(); place once
  22 | //                                          // at file scope, after all tests
  23 | //
  24 | // Design notes:
  25 | //   • No external dependencies (no GoogleTest/Catch2) — keeps the build
  26 | //     hermetic and fast, matching the "single header" comment already in
  27 | //     tests/CMakeLists.txt.
  28 | //   • A failed EXPECT_* records the failure and lets the test continue
  29 | //     running (soft assertion), matching how test_keystore.cpp chains
  30 | //     multiple EXPECT_EQ calls in one test body expecting all of them to be
  31 | //     individually reported rather than stopping at the first failure.
  32 | //   • Each REGISTER_TEST block becomes a distinct function, registered into
  33 | //     a static list at static-init time via a helper struct's constructor —
  34 | //     this is what lets BIFROST_TEST_MAIN() discover and run every test
  35 | //     with zero manual registration boilerplate.
  36 | //   • Exit code: 0 if every test passes, 1 if any test recorded a failure —
  37 | //     required for ctest (via add_test) to correctly mark a binary as
  38 | //     PASSED/FAILED.
  39 | // ---------------------------------------------------------------------------
  40 | 
  41 | #ifndef BIFROST_TEST_FRAMEWORK_HPP
  42 | #define BIFROST_TEST_FRAMEWORK_HPP
  43 | 
  44 | #include <cstdio>
  45 | #include <cstdlib>
  46 | #include <exception>
  47 | #include <functional>
  48 | #include <string>
  49 | #include <vector>
  50 | 
  51 | namespace bifrost_test {
  52 | 
  53 | // ---------------------------------------------------------------------------
  54 | // Global test registry
  55 | // ---------------------------------------------------------------------------
  56 | 
  57 | struct TestCase {
  58 |     std::string name;
  59 |     std::function<void()> fn;
  60 | };
  61 | 
  62 | // Meyer's-singleton accessor avoids static initialization order fiasco
  63 | // between this vector and the TestRegistrar instances defined in each test
  64 | // translation unit (each .cpp file's REGISTER_TEST blocks run their static
  65 | // constructors independently; order across files is unspecified, but each
  66 | // only needs to append to this vector, which works regardless of order).
  67 | inline std::vector<TestCase> &registry() {
  68 |     static std::vector<TestCase> tests;
  69 |     return tests;
  70 | }
  71 | 
  72 | // Registers a test at static-init time. One instance per REGISTER_TEST call.
  73 | struct TestRegistrar {
  74 |     TestRegistrar(const std::string &name, std::function<void()> fn) {
  75 |         registry().push_back(TestCase{name, std::move(fn)});
  76 |     }
  77 | };
  78 | 
  79 | // ---------------------------------------------------------------------------
  80 | // Per-test failure tracking
  81 | // ---------------------------------------------------------------------------
  82 | 
  83 | // Set to true by any failed EXPECT_* within the currently running test body.
  84 | // Reset before each test runs. Kept as a plain global (not thread_local) —
  85 | // this framework assumes serial test execution, matching how
  86 | // tests/CMakeLists.txt registers each test binary as its own CTest entry
  87 | // rather than parallelizing test *cases* within a binary.
  88 | inline bool &current_test_failed() {
  89 |     static bool failed = false;
  90 |     return failed;
  91 | }
  92 | 
  93 | inline int &total_failures() {
  94 |     static int failures = 0;
  95 |     return failures;
  96 | }
  97 | 
  98 | inline void report_failure(const std::string &file, int line,
  99 |                            const std::string &message) {
 100 |     current_test_failed() = true;
 101 |     std::fprintf(stderr, "    FAILED (%s:%d): %s\n", file.c_str(), line,
 102 |                 message.c_str());
 103 | }
 104 | 
 105 | } // namespace bifrost_test
 106 | 
 107 | // ---------------------------------------------------------------------------
 108 | // REGISTER_TEST / END_TEST
 109 | // ---------------------------------------------------------------------------
 110 | //
 111 | // Expands to a free function plus a file-scope TestRegistrar instance whose
 112 | // constructor appends {name, function} to the global registry.
 113 | //
 114 | // __COUNTER__ guarantees a unique function/variable name per invocation even
 115 | // when multiple REGISTER_TEST calls appear in the same file, without
 116 | // requiring the caller to supply a C++-identifier-safe name (test names use
 117 | // dots, e.g. "kdf.hkdf_sha256.rfc5869_test_case_1_basic", which is not a
 118 | // valid identifier on its own).
 119 | 
 120 | #define BIFROST_TEST_CONCAT_INNER(a, b) a##b
 121 | #define BIFROST_TEST_CONCAT(a, b) BIFROST_TEST_CONCAT_INNER(a, b)
 122 | 
 123 | // __COUNTER__ increments on every expansion, including multiple references
 124 | // within the same macro body — so REGISTER_TEST cannot reference __COUNTER__
 125 | // directly more than once (that would produce three different names for
 126 | // what must be the same function). Instead, __COUNTER__ is expanded exactly
 127 | // once here, captured as `id`, and BIFROST_TEST_IMPL reuses that single
 128 | // value for the forward declaration, the registrar, and the definition.
 129 | #define REGISTER_TEST(test_name) BIFROST_TEST_IMPL(test_name, __COUNTER__)
 130 | 
 131 | #define BIFROST_TEST_IMPL(test_name, id)                                     \
 132 |     static void BIFROST_TEST_CONCAT(bifrost_test_fn_, id)();                \
 133 |     namespace {                                                              \
 134 |     static ::bifrost_test::TestRegistrar BIFROST_TEST_CONCAT(                \
 135 |         bifrost_test_registrar_, id)(                                       \
 136 |         test_name, BIFROST_TEST_CONCAT(bifrost_test_fn_, id));              \
 137 |     }                                                                        \
 138 |     static void BIFROST_TEST_CONCAT(bifrost_test_fn_, id)()
 139 | 
 140 | #define END_TEST
 141 | 
 142 | // ---------------------------------------------------------------------------
 143 | // EXPECT_* assertion macros
 144 | // ---------------------------------------------------------------------------
 145 | // All EXPECT_* macros are "soft" — a failure is recorded and execution
 146 | // continues to the next statement in the test body, rather than throwing or
 147 | // aborting. This matches test_keystore.cpp's style of chaining several
 148 | // EXPECT_EQ calls in a single test and expecting to see every failure
 149 | // reported in one run, not just the first.
 150 | 
 151 | #define EXPECT_TRUE(expr)                                                    \
 152 |     do {                                                                     \
 153 |         if (!(expr)) {                                                       \
 154 |             ::bifrost_test::report_failure(__FILE__, __LINE__,               \
 155 |                                            "EXPECT_TRUE(" #expr ") failed"); \
 156 |         }                                                                     \
 157 |     } while (0)
 158 | 
 159 | #define EXPECT_EQ(actual, expected)                                          \
 160 |     do {                                                                     \
 161 |         auto bifrost_test_actual_val = (actual);                            \
 162 |         auto bifrost_test_expected_val = (expected);                        \
 163 |         if (!(bifrost_test_actual_val == bifrost_test_expected_val)) {       \
 164 |             ::bifrost_test::report_failure(                                  \
 165 |                 __FILE__, __LINE__,                                         \
 166 |                 "EXPECT_EQ(" #actual ", " #expected ") failed");            \
 167 |         }                                                                     \
 168 |     } while (0)
 169 | 
 170 | // Byte-range equality: works for Bytes (std::vector<uint8_t>-like) and any
 171 | // container supporting size()/operator[] with comparable element types.
 172 | // Reports index-level detail on mismatch (size or first differing byte)
 173 | // rather than just "not equal", since a raw hex dump of two 64-byte buffers
 174 | // is not useful for spotting a 1-byte KDF/crypto bug by eye.
 175 | #define EXPECT_BYTES_EQ(actual, expected)                                    \
 176 |     do {                                                                     \
 177 |         const auto &bifrost_test_a = (actual);                              \
 178 |         const auto &bifrost_test_b = (expected);                            \
 179 |         bool bifrost_test_eq = (bifrost_test_a.size() == bifrost_test_b.size()); \
 180 |         size_t bifrost_test_diff_idx = 0;                                   \
 181 |         if (bifrost_test_eq) {                                              \
 182 |             for (size_t bifrost_test_i = 0;                                 \
 183 |                 bifrost_test_i < bifrost_test_a.size(); ++bifrost_test_i) { \
 184 |                 if (!(bifrost_test_a[bifrost_test_i] ==                     \
 185 |                       bifrost_test_b[bifrost_test_i])) {                    \
 186 |                     bifrost_test_eq = false;                                \
 187 |                     bifrost_test_diff_idx = bifrost_test_i;                 \
 188 |                     break;                                                  \
 189 |                 }                                                            \
 190 |             }                                                                \
 191 |         }                                                                    \
 192 |         if (!bifrost_test_eq) {                                             \
 193 |             char bifrost_test_msg[256];                                    \
 194 |             if (bifrost_test_a.size() != bifrost_test_b.size()) {           \
 195 |                 std::snprintf(bifrost_test_msg, sizeof(bifrost_test_msg),   \
 196 |                               "EXPECT_BYTES_EQ(" #actual ", " #expected     \
 197 |                               "): size mismatch (%zu vs %zu)",              \
 198 |                               bifrost_test_a.size(), bifrost_test_b.size()); \
 199 |             } else {                                                        \
 200 |                 std::snprintf(                                              \
 201 |                     bifrost_test_msg, sizeof(bifrost_test_msg),            \
 202 |                     "EXPECT_BYTES_EQ(" #actual ", " #expected               \
 203 |                     "): differ at index %zu (0x%02x vs 0x%02x)",           \
 204 |                     bifrost_test_diff_idx,                                  \
 205 |                     static_cast<unsigned>(bifrost_test_a[bifrost_test_diff_idx]), \
 206 |                     static_cast<unsigned>(bifrost_test_b[bifrost_test_diff_idx])); \
 207 |             }                                                                \
 208 |             ::bifrost_test::report_failure(__FILE__, __LINE__,             \
 209 |                                            bifrost_test_msg);               \
 210 |         }                                                                    \
 211 |     } while (0)
 212 | 
 213 | // expr must throw an exception derived from std::exception. If msg_substr
 214 | // is non-empty, the caught exception's what() must contain it as a
 215 | // substring (matching test_keystore.cpp's use, e.g.
 216 | // EXPECT_THROWS_MSG(Key::deserialize(serial), "trailing")). Pass "" to
 217 | // assert only that *some* exception was thrown, without checking the
 218 | // message text.
 219 | #define EXPECT_THROWS_MSG(expr, msg_substr)                                  \
 220 |     do {                                                                     \
 221 |         bool bifrost_test_threw = false;                                    \
 222 |         std::string bifrost_test_what;                                     \
 223 |         try {                                                                \
 224 |             (void)(expr);                                                   \
 225 |         } catch (const std::exception &bifrost_test_e) {                   \
 226 |             bifrost_test_threw = true;                                     \
 227 |             bifrost_test_what = bifrost_test_e.what();                     \
 228 |         } catch (...) {                                                     \
 229 |             bifrost_test_threw = true;                                     \
 230 |         }                                                                    \
 231 |         if (!bifrost_test_threw) {                                          \
 232 |             ::bifrost_test::report_failure(                                 \
 233 |                 __FILE__, __LINE__,                                        \
 234 |                 "EXPECT_THROWS_MSG(" #expr "): expected an exception, "    \
 235 |                 "none was thrown");                                         \
 236 |         } else if (std::string(msg_substr).size() > 0 &&                   \
 237 |                   bifrost_test_what.find(msg_substr) == std::string::npos) { \
 238 |             char bifrost_test_msg[512];                                    \
 239 |             std::snprintf(                                                  \
 240 |                 bifrost_test_msg, sizeof(bifrost_test_msg),                \
 241 |                 "EXPECT_THROWS_MSG(" #expr "): exception message \"%s\" "  \
 242 |                 "does not contain \"%s\"",                                  \
 243 |                 bifrost_test_what.c_str(),                                  \
 244 |                 std::string(msg_substr).c_str());                          \
 245 |             ::bifrost_test::report_failure(__FILE__, __LINE__,             \
 246 |                                            bifrost_test_msg);               \
 247 |         }                                                                    \
 248 |     } while (0)
 249 | 
 250 | // expr must NOT throw. Reports the caught exception's what() on failure so
 251 | // a regression is immediately diagnosable from CTest output alone.
 252 | #define EXPECT_NO_THROW(expr)                                                \
 253 |     do {                                                                     \
 254 |         try {                                                                \
 255 |             (void)(expr);                                                   \
 256 |         } catch (const std::exception &bifrost_test_e) {                   \
 257 |             char bifrost_test_msg[512];                                    \
 258 |             std::snprintf(bifrost_test_msg, sizeof(bifrost_test_msg),      \
 259 |                           "EXPECT_NO_THROW(" #expr "): threw: %s",         \
 260 |                           bifrost_test_e.what());                          \
 261 |             ::bifrost_test::report_failure(__FILE__, __LINE__,             \
 262 |                                            bifrost_test_msg);               \
 263 |         } catch (...) {                                                     \
 264 |             ::bifrost_test::report_failure(                                 \
 265 |                 __FILE__, __LINE__,                                        \
 266 |                 "EXPECT_NO_THROW(" #expr "): threw an unknown exception"); \
 267 |         }                                                                    \
 268 |     } while (0)
 269 | 
 270 | // ---------------------------------------------------------------------------
 271 | // BIFROST_TEST_MAIN — runs every registered test, prints a summary, and
 272 | // returns a process exit code CTest can act on.
 273 | // ---------------------------------------------------------------------------
 274 | 
 275 | #define BIFROST_TEST_MAIN()                                                  \
 276 |     int main() {                                                             \
 277 |         auto &tests = ::bifrost_test::registry();                          \
 278 |         int passed = 0;                                                     \
 279 |         int failed = 0;                                                     \
 280 |         for (const auto &t : tests) {                                       \
 281 |             ::bifrost_test::current_test_failed() = false;                 \
 282 |             std::printf("[ RUN      ] %s\n", t.name.c_str());              \
 283 |             try {                                                            \
 284 |                 t.fn();                                                     \
 285 |             } catch (const std::exception &e) {                            \
 286 |                 ::bifrost_test::report_failure(                            \
 287 |                     "test_framework.hpp", __LINE__,                       \
 288 |                     (std::string("uncaught exception escaped test body: ") + \
 289 |                      e.what()));                                            \
 290 |             } catch (...) {                                                 \
 291 |                 ::bifrost_test::report_failure(                            \
 292 |                     "test_framework.hpp", __LINE__,                       \
 293 |                     "uncaught unknown exception escaped test body");       \
 294 |             }                                                                \
 295 |             if (::bifrost_test::current_test_failed()) {                  \
 296 |                 std::printf("[  FAILED  ] %s\n", t.name.c_str());          \
 297 |                 ++failed;                                                   \
 298 |             } else {                                                        \
 299 |                 std::printf("[       OK ] %s\n", t.name.c_str());          \
 300 |                 ++passed;                                                   \
 301 |             }                                                                \
 302 |         }                                                                    \
 303 |         std::printf("\n[==========] %d test(s) ran.\n",                   \
 304 |                     static_cast<int>(tests.size()));                       \
 305 |         std::printf("[  PASSED  ] %d test(s).\n", passed);                 \
 306 |         if (failed > 0) {                                                   \
 307 |             std::printf("[  FAILED  ] %d test(s).\n", failed);             \
 308 |         }                                                                    \
 309 |         return failed > 0 ? 1 : 0;                                          \
 310 |     }
 311 | 
 312 | #endif // BIFROST_TEST_FRAMEWORK_HPP
  

`tests/test_kdf.cpp`:

   1 | // ---------------------------------------------------------------------------
   2 | // test_kdf.cpp — Unit tests for KDF.cpp
   3 | //
   4 | // Scope:
   5 | //   • hkdf_sha256   — RFC 5869 Appendix A official test vectors (A.1-A.3)
   6 | //   • pbkdf2_sha256 — RFC 6070 vectors are defined for PBKDF2-HMAC-SHA1, NOT
   7 | //                     SHA256, so they cannot be reused here (see note below).
   8 | //                     Instead we test against the KeyStore-mandated iteration
   9 | //                     count, output length, determinism, and sensitivity to
  10 | //                     each input, which are the properties Bifrost actually
  11 | //                     depends on.
  12 | //
  13 | // Why RFC vectors matter more here than in most modules: HKDF and PBKDF2 are
  14 | // the two functions standing between a user's password / mTLS exporter
  15 | // secret and the derived TOTP key. A subtly wrong implementation (e.g. HMAC
  16 | // key/message swapped, salt and IKM swapped, wrong hash length) will not
  17 | // crash and will not look wrong in casual testing — it will just silently
  18 | // produce a different, deterministic, wrong key. Testing against numbers
  19 | // published by a third party (not derived from our own code) is the only way
  20 | // to catch that class of bug.
  21 | //
  22 | // NOT tested here: KeyStore's use of these functions (PBKDF2_N_ITERATIONS,
  23 | // integration with KeyStore's encryption key derivation) — that belongs to
  24 | // test_keystore.cpp / the integration test binary, not this module-level
  25 | // suite.
  26 | // ---------------------------------------------------------------------------
  27 | 
  28 | #include "test_framework.hpp"
  29 | #include <KDF.hpp>
  30 | #include <securebytes.hpp>
  31 | #include <utility.hpp>
  32 | 
  33 | // Small helper: build a SecureBytes from a hex string, since SecureBytes is
  34 | // non-copyable and test vectors are most naturally expressed as hex.
  35 | static SecureBytes secureFromHex(const std::string &hex) {
  36 |     Bytes b = hexToBytes(hex);
  37 |     return SecureBytes(b.data(), b.size());
  38 | }
  39 | 
  40 | // Small helper: build a Bytes (plain, copyable) from a hex string — used for
  41 | // the "info" parameter of hkdf_sha256, which is typed as Bytes, not
  42 | // SecureBytes.
  43 | static Bytes bytesFromHex(const std::string &hex) { return hexToBytes(hex); }
  44 | 
  45 | // ===========================================================================
  46 | // hkdf_sha256 — RFC 5869 Appendix A test vectors
  47 | // ===========================================================================
  48 | 
  49 | REGISTER_TEST("kdf.hkdf_sha256.rfc5869_test_case_1_basic") {
  50 |     // RFC 5869 A.1: Basic test case with SHA-256.
  51 |     // IKM  = 0x0b repeated 22 times
  52 |     // salt = 000102030405060708090a0b0c
  53 |     // info = f0f1f2f3f4f5f6f7f8f9
  54 |     // L    = 42
  55 |     // Expected OKM (first 42 bytes) =
  56 |     //   3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
  57 |     SecureBytes ikm =
  58 |         secureFromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  59 |     SecureBytes salt = secureFromHex("000102030405060708090a0b0c");
  60 |     Bytes info = bytesFromHex("f0f1f2f3f4f5f6f7f8f9");
  61 | 
  62 |     SecureBytes okm;
  63 |     hkdf_sha256(ikm, salt, info, 42, okm);
  64 | 
  65 |     Bytes result(okm.begin(), okm.end());
  66 |     Bytes expected = hexToBytes(
  67 |         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5b"
  68 |         "f34007208d5b887185865");
  69 |     EXPECT_BYTES_EQ(result, expected);
  70 | }
  71 | END_TEST
  72 | 
  73 | REGISTER_TEST("kdf.hkdf_sha256.rfc5869_test_case_2_longer_inputs") {
  74 |     // RFC 5869 A.2: Test with SHA-256 and longer inputs/outputs (L = 82).
  75 |     // Using longer IKM (80 octets), salt (80 octets), info (80 octets).
  76 |     SecureBytes ikm = secureFromHex("000102030405060708090a0b0c0d0e0f"
  77 |                                     "101112131415161718191a1b1c1d1e1f"
  78 |                                     "202122232425262728292a2b2c2d2e2f"
  79 |                                     "303132333435363738393a3b3c3d3e3f"
  80 |                                     "404142434445464748494a4b4c4d4e4f");
  81 |     SecureBytes salt = secureFromHex("606162636465666768696a6b6c6d6e6f"
  82 |                                      "707172737475767778797a7b7c7d7e7f"
  83 |                                      "808182838485868788898a8b8c8d8e8f"
  84 |                                      "909192939495969798999a9b9c9d9e9f"
  85 |                                      "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
  86 |     Bytes info = bytesFromHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
  87 |                               "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
  88 |                               "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
  89 |                               "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
  90 |                               "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  91 | 
  92 |     SecureBytes okm;
  93 |     hkdf_sha256(ikm, salt, info, 82, okm);
  94 | 
  95 |     Bytes result(okm.begin(), okm.end());
  96 |     Bytes expected = hexToBytes("b11e398dc80327a1c8e7f78c596a4934"
  97 |                                 "4f012eda2d4efad8a050cc4c19afa97c"
  98 |                                 "59045a99cac7827271cb41c65e590e09"
  99 |                                 "da3275600c2f09b8367793a9aca3db71"
 100 |                                 "cc30c58179ec3e87c14c01d5c1f3434f1d87");
 101 |     EXPECT_BYTES_EQ(result, expected);
 102 | }
 103 | END_TEST
 104 | 
 105 | REGISTER_TEST("kdf.hkdf_sha256.rfc5869_test_case_3_zero_length_salt_and_info") {
 106 |     // RFC 5869 A.3: Test with SHA-256 and zero-length salt/info.
 107 |     // Confirms empty SecureBytes/Bytes are handled correctly rather than
 108 |     // crashing or defaulting to some other behavior — HKDF's spec requires
 109 |     // an empty salt to be treated as a string of HashLen zero bytes.
 110 |     SecureBytes ikm =
 111 |         secureFromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
 112 |     SecureBytes salt; // zero-length
 113 |     Bytes info;       // zero-length
 114 | 
 115 |     SecureBytes okm;
 116 |     hkdf_sha256(ikm, salt, info, 42, okm);
 117 | 
 118 |     Bytes result(okm.begin(), okm.end());
 119 |     Bytes expected = hexToBytes(
 120 |         "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2"
 121 |         "d9d201395faa4b61a96c8");
 122 |     EXPECT_BYTES_EQ(result, expected);
 123 | }
 124 | END_TEST
 125 | 
 126 | REGISTER_TEST("kdf.hkdf_sha256.output_length_matches_requested") {
 127 |     SecureBytes ikm = secureFromHex("aabbccdd");
 128 |     SecureBytes salt = secureFromHex("1122");
 129 |     Bytes info = bytesFromHex("33");
 130 | 
 131 |     SecureBytes okm16, okm32, okm64;
 132 |     hkdf_sha256(ikm, salt, info, 16, okm16);
 133 |     hkdf_sha256(ikm, salt, info, 32, okm32);
 134 |     hkdf_sha256(ikm, salt, info, 64, okm64);
 135 | 
 136 |     EXPECT_EQ(okm16.size(), 16u);
 137 |     EXPECT_EQ(okm32.size(), 32u);
 138 |     EXPECT_EQ(okm64.size(), 64u);
 139 | }
 140 | END_TEST
 141 | 
 142 | REGISTER_TEST("kdf.hkdf_sha256.different_info_yields_different_output") {
 143 |     // The "info" parameter is Bifrost's binding of the derived key to the
 144 |     // mTLS exporter context — if two different info strings produced the
 145 |     // same output, that binding would be worthless.
 146 |     SecureBytes ikm = secureFromHex("000112233445566778899aabbccddeeff0");
 147 |     SecureBytes salt = secureFromHex("0102030405");
 148 | 
 149 |     SecureBytes okmA, okmB;
 150 |     hkdf_sha256(ikm, salt, bytesFromHex("aa"), 32, okmA);
 151 |     hkdf_sha256(ikm, salt, bytesFromHex("bb"), 32, okmB);
 152 | 
 153 |     Bytes a(okmA.begin(), okmA.end());
 154 |     Bytes b(okmB.begin(), okmB.end());
 155 |     EXPECT_TRUE(a != b);
 156 | }
 157 | END_TEST
 158 | 
 159 | REGISTER_TEST("kdf.hkdf_sha256.deterministic_for_same_inputs") {
 160 |     SecureBytes ikm = secureFromHex("deadbeef");
 161 |     SecureBytes salt = secureFromHex("cafe");
 162 |     Bytes info = bytesFromHex("beef");
 163 | 
 164 |     SecureBytes okm1, okm2;
 165 |     hkdf_sha256(ikm, salt, info, 32, okm1);
 166 |     hkdf_sha256(ikm, salt, info, 32, okm2);
 167 | 
 168 |     Bytes a(okm1.begin(), okm1.end());
 169 |     Bytes b(okm2.begin(), okm2.end());
 170 |     EXPECT_BYTES_EQ(a, b);
 171 | }
 172 | END_TEST
 173 | 
 174 | // ===========================================================================
 175 | // pbkdf2_sha256
 176 | //
 177 | // NOTE ON TEST VECTORS: RFC 6070's published vectors are for
 178 | // PBKDF2-HMAC-SHA1, not SHA256 — they cannot be used to validate a SHA256
 179 | // instantiation. There is no equivalent widely-cited RFC for PBKDF2-SHA256
 180 | // specifically; the closest authoritative source is NIST/community vector
 181 | // sets (e.g. those embedded in Python's hashlib test suite or RFC 7914's
 182 | // Appendix, which target scrypt, not PBKDF2-SHA256 directly).
 183 | //
 184 | // Rather than hard-code an unverified "known-good" hex string here — which
 185 | // would give false confidence if the constant were ever wrong — these tests
 186 | // check the properties that Bifrost's security actually depends on:
 187 | // determinism, sensitivity to every input, and fixed output length. If you
 188 | // later want vector-level certainty, generate a reference value with a
 189 | // separate, trusted implementation (e.g. `python3 -c "import hashlib;
 190 | // print(hashlib.pbkdf2_hmac('sha256', b'password', b'salt',
 191 | // 600000).hex())"`) and hard-code that as an additional regression test.
 192 | // ===========================================================================
 193 | 
 194 | REGISTER_TEST("kdf.pbkdf2_sha256.output_is_32_bytes") {
 195 |     // include/KDF.hpp documents: "derived — output buffer; resized to
 196 |     // SHA256_DIGEST_LENGTH (32) bytes." — this is a stated contract, so it's
 197 |     // worth asserting directly.
 198 |     SecureBytes password = secureFromHex("70617373776f7264"); // "password"
 199 |     SecureBytes salt = secureFromHex("73616c74");             // "salt"
 200 | 
 201 |     SecureBytes derived;
 202 |     pbkdf2_sha256(password, salt, 1000, derived);
 203 | 
 204 |     EXPECT_EQ(derived.size(), 32u);
 205 | }
 206 | END_TEST
 207 | 
 208 | REGISTER_TEST("kdf.pbkdf2_sha256.deterministic_for_same_inputs") {
 209 |     SecureBytes password = secureFromHex("70617373776f7264");
 210 |     SecureBytes salt = secureFromHex("73616c74");
 211 | 
 212 |     SecureBytes d1, d2;
 213 |     pbkdf2_sha256(password, salt, 1000, d1);
 214 |     pbkdf2_sha256(password, salt, 1000, d2);
 215 | 
 216 |     Bytes a(d1.begin(), d1.end());
 217 |     Bytes b(d2.begin(), d2.end());
 218 |     EXPECT_BYTES_EQ(a, b);
 219 | }
 220 | END_TEST
 221 | 
 222 | REGISTER_TEST("kdf.pbkdf2_sha256.different_password_yields_different_key") {
 223 |     SecureBytes salt = secureFromHex("73616c74");
 224 |     SecureBytes d1, d2;
 225 |     pbkdf2_sha256(secureFromHex("70617373776f726431"), salt, 1000,
 226 |                   d1); // "password1"
 227 |     pbkdf2_sha256(secureFromHex("70617373776f726432"), salt, 1000,
 228 |                   d2); // "password2"
 229 | 
 230 |     Bytes a(d1.begin(), d1.end());
 231 |     Bytes b(d2.begin(), d2.end());
 232 |     EXPECT_TRUE(a != b);
 233 | }
 234 | END_TEST
 235 | 
 236 | REGISTER_TEST("kdf.pbkdf2_sha256.different_salt_yields_different_key") {
 237 |     // This is the property that makes rainbow-table attacks impractical —
 238 |     // worth testing explicitly, not just assuming OpenSSL gets it right.
 239 |     SecureBytes password = secureFromHex("70617373776f7264");
 240 |     SecureBytes d1, d2;
 241 |     pbkdf2_sha256(password, secureFromHex("73616c7431"), 1000, d1); // salt1
 242 |     pbkdf2_sha256(password, secureFromHex("73616c7432"), 1000, d2); // salt2
 243 | 
 244 |     Bytes a(d1.begin(), d1.end());
 245 |     Bytes b(d2.begin(), d2.end());
 246 |     EXPECT_TRUE(a != b);
 247 | }
 248 | END_TEST
 249 | 
 250 | REGISTER_TEST(
 251 |     "kdf.pbkdf2_sha256.different_iteration_count_yields_different_key") {
 252 |     SecureBytes password = secureFromHex("70617373776f7264");
 253 |     SecureBytes salt = secureFromHex("73616c74");
 254 |     SecureBytes d1, d2;
 255 |     pbkdf2_sha256(password, salt, 1000, d1);
 256 |     pbkdf2_sha256(password, salt, 2000, d2);
 257 | 
 258 |     Bytes a(d1.begin(), d1.end());
 259 |     Bytes b(d2.begin(), d2.end());
 260 |     EXPECT_TRUE(a != b);
 261 | }
 262 | END_TEST
 263 | 
 264 | REGISTER_TEST("kdf.pbkdf2_sha256.empty_password_does_not_throw") {
 265 |     // An empty password is a legitimate (if weak) input; the KDF itself
 266 |     // should not crash or throw on it — validation of "is this a good
 267 |     // password" belongs to a higher layer, not the primitive.
 268 |     SecureBytes password; // empty
 269 |     SecureBytes salt = secureFromHex("73616c74");
 270 |     SecureBytes derived;
 271 |     EXPECT_NO_THROW(pbkdf2_sha256(password, salt, 1000, derived));
 272 |     EXPECT_EQ(derived.size(), 32u);
 273 | }
 274 | END_TEST
 275 | 
 276 | REGISTER_TEST("kdf.pbkdf2_sha256.production_iteration_count_completes") {
 277 |     // Sanity check at the actual iteration count Bifrost uses in production
 278 |     // (KeyStore.hpp: PBKDF2_N_ITERATIONS = 600'000, the OWASP 2023
 279 |     // recommendation). This mainly guards against a regression that makes
 280 |     // the function hang or throw at realistic cost — timing/performance is
 281 |     // NOT asserted here (that would make the test flaky across machines);
 282 |     // the 60s CTest TIMEOUT set in tests/CMakeLists.txt is the backstop.
 283 |     SecureBytes password = secureFromHex("70617373776f7264");
 284 |     SecureBytes salt = secureFromHex("73616c74");
 285 |     SecureBytes derived;
 286 |     EXPECT_NO_THROW(pbkdf2_sha256(password, salt, 600000, derived));
 287 |     EXPECT_EQ(derived.size(), 32u);
 288 | }
 289 | END_TEST
 290 | 
 291 | BIFROST_TEST_MAIN()
  

`tests/test_totp.cpp`:

   1 | // ---------------------------------------------------------------------------
   2 | // test_totp.cpp — Unit tests for totp.cpp
   3 | //
   4 | // MIGRATION NOTE: Bifrost's HMAC primitive was migrated from HMAC-SHA1 to
   5 | // HMAC-SHA256 (generate_hmac_sha1 -> generate_hmac_sha256, TOTP_DIGEST_SIZE
   6 | // 20 -> 32). This file has been updated end-to-end: every test vector below
   7 | // is a real published HMAC-SHA256 / TOTP-SHA256 vector, not a reused SHA-1
   8 | // number. See the per-section notes for exact sourcing.
   9 | //
  10 | // Scope:
  11 | //   • generate_hmac_sha256 — RFC 4231 official HMAC-SHA-256 test vectors
  12 | //   • genSample            — RFC 6238 Appendix B TOTP-SHA256 test vectors
  13 | //                             (validates the counter -> truncated-sample path
  14 | //                             end-to-end against a third-party-published table)
  15 | //   • generateOTP          — wall-clock integration: format/range checks only,
  16 | //                             NOT an exact-value check (see note below)
  17 | //
  18 | // IMPORTANT NOTE ON generate_hmac_sha256's SIGNATURE:
  19 | // include/totp.hpp now declares:
  20 | //     Bytes generate_hmac_sha256(const SecureBytes &key, const Bytes &msg);
  21 | // RFC 4231's test vectors use ASCII/raw-byte keys and messages of THE SAME
  22 | // kind Bifrost's HMAC-SHA256 consumes elsewhere (the RFC does not require a
  23 | // SecureBytes-typed key — that's a Bifrost-side wrapper choice). The tests
  24 | // below convert RFC vector keys/data into SecureBytes/Bytes accordingly.
  25 | // RFC 4231 test case 4 (25-byte key, 50-byte 0xcd data) is omitted
  26 | // deliberately — cases 1-3 already exercise a single-block key (case 1), a
  27 | // short/sub-block key (case 2), and a short key with multi-block data
  28 | // (case 3); case 4 only varies the key's exact byte pattern and length
  29 | // within that same "short key" regime, adding no new code path coverage.
  30 | // RFC 4231 case 5 (128-bit truncated output) tests a truncation feature
  31 | // Bifrost doesn't use — it consumes the full un-truncated digest — and
  32 | // cases 6-7 are vectors for keys/data longer than the SHA-384/512 block
  33 | // size (128 bytes), which don't apply to HMAC-SHA256's 64-byte block size
  34 | // at all. Cases 1-3 give full coverage of the primitive as Bifrost uses it.
  35 | //
  36 | // IMPORTANT NOTE ON THE genSample SHARED SECRET CHANGING LENGTH:
  37 | // RFC 6238 Appendix B publishes SHA1/SHA256/SHA512 columns side by side in
  38 | // the same table, but — unlike what a naive migration might assume — the
  39 | // SHA-256 column does NOT reuse the SHA-1 column's 20-byte ASCII secret
  40 | // "12345678901234567890". Per the RFC's own reference implementation
  41 | // (Appendix A, `seed32`), the SHA-256 shared secret is that same 20-byte
  42 | // ASCII string concatenated with itself and truncated out to 32 bytes:
  43 | // "12345678901234567890123456789012" (32 ASCII bytes). Reusing the 20-byte
  44 | // SHA-1 secret against the SHA-256 column's published TOTP values would
  45 | // simply fail — it is not testing what RFC 6238 actually specifies for
  46 | // SHA-256. This is exactly the kind of mis-copied-vector risk the original
  47 | // SHA-1 version of this file warned about for its own secret, and it
  48 | // applies again here in a different form.
  49 | //
  50 | // NOTE ON genSample's CONTRACT (confirmed against totp.cpp):
  51 | // genSample(key, timeStep) calls generate_hmac_sha256(key,
  52 | // timeToBytes(timeStep)) directly — timeStep is fed straight into the
  53 | // big-endian 8-byte encoder with NO internal division by TIME_WINDOW. The
  54 | // division by TIME_WINDOW (X = 30 per RFC 6238) happens one layer up, in
  55 | // generateOTP:
  56 | //     curStep = epoch / TIME_WINDOW;
  57 | //     genSample(key, static_cast<std::time_t>(curStep));
  58 | // So genSample's parameter is already the step COUNTER, not a raw Unix
  59 | // timestamp. RFC 6238 Appendix B's "T (hex)" column is exactly that counter
  60 | // value, which is why the tests below pass it to genSample directly (e.g.
  61 | // counter = 1 for Unix time 59, counter = 0x23523EC for Unix time
  62 | // 1111111109) rather than passing the raw Unix timestamp.
  63 | // ---------------------------------------------------------------------------
  64 | 
  65 | #include "test_framework.hpp"
  66 | #include <cstring>
  67 | #include <securebytes.hpp>
  68 | #include <totp.hpp>
  69 | #include <utility.hpp>
  70 | 
  71 | static SecureBytes secureFromHex(const std::string &hex) {
  72 |     Bytes b = hexToBytes(hex);
  73 |     return SecureBytes(b.data(), b.size());
  74 | }
  75 | 
  76 | static SecureBytes secureFromAscii(const std::string &s) {
  77 |     return SecureBytes(reinterpret_cast<const uint8_t *>(s.data()), s.size());
  78 | }
  79 | 
  80 | static Bytes bytesFromAscii(const std::string &s) {
  81 |     return Bytes(s.begin(), s.end());
  82 | }
  83 | 
  84 | // ===========================================================================
  85 | // generate_hmac_sha256 — RFC 4231 test vectors (cases 1-3; see file header
  86 | // note on why case 4 and the SHA-384/512-only cases 6-7 are excluded)
  87 | // ===========================================================================
  88 | 
  89 | REGISTER_TEST("totp.generate_hmac_sha256.rfc4231_case1_hi_there") {
  90 |     SecureBytes key = secureFromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  91 |     Bytes data = bytesFromAscii("Hi There");
  92 | 
  93 |     Bytes digest = generate_hmac_sha256(key, data);
  94 | 
  95 |     Bytes expected = hexToBytes(
  96 |         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  97 |     EXPECT_BYTES_EQ(digest, expected);
  98 | }
  99 | END_TEST
 100 | 
 101 | REGISTER_TEST("totp.generate_hmac_sha256.rfc4231_case2_ascii_key") {
 102 |     // "Jefe" — the RFC's deliberately short (4-byte) ASCII key case; confirms
 103 |     // keys shorter than the SHA-256 block size are handled correctly, not
 104 |     // just full-length 32-byte keys.
 105 |     SecureBytes key = secureFromAscii("Jefe");
 106 |     Bytes data = bytesFromAscii("what do ya want for nothing?");
 107 | 
 108 |     Bytes digest = generate_hmac_sha256(key, data);
 109 | 
 110 |     Bytes expected = hexToBytes(
 111 |         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
 112 |     EXPECT_BYTES_EQ(digest, expected);
 113 | }
 114 | END_TEST
 115 | 
 116 | REGISTER_TEST("totp.generate_hmac_sha256.rfc4231_case3_long_data") {
 117 |     // 0xdd repeated 50 times as the message body — exercises multi-block
 118 |     // HMAC input, unlike cases 1-2 which fit in a single SHA-256 block.
 119 |     // Key is 20 bytes of 0xaa (per RFC 4231 §4.4) — shorter than the
 120 |     // SHA-256 block size (64 bytes), so this still tests the "short key"
 121 |     // path, just combined with a longer data buffer.
 122 |     SecureBytes key = secureFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
 123 |     Bytes data(50, 0xdd);
 124 | 
 125 |     Bytes digest = generate_hmac_sha256(key, data);
 126 | 
 127 |     Bytes expected = hexToBytes(
 128 |         "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
 129 |     EXPECT_BYTES_EQ(digest, expected);
 130 | }
 131 | END_TEST
 132 | 
 133 | REGISTER_TEST("totp.generate_hmac_sha256.output_is_32_bytes") {
 134 |     // TOTP_DIGEST_SIZE in totp.hpp is now documented as 32 (HMAC-SHA256
 135 |     // output length) — assert the primitive actually produces that, since
 136 |     // every downstream truncation offset calculation depends on it.
 137 |     SecureBytes key = secureFromHex("0102030405");
 138 |     Bytes data = bytesFromAscii("test");
 139 |     Bytes digest = generate_hmac_sha256(key, data);
 140 |     EXPECT_EQ(digest.size(), static_cast<size_t>(TOTP_DIGEST_SIZE));
 141 | }
 142 | END_TEST
 143 | 
 144 | REGISTER_TEST("totp.generate_hmac_sha256.deterministic") {
 145 |     SecureBytes key = secureFromHex("deadbeef");
 146 |     Bytes data = bytesFromAscii("repeat me");
 147 |     Bytes d1 = generate_hmac_sha256(key, data);
 148 |     Bytes d2 = generate_hmac_sha256(key, data);
 149 |     EXPECT_BYTES_EQ(d1, d2);
 150 | }
 151 | END_TEST
 152 | 
 153 | // ===========================================================================
 154 | // genSample — RFC 6238 Appendix B test vectors (TOTP-SHA256, X = 30, T0 = 0)
 155 | //
 156 | // Shared secret per RFC 6238 Appendix A's reference implementation (the
 157 | // `seed32` constant): the 20-byte ASCII string "12345678901234567890"
 158 | // extended to 32 bytes as "12345678901234567890123456789012". This is NOT
 159 | // the same secret used for the SHA-1 vectors — see the file header note on
 160 | // why reusing the SHA-1 secret here would be a real (silent) bug, not just
 161 | // a style choice.
 162 | // ===========================================================================
 163 | 
 164 | REGISTER_TEST("totp.genSample.rfc6238_time_59_counter_1") {
 165 |     // Unix time 59, X=30, T0=0 => T = floor(59/30) = 1 = 0x0000000000000001
 166 |     SecureBytes key = secureFromAscii("12345678901234567890123456789012");
 167 |     uint32_t sample = genSample(key, static_cast<std::time_t>(1));
 168 | 
 169 |     // genSample returns the truncated 31-bit DYNAMIC BINARY CODE (per
 170 |     // totp.hpp's doc comment), i.e. the value BEFORE the final "mod 10^8"
 171 |     // digit-count reduction that generateOTP performs. RFC 6238's published
 172 |     // TOTP value (46119246, SHA256 column) is AFTER that final
 173 |     // mod-reduction, so we check that reducing genSample's output the same
 174 |     // way reproduces the RFC's published OTP — this validates genSample's
 175 |     // correctness without assuming its exact pre-truncation return
 176 |     // convention beyond what totp.hpp documents.
 177 |     uint32_t otp = sample % 100000000u; // 10^8 for OTP_SIZE == 6? see note.
 178 |     // NOTE: RFC 6238's example code uses `binary % DIGITS_POWER[codeDigits]`
 179 |     // with codeDigits = 8 in the RFC's own worked example (their table shows
 180 |     // 8-digit OTPs), while Bifrost's OTP_SIZE = 6. genSample's contract is
 181 |     // pre-digit-truncation, so we validate the untruncated dynamic binary
 182 |     // code's low digits are consistent with the RFC's 8-digit value; this is
 183 |     // the correct scope for genSample specifically. generateOTP (below) is
 184 |     // where OTP_SIZE-specific truncation is exercised end-to-end.
 185 |     EXPECT_EQ(otp, 46119246u);
 186 | }
 187 | END_TEST
 188 | 
 189 | REGISTER_TEST("totp.genSample.rfc6238_time_1111111109_counter") {
 190 |     // Unix time 1111111109, X=30, T0=0 => T = floor(1111111109/30)
 191 |     //                                       = 0x23523EC
 192 |     SecureBytes key = secureFromAscii("12345678901234567890123456789012");
 193 |     std::time_t counter = 0x23523EC;
 194 |     uint32_t sample = genSample(key, counter);
 195 |     uint32_t otp = sample % 100000000u;
 196 |     EXPECT_EQ(otp, 68084774u); // RFC's SHA256-column "68084774" as an integer
 197 | }
 198 | END_TEST
 199 | 
 200 | REGISTER_TEST("totp.genSample.deterministic_for_same_counter") {
 201 |     SecureBytes key = secureFromAscii("12345678901234567890123456789012");
 202 |     uint32_t s1 = genSample(key, static_cast<std::time_t>(1));
 203 |     uint32_t s2 = genSample(key, static_cast<std::time_t>(1));
 204 |     EXPECT_EQ(s1, s2);
 205 | }
 206 | END_TEST
 207 | 
 208 | REGISTER_TEST("totp.genSample.different_counters_yield_different_samples") {
 209 |     // Not an RFC-mandated property, but a basic sanity check: adjacent time
 210 |     // steps must not collide, or TOTP codes would repeat across windows.
 211 |     SecureBytes key = secureFromAscii("12345678901234567890123456789012");
 212 |     uint32_t s1 = genSample(key, static_cast<std::time_t>(1));
 213 |     uint32_t s2 = genSample(key, static_cast<std::time_t>(2));
 214 |     EXPECT_TRUE(s1 != s2);
 215 | }
 216 | END_TEST
 217 | 
 218 | REGISTER_TEST("totp.genSample.result_is_31_bits_or_fewer") {
 219 |     // totp.hpp documents genSample as producing a "truncated 31-bit sample"
 220 |     // per the HOTP dynamic-truncation step, which masks the top bit
 221 |     // (0x7fffffff) specifically so the result is never negative when
 222 |     // interpreted as a signed 32-bit integer. Assert that invariant
 223 |     // directly. This property is independent of which hash function
 224 |     // backs genSample, since the mask is applied after HMAC output.
 225 |     SecureBytes key = secureFromAscii("12345678901234567890123456789012");
 226 |     uint32_t sample = genSample(key, static_cast<std::time_t>(1));
 227 |     EXPECT_TRUE(sample <= 0x7fffffffu);
 228 | }
 229 | END_TEST
 230 | 
 231 | // ===========================================================================
 232 | // generateOTP — wall-clock integration
 233 | //
 234 | // Confirmed against totp.cpp: generateOTP calls std::time(nullptr) directly
 235 | // with no injectable time parameter, computes curStep = epoch / TIME_WINDOW,
 236 | // then otp = genSample(key, curStep) % 10^OTP_SIZE, and
 237 | // validity = TIME_WINDOW - (epoch % TIME_WINDOW). Because the wall clock is
 238 | // read internally with no seam, exact OTP values cannot be pinned to an RFC
 239 | // vector here — these tests check CONTRACT properties (digit count,
 240 | // validity range, struct shape) instead. genSample and the modulus/validity
 241 | // arithmetic ARE covered exactly against RFC 6238 vectors above; this
 242 | // section only covers the wall-clock wiring on top of that already-verified
 243 | // core.
 244 | //
 245 | // If exact-value wall-clock testing matters later, the smallest change is
 246 | // splitting generateOTP's body into a testable core:
 247 | //     TOTP generateOTPAt(const SecureBytes &key, std::time_t epoch);
 248 | //     TOTP generateOTP(const SecureBytes &key) {
 249 | //         return generateOTPAt(key, std::time(nullptr));
 250 | //     }
 251 | // generateOTPAt could then be called directly with epoch = 59 or
 252 | // 1111111109 and checked against the RFC's exact SHA256-column 46119246 /
 253 | // 68084774 values — today those exact values are only exercised indirectly
 254 | // through genSample's own tests above, not through generateOTP's public API.
 255 | // ===========================================================================
 256 | 
 257 | REGISTER_TEST("totp.generateOTP.otp_has_at_most_otp_size_digits") {
 258 |     SecureBytes key = secureFromAscii("12345678901234567890123456789012");
 259 |     TOTP result = generateOTP(key);
 260 |     EXPECT_TRUE(result.otp < 1000000u); // OTP_SIZE == 6 => otp in [0, 999999]
 261 | }
 262 | END_TEST
 263 | 
 264 | REGISTER_TEST("totp.generateOTP.validity_within_time_window") {
 265 |     SecureBytes key = secureFromAscii("12345678901234567890123456789012");
 266 |     TOTP result = generateOTP(key);
 267 |     // validity = seconds remaining in the current TIME_WINDOW; must be in
 268 |     // (0, TIME_WINDOW]. Zero would mean the window already expired at the
 269 |     // instant of generation, which should not happen for a fresh call.
 270 |     EXPECT_TRUE(result.validity > 0u);
 271 |     EXPECT_TRUE(result.validity <= static_cast<uint32_t>(TIME_WINDOW));
 272 | }
 273 | END_TEST
 274 | 
 275 | REGISTER_TEST("totp.generateOTP.consecutive_calls_within_same_window_match") {
 276 |     // Two calls made back-to-back (same 30s window, near-certainly) should
 277 |     // return the same OTP — this indirectly confirms generateOTP is
 278 |     // deterministic with respect to the counter and isn't, e.g., mixing in
 279 |     // any per-call randomness by mistake.
 280 |     SecureBytes key = secureFromAscii("12345678901234567890123456789012");
 281 |     TOTP r1 = generateOTP(key);
 282 |     TOTP r2 = generateOTP(key);
 283 |     // This assumes the two calls land in the same 30-second window, which is
 284 |     // true except for a rare race at a window boundary. If this test proves
 285 |     // flaky in CI, that boundary race is the cause — not a bug in
 286 |     // generateOTP — and the fix is to inject time rather than remove the
 287 |     // test.
 288 |     EXPECT_EQ(r1.otp, r2.otp);
 289 | }
 290 | END_TEST
 291 | 
 292 | BIFROST_TEST_MAIN()
  

`tests/test_utility.cpp`:

   1 | // ---------------------------------------------------------------------------
   2 | // test_utility.cpp — Unit tests for utility.cpp
   3 | //
   4 | // Scope (pure functions, no OpenSSL, no filesystem, no network):
   5 | //   • hexNibble          — single hex-character decode, valid + invalid input
   6 | //   • hexToBytes / bytesToHex — round-trip and known-vector checks
   7 | //   • writeu32 / readu32 — little-endian 32-bit encode/decode, boundary values
   8 | //   • readField          — length-prefixed field reader used by (de)serialise
   9 | //   • timeToBytes        — big-endian 8-byte counter encoding (RFC 6238 style)
  10 | //   • parseURLParams     — query-string parsing, delimiters, edge cases
  11 | //
  12 | // NOT tested here: writeAtomic / readAtomic (filesystem integration test —
  13 | // requires a real temp directory and is covered by the integration test
  14 | // binary, matching the convention set in test_keystore.cpp for KeyStore::init
  15 | // and loadStore/saveStore).
  16 | //
  17 | // This file follows the same structure as test_keystore.cpp: one
  18 | // REGISTER_TEST block per behavior, named "module.function.case", with no
  19 | // shared mutable state between tests (all functions here are pure, so no
  20 | // clear_store()-style fixture is needed).
  21 | // ---------------------------------------------------------------------------
  22 | 
  23 | #include "test_framework.hpp"
  24 | #include <utility.hpp>
  25 | 
  26 | // ===========================================================================
  27 | // hexNibble
  28 | // ===========================================================================
  29 | 
  30 | REGISTER_TEST("utility.hexNibble.decimal_digits") {
  31 |     EXPECT_EQ(hexNibble('0'), 0);
  32 |     EXPECT_EQ(hexNibble('5'), 5);
  33 |     EXPECT_EQ(hexNibble('9'), 9);
  34 | }
  35 | END_TEST
  36 | 
  37 | REGISTER_TEST("utility.hexNibble.lowercase_letters") {
  38 |     EXPECT_EQ(hexNibble('a'), 10);
  39 |     EXPECT_EQ(hexNibble('f'), 15);
  40 | }
  41 | END_TEST
  42 | 
  43 | REGISTER_TEST("utility.hexNibble.uppercase_letters") {
  44 |     EXPECT_EQ(hexNibble('A'), 10);
  45 |     EXPECT_EQ(hexNibble('F'), 15);
  46 | }
  47 | END_TEST
  48 | 
  49 | REGISTER_TEST("utility.hexNibble.invalid_char_returns_negative") {
  50 |     // 'g' is not a hex digit; the function should signal failure rather than
  51 |     // silently returning a plausible-looking value.
  52 |     EXPECT_TRUE(hexNibble('g') < 0);
  53 |     EXPECT_TRUE(hexNibble('!') < 0);
  54 |     EXPECT_TRUE(hexNibble(' ') < 0);
  55 | }
  56 | END_TEST
  57 | 
  58 | // ===========================================================================
  59 | // hexToBytes / bytesToHex
  60 | // ===========================================================================
  61 | 
  62 | REGISTER_TEST("utility.hexToBytes.known_vector") {
  63 |     Bytes b = hexToBytes("deadbeef");
  64 |     Bytes expected = {0xde, 0xad, 0xbe, 0xef};
  65 |     EXPECT_BYTES_EQ(b, expected);
  66 | }
  67 | END_TEST
  68 | 
  69 | REGISTER_TEST("utility.hexToBytes.empty_string") {
  70 |     Bytes b = hexToBytes("");
  71 |     EXPECT_TRUE(b.empty());
  72 | }
  73 | END_TEST
  74 | 
  75 | REGISTER_TEST("utility.hexToBytes.uppercase_and_lowercase_mixed") {
  76 |     Bytes lower = hexToBytes("aabbcc");
  77 |     Bytes upper = hexToBytes("AABBCC");
  78 |     Bytes mixed = hexToBytes("AaBbCc");
  79 |     EXPECT_BYTES_EQ(lower, upper);
  80 |     EXPECT_BYTES_EQ(lower, mixed);
  81 | }
  82 | END_TEST
  83 | 
  84 | REGISTER_TEST("utility.bytesToHex.known_vector") {
  85 |     Bytes b = {0xde, 0xad, 0xbe, 0xef};
  86 |     EXPECT_EQ(bytesToHex(b), std::string("deadbeef"));
  87 | }
  88 | END_TEST
  89 | 
  90 | REGISTER_TEST("utility.hexToBytes_bytesToHex.roundtrip") {
  91 |     // Round-trip through both directions for a value that exercises every
  92 |     // nibble 0x0-0xF at least once.
  93 |     std::string original = "0123456789abcdef";
  94 |     Bytes b = hexToBytes(original);
  95 |     std::string back = bytesToHex(b);
  96 |     EXPECT_EQ(back, original);
  97 | }
  98 | END_TEST
  99 | 
 100 | REGISTER_TEST("utility.bytesToHex.empty_bytes") {
 101 |     Bytes b;
 102 |     EXPECT_EQ(bytesToHex(b), std::string(""));
 103 | }
 104 | END_TEST
 105 | 
 106 | REGISTER_TEST("utility.hexToBytes.strips_0x_prefix") {
 107 |     // Confirmed in utility.cpp: an optional "0x"/"0X" prefix is stripped
 108 |     // before decoding. Worth testing directly since it's an easy thing to
 109 |     // silently break (e.g. if someone "simplifies" the function later) with
 110 |     // no compiler warning to catch it.
 111 |     Bytes withPrefix = hexToBytes("0xdeadbeef");
 112 |     Bytes withoutPrefix = hexToBytes("deadbeef");
 113 |     EXPECT_BYTES_EQ(withPrefix, withoutPrefix);
 114 | }
 115 | END_TEST
 116 | 
 117 | REGISTER_TEST("utility.hexToBytes.strips_uppercase_0X_prefix") {
 118 |     Bytes withPrefix = hexToBytes("0XDEADBEEF");
 119 |     Bytes expected = {0xde, 0xad, 0xbe, 0xef};
 120 |     EXPECT_BYTES_EQ(withPrefix, expected);
 121 | }
 122 | END_TEST
 123 | 
 124 | REGISTER_TEST("utility.hexToBytes.odd_length_throws") {
 125 |     // Confirmed in utility.cpp: hex.size() % 2 != 0 throws explicitly rather
 126 |     // than silently truncating or padding the last nibble.
 127 |     EXPECT_THROWS_MSG(hexToBytes("abc"), "");
 128 | }
 129 | END_TEST
 130 | 
 131 | REGISTER_TEST("utility.hexToBytes.invalid_character_throws") {
 132 |     EXPECT_THROWS_MSG(hexToBytes("zz"), "");
 133 | }
 134 | END_TEST
 135 | 
 136 | // ===========================================================================
 137 | // writeu32 / readu32  (little-endian, per KeyStore serialisation format)
 138 | // ===========================================================================
 139 | 
 140 | REGISTER_TEST("utility.writeu32_readu32.roundtrip_zero") {
 141 |     Bytes out;
 142 |     writeu32(out, 0u);
 143 |     EXPECT_EQ(out.size(), 4u);
 144 |     EXPECT_EQ(readu32(out.data()), 0u);
 145 | }
 146 | END_TEST
 147 | 
 148 | REGISTER_TEST("utility.writeu32_readu32.roundtrip_max") {
 149 |     Bytes out;
 150 |     writeu32(out, 0xFFFFFFFFu);
 151 |     EXPECT_EQ(readu32(out.data()), 0xFFFFFFFFu);
 152 | }
 153 | END_TEST
 154 | 
 155 | REGISTER_TEST("utility.writeu32_readu32.roundtrip_arbitrary") {
 156 |     Bytes out;
 157 |     writeu32(out, 0x12345678u);
 158 |     EXPECT_EQ(readu32(out.data()), 0x12345678u);
 159 | }
 160 | END_TEST
 161 | 
 162 | REGISTER_TEST("utility.writeu32.little_endian_byte_order") {
 163 |     // Pin down the wire format explicitly: least-significant byte first.
 164 |     // This is a deliberate format guarantee (KeyStore's on-disk layout
 165 |     // depends on it), so the byte order itself is worth asserting, not just
 166 |     // the round-trip.
 167 |     Bytes out;
 168 |     writeu32(out, 0x12345678u);
 169 |     Bytes expected = {0x78, 0x56, 0x34, 0x12};
 170 |     EXPECT_BYTES_EQ(out, expected);
 171 | }
 172 | END_TEST
 173 | 
 174 | REGISTER_TEST("utility.writeu32.appends_without_clearing") {
 175 |     // writeu32 takes Bytes& out and should append, not overwrite — callers
 176 |     // build up serialized records by calling it multiple times.
 177 |     Bytes out = {0xAA};
 178 |     writeu32(out, 1u);
 179 |     EXPECT_EQ(out.size(), 5u);
 180 |     EXPECT_EQ(out[0], 0xAAu);
 181 | }
 182 | END_TEST
 183 | 
 184 | // ===========================================================================
 185 | // readField — length-prefixed field reader
 186 | // ===========================================================================
 187 | 
 188 | REGISTER_TEST("utility.readField.basic_extraction") {
 189 |     // Build a manual [u32 length][payload] record.
 190 |     Bytes data;
 191 |     writeu32(data, 3u);
 192 |     data.push_back('a');
 193 |     data.push_back('b');
 194 |     data.push_back('c');
 195 | 
 196 |     size_t offset = 0;
 197 |     Bytes field = readField(data, offset);
 198 | 
 199 |     Bytes expected = {'a', 'b', 'c'};
 200 |     EXPECT_BYTES_EQ(field, expected);
 201 |     // offset must advance past the 4-byte length prefix AND the payload.
 202 |     EXPECT_EQ(offset, 7u);
 203 | }
 204 | END_TEST
 205 | 
 206 | REGISTER_TEST("utility.readField.empty_field") {
 207 |     Bytes data;
 208 |     writeu32(data, 0u);
 209 | 
 210 |     size_t offset = 0;
 211 |     Bytes field = readField(data, offset);
 212 | 
 213 |     EXPECT_TRUE(field.empty());
 214 |     EXPECT_EQ(offset, 4u);
 215 | }
 216 | END_TEST
 217 | 
 218 | REGISTER_TEST("utility.readField.advances_offset_for_sequential_reads") {
 219 |     // Two fields back-to-back; offset must be threaded through correctly so
 220 |     // the second readField call picks up exactly where the first left off.
 221 |     Bytes data;
 222 |     writeu32(data, 2u);
 223 |     data.push_back('h');
 224 |     data.push_back('i');
 225 |     writeu32(data, 3u);
 226 |     data.push_back('b');
 227 |     data.push_back('y');
 228 |     data.push_back('e');
 229 | 
 230 |     size_t offset = 0;
 231 |     Bytes first = readField(data, offset);
 232 |     Bytes second = readField(data, offset);
 233 | 
 234 |     Bytes expectedFirst = {'h', 'i'};
 235 |     Bytes expectedSecond = {'b', 'y', 'e'};
 236 |     EXPECT_BYTES_EQ(first, expectedFirst);
 237 |     EXPECT_BYTES_EQ(second, expectedSecond);
 238 |     EXPECT_EQ(offset, data.size());
 239 | }
 240 | END_TEST
 241 | 
 242 | REGISTER_TEST("utility.readField.truncated_length_prefix_throws") {
 243 |     // Fewer than 4 bytes available — not even enough for the length prefix.
 244 |     Bytes data = {0x01, 0x02};
 245 |     size_t offset = 0;
 246 |     EXPECT_THROWS_MSG(readField(data, offset), "");
 247 | }
 248 | END_TEST
 249 | 
 250 | REGISTER_TEST("utility.readField.length_exceeds_buffer_throws") {
 251 |     // Length prefix claims more payload bytes than actually follow.
 252 |     Bytes data;
 253 |     writeu32(data, 100u); // claims 100 bytes of payload
 254 |     data.push_back('x');  // only 1 byte actually present
 255 | 
 256 |     size_t offset = 0;
 257 |     EXPECT_THROWS_MSG(readField(data, offset), "");
 258 | }
 259 | END_TEST
 260 | 
 261 | // ===========================================================================
 262 | // timeToBytes — big-endian 8-byte counter (RFC 6238 / HOTP wire format)
 263 | // ===========================================================================
 264 | 
 265 | REGISTER_TEST("utility.timeToBytes.size_is_eight_bytes") {
 266 |     Bytes b = timeToBytes(static_cast<std::time_t>(59));
 267 |     EXPECT_EQ(b.size(), 8u);
 268 | }
 269 | END_TEST
 270 | 
 271 | REGISTER_TEST("utility.timeToBytes.zero") {
 272 |     Bytes b = timeToBytes(static_cast<std::time_t>(0));
 273 |     Bytes expected = {0, 0, 0, 0, 0, 0, 0, 0};
 274 |     EXPECT_BYTES_EQ(b, expected);
 275 | }
 276 | END_TEST
 277 | 
 278 | REGISTER_TEST("utility.timeToBytes.rfc6238_known_value") {
 279 |     // RFC 6238 Appendix B uses T = 1 (i.e. time step counter value 1) as its
 280 |     // first test vector's derived counter. The 8-byte big-endian encoding of
 281 |     // 1 is 00 00 00 00 00 00 00 01 — this pins down byte order, which
 282 |     // genSample()/generateOTP() depend on for correct HMAC input.
 283 |     Bytes b = timeToBytes(static_cast<std::time_t>(1));
 284 |     Bytes expected = {0, 0, 0, 0, 0, 0, 0, 1};
 285 |     EXPECT_BYTES_EQ(b, expected);
 286 | }
 287 | END_TEST
 288 | 
 289 | REGISTER_TEST("utility.timeToBytes.big_endian_byte_order") {
 290 |     // 0x0000000000000100 = 256. Big-endian means the 0x01 byte lands second
 291 |     // from the end, not first.
 292 |     Bytes b = timeToBytes(static_cast<std::time_t>(256));
 293 |     Bytes expected = {0, 0, 0, 0, 0, 0, 1, 0};
 294 |     EXPECT_BYTES_EQ(b, expected);
 295 | }
 296 | END_TEST
 297 | 
 298 | // ===========================================================================
 299 | // parseURLParams
 300 | // ===========================================================================
 301 | 
 302 | REGISTER_TEST("utility.parseURLParams.single_param") {
 303 |     auto params = parseURLParams("key=value");
 304 |     EXPECT_EQ(params.size(), 1u);
 305 |     EXPECT_TRUE(params.count("key") == 1);
 306 |     EXPECT_EQ(std::string(params.at("key")), std::string("value"));
 307 | }
 308 | END_TEST
 309 | 
 310 | REGISTER_TEST("utility.parseURLParams.multiple_params") {
 311 |     auto params = parseURLParams("a=1&b=2&c=3");
 312 |     EXPECT_EQ(params.size(), 3u);
 313 |     EXPECT_EQ(std::string(params.at("a")), std::string("1"));
 314 |     EXPECT_EQ(std::string(params.at("b")), std::string("2"));
 315 |     EXPECT_EQ(std::string(params.at("c")), std::string("3"));
 316 | }
 317 | END_TEST
 318 | 
 319 | REGISTER_TEST("utility.parseURLParams.custom_delimiters") {
 320 |     // Bifrost's TOTP URL scheme may not use standard &/= — verify the
 321 |     // delimiter parameters actually take effect.
 322 |     auto params = parseURLParams("a:1;b:2", ';', ':');
 323 |     EXPECT_EQ(params.size(), 2u);
 324 |     EXPECT_EQ(std::string(params.at("a")), std::string("1"));
 325 |     EXPECT_EQ(std::string(params.at("b")), std::string("2"));
 326 | }
 327 | END_TEST
 328 | 
 329 | REGISTER_TEST("utility.parseURLParams.empty_string") {
 330 |     auto params = parseURLParams("");
 331 |     EXPECT_TRUE(params.empty());
 332 | }
 333 | END_TEST
 334 | 
 335 | REGISTER_TEST(
 336 |     "utility.parseURLParams.pair_with_no_value_delim_gets_empty_value") {
 337 |     // Confirmed against utility.cpp: a segment with no valDelim ('=') is
 338 |     // still inserted as a key, mapped to an empty string_view — it is NOT
 339 |     // dropped. This matters because bifrost-totp:// URLs come from an
 340 |     // external process (xdg-open / the desktop file's %u), so a caller
 341 |     // passing a bare flag-style param (no "=value") must not silently
 342 |     // disappear from the result map.
 343 |     auto params = parseURLParams("standalone&key=value");
 344 |     EXPECT_EQ(params.size(), 2u);
 345 |     EXPECT_TRUE(params.count("standalone") == 1);
 346 |     EXPECT_EQ(std::string(params.at("standalone")), std::string(""));
 347 |     EXPECT_TRUE(params.count("key") == 1);
 348 |     EXPECT_EQ(std::string(params.at("key")), std::string("value"));
 349 | }
 350 | END_TEST
 351 | 
 352 | REGISTER_TEST(
 353 |     "utility.parseURLParams.value_with_equals_in_value_splits_on_first") {
 354 |     // segment.find(valDelim) locates the FIRST '=' only; a value that itself
 355 |     // contains '=' (e.g. base64url padding is rare but not impossible in a
 356 |     // future param) is not re-split. Pin this down explicitly since it's a
 357 |     // one-line implementation detail with no test otherwise.
 358 |     auto params = parseURLParams("key=a=b=c");
 359 |     EXPECT_EQ(params.size(), 1u);
 360 |     EXPECT_EQ(std::string(params.at("key")), std::string("a=b=c"));
 361 | }
 362 | END_TEST
 363 | 
 364 | REGISTER_TEST("utility.parseURLParams.trailing_delimiter_no_extra_entry") {
 365 |     // A trailing '&' with nothing after it must not produce a spurious
 366 |     // empty-string key. pos == size on the final loop iteration, so the
 367 |     // while(pos < size) guard should stop before processing anything past
 368 |     // the last real pair.
 369 |     auto params = parseURLParams("key=value&");
 370 |     EXPECT_EQ(params.size(), 1u);
 371 |     EXPECT_EQ(std::string(params.at("key")), std::string("value"));
 372 | }
 373 | END_TEST
 374 | 
 375 | BIFROST_TEST_MAIN()
  


I'd like you to add documentation comments to all public functions, methods, classes and modules in this codebase.

For each one, the comment should include:
1. A brief description of what it does
2. Explanations of all parameters including types/constraints 
3. Description of the return value (if applicable)
4. Any notable error or edge cases handled
5. Links to any related code entities

Try to keep comments concise but informative. Use the function/parameter names as clues to infer their purpose. Analyze the implementation carefully to determine behavior.

Comments should use the idiomatic style for the language, e.g. /// for Rust, """ for Python, /** */ for TypeScript, etc. Place them directly above the function/class/module definition.

Let me know if you have any questions! And be sure to review your work for accuracy before submitting.