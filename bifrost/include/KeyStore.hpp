#pragma once

#include <bifrost.hpp>
#include <cassert>
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
#include <string>
#include <unordered_map>
#include <utility.hpp>
#include <vector>

// ---------------------------------------------------------------------------
// Encryption constants — typed so the compiler enforces units at call
// sites.
// ---------------------------------------------------------------------------
inline constexpr size_t KEY_STORE_ENC_KEY_SIZE = 32;
inline constexpr size_t ENC_BLOB_NONCE_SIZE = 12; // AES-GCM 96-bit nonce
inline constexpr size_t ENC_BLOB_TAG_SIZE = 16;   // AES-GCM 128-bit tag
inline constexpr int PBKDF2_N_ITERATIONS = 310'000;
inline constexpr size_t PBKDF2_SALT_SIZE = 16;

// ---------------------------------------------------------------------------
// Key — holds everything we need to generate and display a TOTP for one
// registered account.  Non-copyable because it owns a SecureBytes secret.
// ---------------------------------------------------------------------------
struct Key {
        std::string accinfo;
        Bytes fingerprint; // = SHA(Server X509 Certificate)
        std::string commonName;
        std::vector<std::string> sans;
        SecureBytes secret;

        Key() = default;
        Key(const Key &) = delete;
        Key &operator=(const Key &) = delete;
        Key(Key &&) noexcept = default;
        Key &operator=(Key &&) noexcept = default;
        ~Key() = default;

        // Serialisation: length-prefixed TLV format.
        size_t size() const;
        Bytes serialize() const;
        static Key deserialize(const Bytes &data);
};

// ---------------------------------------------------------------------------
// EncryptedBlob — the on-disk envelope for an AES-256-GCM-encrypted KeyStore.
// Layout: [version:1][nonce:12][cipherSize:4][ciphertext:N][tag:16]
// ---------------------------------------------------------------------------
struct EncryptedBlob {
        uint8_t version{1};
        Bytes nonce;
        Bytes ciphertext;
        Bytes tag;

        size_t size() const;
        Bytes serialize() const;
        static EncryptedBlob deserialize(const Bytes &data);
};

// ---------------------------------------------------------------------------
// KeyStore — static singleton that owns all registered Keys in memory and on
// disk.  Indexed by UKID (SHA-256 of accinfo || fingerprint).
// ---------------------------------------------------------------------------
class KeyStore {
        static SecureBytes _encryptionKey;
        static SecureBytes _salt;
        static std::unordered_map<Bytes, Key, BytesHash> _store;

    public:
        // Initialise from the password: derive the encryption key, then load
        // and decrypt the on-disk store if it already exists.
        static void init(std::string &password);

        // Number of entries currently held in memory.
        static size_t size();

        // ── Certificate helpers
        // ──────────────────────────────────────────────────
        static Bytes computeFingerprint(X509 *cert);
        static std::string extractCN(X509_NAME *name);
        static std::vector<std::string> extractSANs(X509 *cert);

        // Populate fingerprint / CN / SANs from a certificate (no secret or
        // accinfo; callers fill those in before calling store()).
        static Key buildKey(X509 *cert);

        // ── Mutation
        // ─────────────────────────────────────────────────────────────
        static void store(X509 *cert, const std::string &accinfo,
                          SecureBytes &&secret);
        // Takes ownership of key via move; existing entries with the same UKID
        // are overwritten.
        static void store(Key &key);
        static void erase(const Bytes &ukid);

        // ── Key identifiers
        // ────────────────────────────────────────────────────── UKID =
        // SHA-256(accinfo || fingerprint) — stable, unique per registration.
        static Bytes getUKID(const Key &key);

        // ── Lookup
        // ───────────────────────────────────────────────────────────────
        static const Key *lookupByUKID(const Bytes &ukid);
        static std::vector<const Key *> lookupByFG(const Bytes &fingerprint);
        static std::vector<const Key *> lookupByCN(const std::string &cn);
        static std::vector<const Key *>
        lookupByAccInfo(const std::string &accinfo);
        static std::vector<const Key *> getAllKeys();

        // ── Persistence
        // ──────────────────────────────────────────────────────────
        static Bytes serialize();
        static void deserialize(const Bytes &data);
        static EncryptedBlob encryptStore();
        static void decryptStore(const EncryptedBlob &blob);
        // Layout: [PBKDF2_SALT_SIZE] + [EncryptedBlob]
        static void saveStore();
        static void loadStore();
};
