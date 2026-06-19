#pragma once

#include <TypeDefs.hpp>
#include <assert.h>
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
#define BLOB_NONCE_SIZE 12
#define BLOB_TAG_SIZE 16
const Bytes STORE_SIGNATURE{0x42, 0x4B, 0x53, 0x4D, 0x00, 0x01, 0x00, 0x02};

struct Key {
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
        static std::unordered_map<Bytes, Key, BytesHash> _store;

    public:
        static void init(Bytes &encryptionKey);
        static size_t size();
        static Bytes computeFingerprint(X509 *cert);
        static std::string extractCN(X509_NAME *name);
        static std::vector<std::string> extractSANs(X509 *cert);
        static Key buildKey(X509 *cert);

        static void store(X509 *cert, SecureBytes &&secret);
        static void store(Key &key);
        static const Key *lookup(const Bytes &fingerprint);
        static std::vector<const Key *> lookup(const std::string &cn);
        static std::vector<const Key *> getAllKeys();

        static void erase(const Bytes &fingerprint);
        static Bytes serialize();
        static void deserialize(const Bytes &data);
        static EncryptedBlob encryptStore();
        static void decryptStore(const EncryptedBlob &blob);
        static void saveStore();
        static void loadStore();
};
