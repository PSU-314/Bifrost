#include "bifrost.hpp"
#include <KDF.hpp>
#include <KeyStore.hpp>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <ranges>
#include <securebytes.hpp>
#include <stdexcept>
#include <utility.hpp>

// ---------------------------------------------------------------------------
// Static member definitions
// ---------------------------------------------------------------------------
SecureBytes KeyStore::_encryptionKey;
SecureBytes KeyStore::_salt;
std::unordered_map<Bytes, Key, BytesHash> KeyStore::_store;

// ---------------------------------------------------------------------------
// Key serialisation  (length-prefixed TLV, little-endian uint32 lengths)
// ---------------------------------------------------------------------------

size_t Key::size() const {
    // Each field: 4-byte length prefix + payload.
    size_t s = (4 + accinfo.size()) + (4 + fingerprint.size()) +
               (4 + commonName.size()) + 4 + // SAN count
               (4 + secret.size());
    for (const auto &san : sans)
        s += 4 + san.size();
    return s;
}

Bytes Key::serialize() const {
    Bytes data;
    data.reserve(size());

    auto appendStr = [&](const std::string &s) {
        writeu32(data, static_cast<uint32_t>(s.size()));
        data.insert(data.end(), s.begin(), s.end());
    };
    auto appendBytes = [&](const Bytes &b) {
        writeu32(data, static_cast<uint32_t>(b.size()));
        data.insert(data.end(), b.begin(), b.end());
    };

    appendStr(accinfo);
    appendBytes(fingerprint);
    appendStr(commonName);

    writeu32(data, static_cast<uint32_t>(sans.size()));
    for (const auto &san : sans)
        appendStr(san);

    // Secret is last; SecureBytes iterators yield Byte values.
    writeu32(data, static_cast<uint32_t>(secret.size()));
    data.insert(data.end(), secret.begin(), secret.end());

    return data;
}

Key Key::deserialize(const Bytes &data) {
    size_t offset = 0;
    Key key;

    // Helper that reads a field and converts it to std::string.
    auto readStr = [&]() -> std::string {
        Bytes b = readField(data, offset);
        return std::string(b.begin(), b.end());
    };

    key.accinfo = readStr();
    key.fingerprint = readField(data, offset);
    key.commonName = readStr();

    if (offset + 4 > data.size())
        throw std::runtime_error("Key::deserialize: truncated SAN count");
    uint32_t sanCount = readu32(data.data() + offset);
    offset += 4;

    // Guard against pathological inputs before reserving / looping.
    constexpr uint32_t MaxSansCount = 1000;
    if (sanCount > MaxSansCount)
        throw std::runtime_error("Key::deserialize: implausible SAN count");

    key.sans.reserve(sanCount);
    for (uint32_t i = 0; i < sanCount; ++i) {
        Bytes san = readField(data, offset);
        key.sans.emplace_back(san.begin(), san.end());
    }

    key.secret = readField(data, offset);

    if (offset != data.size())
        throw std::runtime_error("Key::deserialize: trailing bytes after end");

    return key;
}

// ---------------------------------------------------------------------------
// EncryptedBlob serialisation
// Layout: [version:1][nonce:12][cipherSize:4][ciphertext:N][tag:16]
// ---------------------------------------------------------------------------

size_t EncryptedBlob::size() const {
    //        version      nonce              cipherSize     ciphertext tag
    return 1 + nonce.size() + 4 + ciphertext.size() + tag.size();
}

Bytes EncryptedBlob::serialize() const {
    Bytes out;
    out.reserve(size());

    out.push_back(version);
    out.insert(out.end(), nonce.begin(), nonce.end());

    writeu32(out, static_cast<uint32_t>(ciphertext.size()));
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), tag.begin(), tag.end());

    return out;
}

EncryptedBlob EncryptedBlob::deserialize(const Bytes &data) {
    // Minimum size: 1 (version) + 12 (nonce) + 4 (cipherSize) + 16 (tag).
    constexpr size_t headerSize =
        1 + ENC_BLOB_NONCE_SIZE + 4 + ENC_BLOB_TAG_SIZE;

    if (data.empty())
        throw std::runtime_error("EncryptedBlob::deserialize: empty data");

    EncryptedBlob blob;
    blob.version = data[0];
    if (blob.version != 1)
        throw std::runtime_error(
            "EncryptedBlob::deserialize: unsupported version");
    if (data.size() < headerSize)
        throw std::runtime_error("EncryptedBlob::deserialize: data too short");

    blob.nonce =
        Bytes(data.begin() + 1,
              data.begin() + 1 + static_cast<ptrdiff_t>(ENC_BLOB_NONCE_SIZE));

    uint32_t cipherSize = readu32(data.data() + 1 + ENC_BLOB_NONCE_SIZE);

    // Both checks are needed: the first catches overflow, the second catches
    // trailing bytes which indicate a corrupt or truncated file.
    if (cipherSize > data.size() - headerSize)
        throw std::runtime_error(
            "EncryptedBlob::deserialize: cipherSize overflows buffer");
    if (data.size() != headerSize + cipherSize)
        throw std::runtime_error(
            "EncryptedBlob::deserialize: unexpected trailing bytes");

    auto cipherStart =
        data.begin() + 1 + static_cast<ptrdiff_t>(ENC_BLOB_NONCE_SIZE) + 4;
    blob.ciphertext =
        Bytes(cipherStart, cipherStart + static_cast<ptrdiff_t>(cipherSize));
    blob.tag =
        Bytes(cipherStart + static_cast<ptrdiff_t>(cipherSize), data.end());

    return blob;
}

// ---------------------------------------------------------------------------
// KeyStore — initialisation
// ---------------------------------------------------------------------------

void KeyStore::init(std::string &password) {
    // Wrap the password in SecureBytes immediately so it is wiped on exit.
    SecureBytes passwd(reinterpret_cast<const Byte *>(password.data()),
                       password.size());

    _salt.resize(PBKDF2_SALT_SIZE);
    bool keyfileExists = fs::exists(Paths::keyfile());

    if (keyfileExists) {
        // Read the salt that was stored at the front of the existing keyfile.
        std::ifstream kf(Paths::keyfile(), std::ios::binary);
        kf.read(reinterpret_cast<char *>(_salt.data()),
                static_cast<std::streamsize>(PBKDF2_SALT_SIZE));
        if (static_cast<size_t>(kf.gcount()) != PBKDF2_SALT_SIZE)
            throw std::runtime_error("KeyStore::init: corrupted keyfile");
    } else {
        // First run — generate a fresh random salt.
        if (RAND_bytes(_salt.data(), static_cast<int>(PBKDF2_SALT_SIZE)) != 1)
            throw std::runtime_error("KeyStore::init: RAND_bytes failed");
    }

    pbkdf2_sha256(passwd, _salt, PBKDF2_N_ITERATIONS, _encryptionKey);
    // Wipe the caller's plaintext password now that the key is derived.
    OPENSSL_cleanse(password.data(), password.size());

    if (keyfileExists)
        loadStore();
}

// ---------------------------------------------------------------------------
// Size (bytes that serialize() would produce, excluding the outer salt field)
// ---------------------------------------------------------------------------
size_t KeyStore::size() {
    size_t s = 4; // key count
    for (const auto &[fp, key] : _store)
        s += 4 + key.size();
    return s;
}

// ---------------------------------------------------------------------------
// Certificate helpers
// ---------------------------------------------------------------------------

Bytes KeyStore::computeFingerprint(X509 *cert) {
    // DER-encode the full certificate, then SHA-256 hash it.
    unsigned char *der = nullptr;
    int derLen = i2d_X509(cert, &der);
    if (derLen < 0 || !der)
        throw std::runtime_error("computeFingerprint: DER encoding failed");

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (!mdctx || EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, der, static_cast<size_t>(derLen)) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest, &digestLen) != 1) {
        if (mdctx)
            EVP_MD_CTX_free(mdctx);
        OPENSSL_free(der);
        throw std::runtime_error("computeFingerprint: digest failed");
    }
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(der);

    return Bytes(digest, digest + digestLen);
}

std::string KeyStore::extractCN(X509_NAME *name) {
    // Query length first, then allocate exactly the right buffer.
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

    auto *gens = static_cast<GENERAL_NAMES *>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (!gens)
        return result;

    for (int i = 0; i < sk_GENERAL_NAME_num(gens); ++i) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(gens, i);
        if (gen->type == GEN_DNS) {
            ASN1_STRING *dns = gen->d.dNSName;
            result.emplace_back(
                reinterpret_cast<const char *>(ASN1_STRING_get0_data(dns)),
                static_cast<size_t>(ASN1_STRING_length(dns)));
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

// ---------------------------------------------------------------------------
// Mutation
// ---------------------------------------------------------------------------

void KeyStore::store(X509 *cert, const std::string &accinfo,
                     SecureBytes &&secret) {
    Key key = buildKey(cert);
    key.secret = std::move(secret);
    key.accinfo = accinfo;
    Bytes ukid = getUKID(key);
    _store[ukid] = std::move(key);
}

// Moves key into the store; caller should not use key after this call.
void KeyStore::store(Key &key) {
    Bytes ukid = getUKID(key);
    _store[ukid] = std::move(key);
}

void KeyStore::erase(const Bytes &ukid) {
    // find-then-erase avoids a second lookup compared to _store.erase(ukid).
    auto it = _store.find(ukid);
    if (it != _store.end())
        _store.erase(it);
}

// ---------------------------------------------------------------------------
// Key identifiers
// ---------------------------------------------------------------------------

// UKID = SHA-256(accinfo || fingerprint) — stable and unique per registration.
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
        throw std::runtime_error("getUKID: SHA-256 computation failed");
    }
    EVP_MD_CTX_free(mdctx);
    return Bytes(digest, digest + digestLen);
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

const Key *KeyStore::lookupByUKID(const Bytes &ukid) {
    auto it = _store.find(ukid);
    return it != _store.end() ? &it->second : nullptr;
}

std::vector<const Key *> KeyStore::lookupByFG(const Bytes &fingerprint) {
    std::vector<const Key *> matches;
    for (const auto &[ukid, key] : _store) {
        // Use CRYPTO_memcmp to avoid timing side-channels even though
        // fingerprints are not secret; it's a cheap habit here.
        if (key.fingerprint.size() == fingerprint.size() &&
            CRYPTO_memcmp(key.fingerprint.data(), fingerprint.data(),
                          fingerprint.size()) == 0)
            matches.push_back(&key);
    }
    return matches;
}

std::vector<const Key *> KeyStore::lookupByCN(const std::string &cn) {
    std::vector<const Key *> matches;
    for (const auto &[ukid, key] : _store)
        if (key.commonName == cn)
            matches.push_back(&key);
    return matches;
}

std::vector<const Key *> KeyStore::lookupByAccInfo(const std::string &accinfo) {
    std::vector<const Key *> matches;
    for (const auto &[ukid, key] : _store)
        if (key.accinfo == accinfo)
            matches.push_back(&key);
    return matches;
}

std::vector<const Key *> KeyStore::getAllKeys() {
    std::vector<const Key *> keys;
    keys.reserve(_store.size());
    for (const auto &[ukid, key] : _store)
        keys.push_back(&key);
    return keys;
}

// ---------------------------------------------------------------------------
// Encryption / decryption  (AES-256-GCM)
// ---------------------------------------------------------------------------

EncryptedBlob KeyStore::encryptStore() {
    EncryptedBlob blob;
    blob.nonce.resize(ENC_BLOB_NONCE_SIZE);
    if (RAND_bytes(blob.nonce.data(), static_cast<int>(ENC_BLOB_NONCE_SIZE)) !=
        1)
        throw std::runtime_error("encryptStore: RAND_bytes failed");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("encryptStore: EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           _encryptionKey.data(), blob.nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("encryptStore: EVP_EncryptInit_ex failed");
    }

    // Prepend the magic signature so we can detect a wrong password on decrypt.
    Bytes storeSerial = serialize();
    Bytes plaintext;
    plaintext.reserve(KEY_STORE_SIGNATURE.size() + storeSerial.size());
    plaintext.insert(plaintext.end(), KEY_STORE_SIGNATURE.begin(),
                     KEY_STORE_SIGNATURE.end());
    plaintext.insert(plaintext.end(), storeSerial.begin(), storeSerial.end());

    blob.ciphertext.resize(plaintext.size()); // GCM produces no expansion

    int outlen = 0, finallen = 0;
    if (EVP_EncryptUpdate(ctx, blob.ciphertext.data(), &outlen,
                          plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("encryptStore: EVP_EncryptUpdate failed");
    }
    if (EVP_EncryptFinal_ex(ctx, blob.ciphertext.data() + outlen, &finallen) !=
        1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("encryptStore: EVP_EncryptFinal_ex failed");
    }

    blob.tag.resize(ENC_BLOB_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(ENC_BLOB_TAG_SIZE),
                            blob.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("encryptStore: GCM tag extraction failed");
    }
    EVP_CIPHER_CTX_free(ctx);
    return blob;
}

void KeyStore::decryptStore(const EncryptedBlob &blob) {
    if (blob.nonce.size() != ENC_BLOB_NONCE_SIZE)
        throw std::runtime_error("decryptStore: invalid nonce size");
    if (blob.tag.size() != ENC_BLOB_TAG_SIZE)
        throw std::runtime_error("decryptStore: invalid tag size");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("decryptStore: EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           _encryptionKey.data(), blob.nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("decryptStore: EVP_DecryptInit_ex failed");
    }

    Bytes plaintext(blob.ciphertext.size());
    int outlen = 0, finallen = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen,
                          blob.ciphertext.data(),
                          static_cast<int>(blob.ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("decryptStore: EVP_DecryptUpdate failed");
    }

    // Set the expected GCM authentication tag before calling Final.
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(blob.tag.size()),
                            const_cast<Byte *>(blob.tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("decryptStore: failed to set GCM tag");
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &finallen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw std::runtime_error("decryptStore: authentication tag mismatch — "
                                 "data corrupted, tampered, or wrong key");
    }

    plaintext.resize(static_cast<size_t>(outlen + finallen));

    // Verify the magic signature to catch a wrong password that somehow
    // produces an otherwise valid GCM tag (e.g. all-zero key scenario).
    if (plaintext.size() < KEY_STORE_SIGNATURE.size() ||
        CRYPTO_memcmp(plaintext.data(), KEY_STORE_SIGNATURE.data(),
                      KEY_STORE_SIGNATURE.size()) != 0) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw std::runtime_error("decryptStore: store signature missing");
    }

    Bytes serialized(plaintext.begin() +
                         static_cast<ptrdiff_t>(KEY_STORE_SIGNATURE.size()),
                     plaintext.end());
    OPENSSL_cleanse(plaintext.data(), plaintext.size());

    deserialize(serialized);
}

// ---------------------------------------------------------------------------
// Serialisation (unencrypted, in-memory only — always goes through encrypt)
// ---------------------------------------------------------------------------

Bytes KeyStore::serialize() {
    Bytes out;
    out.reserve(size());

    writeu32(out, static_cast<uint32_t>(_store.size()));
    for (const auto &[ukid, key] : _store) {
        Bytes k = key.serialize();
        writeu32(out, static_cast<uint32_t>(k.size()));
        out.insert(out.end(), k.begin(), k.end());
    }
    return out;
}

void KeyStore::deserialize(const Bytes &data) {
    _store.clear();

    if (data.size() < 4)
        throw std::runtime_error("KeyStore::deserialize: missing key count");

    uint32_t nKeys = readu32(data.data());
    size_t offset = 4;

    for (uint32_t i = 0; i < nKeys; ++i) {
        if (offset + 4 > data.size())
            throw std::runtime_error(
                "KeyStore::deserialize: truncated key-size field");

        uint32_t keySize = readu32(data.data() + offset);
        offset += 4;

        if (keySize > data.size() - offset)
            throw std::runtime_error(
                "KeyStore::deserialize: key size overflows buffer");

        Key k = Key::deserialize(
            Bytes(data.begin() + static_cast<ptrdiff_t>(offset),
                  data.begin() + static_cast<ptrdiff_t>(offset + keySize)));
        offset += keySize;

        Bytes ukid = getUKID(k);
        _store[ukid] = std::move(k);
    }

    if (offset != data.size())
        throw std::runtime_error("KeyStore::deserialize: trailing bytes");
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

void KeyStore::saveStore() {
    EncryptedBlob eb = encryptStore();
    Bytes ebSerial = eb.serialize();

    // On-disk layout: [salt:16][encrypted_blob...]
    Bytes storeData;
    storeData.reserve(PBKDF2_SALT_SIZE + ebSerial.size());
    storeData.insert(storeData.end(), _salt.begin(), _salt.end());
    storeData.insert(storeData.end(), ebSerial.begin(), ebSerial.end());

    writeAtomic(Paths::keyfile(), storeData, 0600);
}

void KeyStore::loadStore() {
    Bytes storeData = readAtomic(Paths::keyfile());
    // Skip the salt prefix (already read during init).
    Bytes ebSerial(storeData.begin() + static_cast<ptrdiff_t>(PBKDF2_SALT_SIZE),
                   storeData.end());
    EncryptedBlob eb = EncryptedBlob::deserialize(ebSerial);
    decryptStore(eb);
}
