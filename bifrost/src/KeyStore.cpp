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

    uint32_t cipherSize = static_cast<uint32_t>(ciphertext.size());
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
    SecureBytes passwd(reinterpret_cast<const Byte *>(password.data()),
                       password.size());

    _salt.resize(PBKDF2_SALT_SIZE);
    bool keyfileExists = fs::exists(Paths::keyfile());

    if (keyfileExists) {
        std::ifstream keyfile(Paths::keyfile(), std::ios::binary);
        keyfile.read(reinterpret_cast<char *>(_salt.data()), PBKDF2_SALT_SIZE);
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
        EVP_DigestUpdate(mdctx, der, static_cast<size_t>(derLen)) != 1 ||
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

    writeu32(out, static_cast<uint32_t>(_store.size()));

    for (const auto &[fp, key] : _store) {
        Bytes k = key.serialize();
        uint32_t keySize = static_cast<uint32_t>(key.size());
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
                          plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
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

    plaintext.resize(static_cast<size_t>(outlen + finallen));

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
