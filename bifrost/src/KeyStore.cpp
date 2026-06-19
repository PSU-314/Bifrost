#include <KeyStore.hpp>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <securebytes.hpp>
#include <stdexcept>
#include <utility.hpp>

size_t Key::size() const {
    size_t s =
        4 + fingerprint.size() + 4 + commonName.size() + 4 + secret.size() + 4;
    for (const auto &san : sans)
        s += 4 + san.size();
    return s;
}

Bytes Key::serialize() const {
    Bytes data;
    data.reserve(size());

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

    if (data.empty())
        throw std::runtime_error("Could not deserialize blob: empty data");
    blob.version = data[0];
    if (blob.version != 1)
        throw std::runtime_error(
            "Could not deserialize blob: unsupported version");

    if (data.size() < 1 + BLOB_NONCE_SIZE)
        throw std::runtime_error("Could not deserialize blob");
    blob.nonce = Bytes(data.begin() + 1, data.begin() + 1 + BLOB_NONCE_SIZE);

    uint32_t cipherSize = readu32(data.data() + 1 + BLOB_NONCE_SIZE);

    // TODO: Handle overflow errors
    if (data.size() != 1 + BLOB_NONCE_SIZE + 4 + cipherSize + BLOB_TAG_SIZE)
        throw std::runtime_error(
            "Could not deserialize blob: invalid data size");

    blob.ciphertext =
        Bytes(data.begin() + 1 + BLOB_NONCE_SIZE + 4,
              data.begin() + 1 + BLOB_NONCE_SIZE + 4 + cipherSize);
    blob.tag =
        Bytes(data.begin() + 1 + BLOB_NONCE_SIZE + 4 + cipherSize, data.end());

    return blob;
}

// ========================================================================================

SecureBytes KeyStore::_encryptionKey;
std::unordered_map<Bytes, Key, BytesHash> KeyStore::_store;

void KeyStore::init(Bytes &encryptionKey) {
    assert(encryptionKey.size() == 32 &&
           "Could not decrypt KeyStore: given key was of incorrect len");

    _encryptionKey = SecureBytes(encryptionKey);

    if (fs::exists(Paths::keyfile())) {
        try {
            loadStore();
        } catch (const std::runtime_error &e) {
            std::cerr << "Failed to load existing key store due to wrong "
                         "encryption key\n"
                      << e.what() << std::endl;
            exit(EXIT_FAILURE);
        }
    }
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
    if (derLen < 0)
        throw std::runtime_error("Failed to DER-encode certificate");

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(der, derLen, digest);
    OPENSSL_free(der);
    return Bytes(digest, digest + SHA256_DIGEST_LENGTH);
}

std::string KeyStore::extractCN(X509_NAME *name) {
    char buf[256]{0};
    int len = X509_NAME_get_text_by_NID(name, NID_commonName, buf, sizeof(buf));
    if (len < 0)
        return "";
    return std::string(buf, len);
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

void KeyStore::store(X509 *cert, Bytes &secret) {
    Key key = buildKey(cert);
    key.secret = SecureBytes(secret);
    OPENSSL_cleanse(secret.data(), secret.size());
    _store[key.fingerprint] = std::move(key);
}

void KeyStore::store(Key &key) { _store[key.fingerprint] = std::move(key); }

const Key *KeyStore::lookup(const Bytes &fingerprint) {
    auto it = _store.find(fingerprint);
    return it != _store.end() ? &it->second : nullptr;
}

std::vector<const Key *> KeyStore::lookup(const std::string &cn) {
    std::vector<const Key *> matches;
    for (auto &[fp, key] : _store) {
        if (key.commonName == cn)
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

void KeyStore::erase(const Bytes &fingerprint) {
    auto it = _store.find(fingerprint);
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

    uint32_t nKeys = readu32(data.data());
    size_t offset = 4;
    for (uint32_t i = 0; i < nKeys; i++) {
        uint32_t keySize = readu32(data.data() + offset);
        if (data.size() < offset + 4 + keySize)
            throw std::runtime_error(
                "Cannot deserialize KeyStore: invalid data given");
        Key k = Key::deserialize(Bytes(data.begin() + offset + 4,
                                       data.begin() + offset + 4 + keySize));
        offset += 4 + keySize;
        _store[k.fingerprint] = std::move(k);
    }
    if (offset != data.size())
        throw std::runtime_error(
            "Trailing bytes after KeyStore deserialization");
}

EncryptedBlob KeyStore::encryptStore() {
    EncryptedBlob blob;
    blob.nonce.resize(BLOB_NONCE_SIZE);
    if (RAND_bytes(blob.nonce.data(), BLOB_NONCE_SIZE) != 1)
        throw std::runtime_error("RAND_bytes failed to generate nonce");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           _encryptionKey.data(), blob.nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    blob.ciphertext.resize(STORE_SIGNATURE.size() + size());
    Bytes plaintext, storeSerial = serialize();
    plaintext.reserve(STORE_SIGNATURE.size() + size());
    plaintext.insert(plaintext.end(), STORE_SIGNATURE.begin(),
                     STORE_SIGNATURE.end());
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

    blob.tag.resize(BLOB_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, BLOB_TAG_SIZE,
                            blob.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    return blob;
}

void KeyStore::decryptStore(const EncryptedBlob &blob) {
    if (blob.nonce.size() != BLOB_NONCE_SIZE)
        throw std::runtime_error("Invalid nonce size in encrypted blob");
    if (blob.tag.size() != BLOB_TAG_SIZE)
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

    if (plaintext.size() < STORE_SIGNATURE.size() ||
        !std::equal(STORE_SIGNATURE.begin(), STORE_SIGNATURE.end(),
                    plaintext.begin())) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw std::runtime_error(
            "Decrypted data missing expected store signature");
    }

    Bytes serialized(plaintext.begin() + STORE_SIGNATURE.size(),
                     plaintext.end());

    OPENSSL_cleanse(plaintext.data(), plaintext.size());

    deserialize(serialized);
}

void KeyStore::saveStore() {
    EncryptedBlob eb = encryptStore();
    Bytes ebSerial = eb.serialize();
    writeAtomic(Paths::keyfile(), ebSerial);
}

void KeyStore::loadStore() {
    Bytes ebSerial = readAtomic(Paths::keyfile());
    EncryptedBlob eb = EncryptedBlob::deserialize(ebSerial);
    decryptStore(eb);
}
