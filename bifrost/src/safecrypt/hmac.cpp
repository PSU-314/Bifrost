#include "safecrypt/utility.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <safecrypt/hmac.hpp>

Bytes hmac_sha1(const std::string &key, const std::string &msg) {
    return hmac_sha1(strToBytes(key), strToBytes(msg));
}

Bytes hmac_sha1(const Bytes &key, const Bytes &msg) {
    Bytes hash(20);
    unsigned int len = 0;

    if (!HMAC(EVP_sha1(), key.data(), key.size(),
              reinterpret_cast<const unsigned char *>(msg.data()), msg.size(),
              hash.data(), &len)) {
        return Bytes();
    }

    return hash;
}

Bytes hmac_sha256(const std::string &key, const std::string &msg) {
    return hmac_sha256(strToBytes(key), strToBytes(msg));
}

Bytes hmac_sha256(const Bytes &key, const Bytes &msg) {
    Bytes hash(32);
    unsigned int len = 0;

    if (!HMAC(EVP_sha256(), key.data(), key.size(),
              reinterpret_cast<const unsigned char *>(msg.data()), msg.size(),
              hash.data(), &len)) {
        return Bytes();
    }
    return hash;
}
