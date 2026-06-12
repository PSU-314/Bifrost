#include <HMAC-SHA1.hpp>
#include <TypeDefs.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>

Bytes generate_hmac_sha1(const Bytes &key, const std::string &msg) {
    Bytes hash(20);
    unsigned int len = 0;

    if (!HMAC(EVP_sha1(), key.data(), key.size(),
              reinterpret_cast<const unsigned char *>(msg.c_str()),
              msg.length(), hash.data(), &len)) {
        return Bytes();
    }

    return hash;
}
