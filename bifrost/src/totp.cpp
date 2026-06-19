#include <math.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <securebytes.hpp>
#include <totp.hpp>

Bytes generate_hmac_sha1(const SecureBytes &key, const std::string &msg) {
    Bytes hash(20);
    unsigned int len = 0;

    if (!HMAC(EVP_sha1(), key.data(), key.size(),
              reinterpret_cast<const unsigned char *>(msg.c_str()),
              msg.length(), hash.data(), &len)) {
        return Bytes();
    }

    return hash;
}

uint32_t genSample(const SecureBytes &key, std::time_t time) {
    Bytes hash = generate_hmac_sha1(key, std::to_string(time));
    std::cout << std::endl;
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
