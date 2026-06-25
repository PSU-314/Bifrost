#include <cstdint>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <securebytes.hpp>
#include <stdexcept>
#include <totp.hpp>
#include <utility.hpp>

// TODO:
// SECURITY ISSUE: SHA1 is deprecated. Consider using SHA256
Bytes generate_hmac_sha1(const SecureBytes &key, const Bytes &msg) {
    Bytes hash(TOTP_DIGEST_SIZE);
    unsigned int len = 0;

    if (!HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char *>(msg.data()), msg.size(),
              hash.data(), &len))
        throw std::runtime_error("HMAC-SHA1 computaion failed");
    if (len != TOTP_DIGEST_SIZE)
        throw std::runtime_error("Unexpected HMAC-SHA1 output length");

    return hash;
}

uint32_t genSample(const SecureBytes &key, std::time_t time) {
    Bytes hash = generate_hmac_sha1(key, timeToBytes(time));
    Byte offset = hash.back() & 0x0F;
    auto sample =
        static_cast<uint32_t>((hash[offset] << 24) | (hash[offset + 1] << 16) |
                              (hash[offset + 2] << 8) | hash[offset + 3]);
    sample &= 0x7FFFFFFF;
    return sample;
}

TOTP generateOTP(const SecureBytes &key) {
    uint32_t epoch = static_cast<uint32_t>(std::time(nullptr));
    uint32_t curtime = epoch / TIME_WINDOW;

    uint32_t otp =
        genSample(key, curtime) % static_cast<uint32_t>(std::pow(10, OTP_SIZE));
    uint32_t validity = TIME_WINDOW - epoch % TIME_WINDOW;
    return {otp, validity};
}
