// Implements RFC 6238 TOTP generation declared in totp.hpp: HMAC-SHA256,
// RFC 4226 dynamic truncation, and the final OTP_SIZE-digit code + validity
// window calculation.

#include <bifrost.hpp>
#include <cmath>
#include <cstdint>
#include <ctime>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <securebytes.hpp>
#include <stdexcept>
#include <totp.hpp>
#include <utility.hpp>

// Compute HMAC-SHA256(key, msg).  Returns TOTP_DIGEST_SIZE (32) bytes.
Bytes generate_hmac_sha256(const SecureBytes &key, const Bytes &msg) {
    Bytes hash(TOTP_DIGEST_SIZE);
    unsigned int len = 0;

    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char *>(msg.data()), msg.size(),
              hash.data(), &len))
        throw std::runtime_error(
            "generate_hmac_sha256: HMAC computation failed");

    if (len != TOTP_DIGEST_SIZE)
        throw std::runtime_error(
            "generate_hmac_sha256: unexpected output length");

    return hash;
}

// Dynamic truncation per RFC 4226 §5.3: the last nibble of the hash selects
// the offset, then four bytes are read and the top bit is masked off to
// produce a 31-bit unsigned integer.
uint32_t genSample(const SecureBytes &key, std::time_t timeStep) {
    Bytes hash = generate_hmac_sha256(key, timeToBytes(timeStep));
    Byte offset = hash.back() & 0x0F;

    uint32_t sample = (static_cast<uint32_t>(hash[offset]) << 24) |
                      (static_cast<uint32_t>(hash[offset + 1]) << 16) |
                      (static_cast<uint32_t>(hash[offset + 2]) << 8) |
                      static_cast<uint32_t>(hash[offset + 3]);

    sample &= 0x7FFF'FFFF; // clear the top bit per RFC 4226
    return sample;
}

// Generate the current TOTP code and how many seconds remain in the window.
TOTP generateOTP(const SecureBytes &key) {
    auto epoch = static_cast<uint32_t>(std::time(nullptr));
    auto curStep = static_cast<uint32_t>(epoch / TIME_WINDOW);

    // Use std::pow only for the modulus base; the cast to uint32_t is safe
    // because OTP_SIZE is 6 and 10^6 = 1,000,000 fits comfortably.
    uint32_t modulus = static_cast<uint32_t>(std::pow(10, OTP_SIZE));
    uint32_t otp = genSample(key, static_cast<std::time_t>(curStep)) % modulus;
    uint32_t validity =
        static_cast<uint32_t>(TIME_WINDOW) - epoch % TIME_WINDOW;

    return {otp, validity};
}
