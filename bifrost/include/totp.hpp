#pragma once

#include <bifrost.hpp>
#include <cstdint>
#include <ctime>
#include <securebytes.hpp>
#include <utility.hpp>

// TOTP parameters matching RFC 6238 defaults used by the Bifrost server.
// Converted from macros to typed constants to avoid preprocessor pollution and
// to let the compiler enforce types at call sites.
inline constexpr int TIME_WINDOW = 30;      // seconds per TOTP step
inline constexpr int OTP_SIZE = 6;          // decimal digits
inline constexpr int TOTP_KEY_LEN = 32;     // bytes; output of HKDF step
inline constexpr int TOTP_DIGEST_SIZE = 20; // HMAC-SHA1 output length

// TODO: SECURITY — SHA-1 is cryptographically weak; migrate to TOTP-SHA256
// (HMAC-SHA256, TOTP_DIGEST_SIZE = 32) once the server supports it.
// Both sides must switch simultaneously to avoid interoperability breakage.

struct TOTP {
        uint32_t otp;      // OTP_SIZE-digit code
        uint32_t validity; // seconds remaining in the current TIME_WINDOW
};

// Internal: compute HMAC-SHA1(key, msg).  Exposed for unit testing.
Bytes generate_hmac_sha1(const SecureBytes &key, const Bytes &msg);

// Internal: derive the truncated 31-bit sample for a given counter value.
uint32_t genSample(const SecureBytes &key, std::time_t timeStep);

// Generate a TOTP code from the stored secret using the current wall clock.
TOTP generateOTP(const SecureBytes &key);
