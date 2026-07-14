// RFC 6238 TOTP generation from a stored HMAC-SHA256 secret: HMAC-SHA256
// over the current time step, RFC 4226 dynamic truncation, and reduction to
// an OTP_SIZE-digit code with remaining window validity.

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
inline constexpr int TOTP_DIGEST_SIZE = 32; // HMAC-SHA256 output length

struct TOTP {
        uint32_t otp;      // OTP_SIZE-digit code
        uint32_t validity; // seconds remaining in the current TIME_WINDOW
};

// Internal: compute HMAC-SHA256(key, msg).  Exposed for unit testing.
Bytes generate_hmac_sha256(const SecureBytes &key, const Bytes &msg);

// Internal: derive the truncated 31-bit sample for a given counter value.
uint32_t genSample(const SecureBytes &key, std::time_t timeStep);

// Generate a TOTP code from the stored secret using the current wall clock.
TOTP generateOTP(const SecureBytes &key);
