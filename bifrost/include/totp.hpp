#pragma once
#include <bifrost.hpp>
#include <cstdint>
#include <securebytes.hpp>
#include <utility.hpp>

#define TIME_WINDOW 30
#define OTP_SIZE 6
#define TOTP_KEY_LEN 32
#define TOTP_DIGEST_SIZE 20

struct TOTP {
        uint32_t otp, validity;

        TOTP(uint32_t _otp, uint32_t _validity)
            : otp(_otp),
              validity(_validity) {}
};

Bytes generate_hmac_sha1(const SecureBytes &key, const Bytes &msg);
uint32_t genSample(const SecureBytes &key, std::time_t time);
TOTP generateOTP(const SecureBytes &key);
