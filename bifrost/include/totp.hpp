#pragma once
#include <TypeDefs.hpp>
#include <securebytes.hpp>
#include <utility.hpp>

#define TIME_WINDOW 30
#define OTP_SIZE 6
#define TOTP_KEY_LEN 32

struct TOTP {
        int otp, validity;

        TOTP(int otp, int validity)
            : otp(otp),
              validity(validity) {}
};

Bytes generate_hmac_sha1(const SecureBytes &key, const std::string &msg);
uint32_t genSample(const SecureBytes &key, std::time_t time);
TOTP generateOTP(const SecureBytes &key);
