#pragma once
#include <HMAC-SHA1.hpp>
#include <TypeDefs.hpp>
#include <utility.hpp>

#define TIME_WINDOW 30
#define OTP_SIZE 6
#define TOTP_KEY_FILE "totp.key"
#define TOTP_KEY_LEN 32

uint32_t genSample(const Bytes &key, std::time_t time);
uint32_t generateOTP(const Bytes &key);
