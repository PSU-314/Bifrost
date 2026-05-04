#pragma once
#include "Types.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string>

Bytes generate_hmac_sha1(const std::string &key, const std::string &msg);
