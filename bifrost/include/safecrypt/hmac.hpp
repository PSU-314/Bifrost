#pragma once
#include "Types.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string>

Bytes hmac_sha1(const std::string &key, const std::string &msg);
Bytes hmac_sha1(const Bytes &key, const Bytes &msg);

Bytes hmac_sha256(const std::string &key, const std::string &msg);
Bytes hmac_sha256(const Bytes &key, const Bytes &msg);
