#pragma once
#include "TypeDefs.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>

Bytes generate_hmac_sha1(const std::string &key, const std::string &msg);
