#pragma once

#include "Types.hpp"

#define HKDF_HASH_LEN 32

Bytes hkdfExtract(const Bytes &salt, const Bytes &ikm);
Bytes hkdfExpand(const Bytes &prk, const Bytes &info, size_t L);
Bytes hkdf(const Bytes &ikm, const Bytes &salt, const Bytes &info, size_t L);
