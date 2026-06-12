#pragma once

#include <TypeDefs.hpp>

void hkdf_sha256(const Bytes &ikm, const Bytes &salt, const Bytes &info,
                 size_t outLen, Bytes &okm);
