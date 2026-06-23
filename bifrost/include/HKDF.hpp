#pragma once

#include <bifrost.hpp>
#include <securebytes.hpp>

void hkdf_sha256(const SecureBytes &ikm, const SecureBytes &salt,
                 const Bytes &info, size_t outLen, SecureBytes &okm);
