#pragma once

#include <bifrost.hpp>
#include <securebytes.hpp>

void hkdf_sha256(const SecureBytes &ikm, const SecureBytes &salt,
                 const Bytes &info, size_t outLen, SecureBytes &okm);
void pbkdf2_sha256(const SecureBytes &password, const SecureBytes &salt,
                   int n_iterations, SecureBytes &derived);
