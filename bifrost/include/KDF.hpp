#pragma once

#include <bifrost.hpp>
#include <securebytes.hpp>

// HKDF-SHA256: Extract-then-Expand per RFC 5869.
// ikm  — input keying material (the source secret)
// salt — optional random value; improves security when ikm has low entropy
// info — context/application-specific binding string
// okm  — output buffer; resized to outLen bytes before returning
void hkdf_sha256(const SecureBytes &ikm, const SecureBytes &salt,
                 const Bytes &info, size_t outLen, SecureBytes &okm);
// PBKDF2-SHA256: password-based key derivation per RFC 2898 §5.2.
// n_iterations should be >= 310 000 (OWASP 2023 recommendation for SHA-256).
// derived — output buffer; resized to SHA256_DIGEST_LENGTH (32) bytes.
void pbkdf2_sha256(const SecureBytes &password, const SecureBytes &salt,
                   int n_iterations, SecureBytes &derived);
