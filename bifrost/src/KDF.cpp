#include <KDF.hpp>
#include <bifrost.hpp>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/sha.h>
#include <stdexcept>

// ---------------------------------------------------------------------------
// HKDF-SHA256  (RFC 5869)
// ---------------------------------------------------------------------------
// Uses the OpenSSL 3.x EVP_KDF API.  EVP_KDF_free is called right after
// EVP_KDF_CTX_new; the context holds its own reference so freeing the
// algorithm handle early is safe and keeps resource cleanup simple.
void hkdf_sha256(const SecureBytes &ikm, const SecureBytes &salt,
                 const Bytes &info, size_t outLen, SecureBytes &okm) {
    okm.resize(outLen);

    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf)
        throw std::runtime_error("hkdf_sha256: failed to fetch HKDF provider");

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf); // context holds its own ref; safe to release early
    if (!ctx)
        throw std::runtime_error("hkdf_sha256: failed to create KDF context");

    // OSSL_PARAM_construct_* takes non-const pointers for legacy reasons; the
    // values are only read, not written.
    char md_name[] = "SHA256";
    OSSL_PARAM params[5];
    size_t i = 0;
    params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                   md_name, sizeof(md_name));
    params[i++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<Byte *>(ikm.data()), ikm.size());
    params[i++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, const_cast<Byte *>(salt.data()), salt.size());
    params[i++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, const_cast<Byte *>(info.data()), info.size());
    params[i++] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, okm.data(), okm.size(), params) <= 0) {
        EVP_KDF_CTX_free(ctx);
        throw std::runtime_error("hkdf_sha256: key derivation failed");
    }
    EVP_KDF_CTX_free(ctx);
}

// ---------------------------------------------------------------------------
// PBKDF2-SHA256  (RFC 2898 §5.2)
// ---------------------------------------------------------------------------
// Output is always SHA256_DIGEST_LENGTH (32) bytes; the caller receives the
// result via the out-parameter pattern used throughout KDF.hpp.
void pbkdf2_sha256(const SecureBytes &password, const SecureBytes &salt,
                   const int n_iterations, SecureBytes &derived) {
    derived.resize(SHA256_DIGEST_LENGTH);

    if (PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(password.data()),
                          static_cast<int>(password.size()), salt.data(),
                          static_cast<int>(salt.size()), n_iterations,
                          EVP_sha256(), static_cast<int>(derived.size()),
                          derived.data()) != 1)
        throw std::runtime_error("pbkdf2_sha256: derivation failed");
}
