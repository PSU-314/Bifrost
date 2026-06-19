#include <HKDF.hpp>
#include <TypeDefs.hpp>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

void hkdf_sha256(const SecureBytes &ikm, const Bytes &salt, const Bytes &info,
                 size_t outLen, SecureBytes &okm) {
    okm.resize(outLen);

    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) {
        throw std::runtime_error("Failed to fetch HKDF implementation");
    }

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) {
        throw std::runtime_error("Failed to create KDF context");
    }

    OSSL_PARAM params[5];
    size_t i = 0;

    char md_name[] = "SHA256";
    params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                   md_name, sizeof(md_name));
    params[i++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<uint8_t *>(ikm.data()), ikm.size());
    params[i++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, const_cast<uint8_t *>(salt.data()), salt.size());
    params[i++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, const_cast<uint8_t *>(info.data()), info.size());
    params[i++] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, okm.data(), okm.size(), params) <= 0) {
        EVP_KDF_CTX_free(ctx);
        throw std::runtime_error("HKDF key derivation failed");
    }

    EVP_KDF_CTX_free(ctx);
}
