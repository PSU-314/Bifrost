#include <safecrypt/hkdf.hpp>
#include <safecrypt/hmac.hpp>
#include <stdexcept>

Bytes hkdfExtract(const Bytes &salt, const Bytes &ikm) {
    const static Bytes zero_salt(HKDF_HASH_LEN, 0x00);
    const auto &s = salt.empty() ? zero_salt : salt;

    return hmac_sha256(salt, ikm);
}

Bytes hkdfExpand(const Bytes &prk, const Bytes &info, size_t L) {
    if (L > 255 * HKDF_HASH_LEN)
        throw std::invalid_argument(
            "HKDF-Expand: requested length exceeds 255 * Hash Length");

    size_t N = (L + HKDF_HASH_LEN - 1) / HKDF_HASH_LEN;
    Bytes okm;
    okm.reserve(N * HKDF_HASH_LEN);

    Bytes T;
    for (Byte i = 1; i <= static_cast<Byte>(N); i++) {
        Bytes input;
        input.insert(input.end(), T.begin(), T.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(i);

        T = hmac_sha256(prk, input);
        okm.insert(okm.end(), T.begin(), T.end());
    }

    okm.resize(L);
    return okm;
}

Bytes hkdf(const Bytes &ikm, const Bytes &salt, const Bytes &info, size_t L) {
    auto prk = hkdfExtract(salt, ikm);
    return hkdfExpand(prk, info, L);
}
