#include <algorithm>
#include <safecrypt/BG.hpp>
#include <safecrypt/x25519.hpp>
#include <stdexcept>

namespace Curve25519 {
const BigNum &P() {
    static const BigNum P = BigNum(
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
    return P;
}
const BigNum &A() {
    static const BigNum A(486662ULL);
    return A;
}
const Bytes &Gx() {
    // Little Endian
    static const Bytes Gx = {0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    return Gx;
}

BigNum loadU(const Bytes &inp) {
    if (inp.size() != 32)
        throw std::runtime_error(
            "Size of given input bytes is not correct (32B)");
    Bytes _inp = inp;
    _inp[31] &= 0x7f;
    std::reverse(_inp.begin(), _inp.end());
    BigNum u = BigNum::fromBytes(_inp.data(), 32);
    return u;
}

BigNum decodeScalar(const Bytes &scal) {
    Bytes _k = scal;
    _k[0] &= 248;
    _k[31] &= 127;
    _k[31] |= 64;
    std::reverse(_k.begin(), _k.end());
    return BigNum::fromBytes(_k.data(), 32);
}

BigNum scalarMul(const BigNum &k, const BigNum &u) {
    const BigNum &p = Curve25519::P();
    const BigNum a24(121665ULL);

    // Initial state
    BigNum x_1 = u;
    BigNum x_2(1ULL);
    BigNum z_2(0ULL);
    BigNum x_3 = u;
    BigNum z_3(1ULL);
    int swap = 0;

    for (int t = 254; t >= 0; t--) {
        int k_t = k.bit(t) ? 1 : 0;
        swap ^= k_t;
        BigNum::cswap(x_2, x_3, swap, FIELD_BITS);
        BigNum::cswap(z_2, z_3, swap, FIELD_BITS);
        swap = k_t;

        // Step-by-step Montgomery math
        BnContext ctx;
        BigNum _A = BigNum::modAdd(x_2, z_2, p, ctx);
        BigNum _AA = BigNum::modSqr(_A, p, ctx);
        BigNum _B = BigNum::modSub(x_2, z_2, p, ctx);
        BigNum _BB = BigNum::modSqr(_B, p, ctx);
        BigNum _E = BigNum::modSub(_AA, _BB, p, ctx);
        BigNum _C = BigNum::modAdd(x_3, z_3, p, ctx);
        BigNum _D = BigNum::modSub(x_3, z_3, p, ctx);

        BigNum _DA = BigNum::modMul(_D, _A, p, ctx);
        BigNum _CB = BigNum::modMul(_C, _B, p, ctx);

        // x_3 = (DA + CB)^2
        x_3 = BigNum::modSqr(BigNum::modAdd(_DA, _CB, p, ctx), p, ctx);
        // z_3 = x_1 * (DA - CB)^2
        z_3 = BigNum::modMul(
            x_1, BigNum::modSqr(BigNum::modSub(_DA, _CB, p, ctx), p, ctx), p,
            ctx);

        // x_2 = AA * BB
        x_2 = BigNum::modMul(_AA, _BB, p, ctx);

        // z_2 = E * (AA + a24 * E)
        BigNum a24E = BigNum::modMul(a24, _E, p, ctx);
        z_2 = BigNum::modMul(_E, BigNum::modAdd(_AA, a24E, p, ctx), p, ctx);
    }
    // Final swap and inversion
    BigNum::cswap(x_2, x_3, swap, FIELD_BITS);
    BigNum::cswap(z_2, z_3, swap, FIELD_BITS);

    BnContext ctx;
    // Return x_2 * (z_2^(p - 2)) mod p (Fermat's Little Theorem for inverse)
    BigNum z2_inv = BigNum::modExp(z_2, p - BigNum(2ULL), p, ctx);
    // BigNum z2_inv = BigNum::modInverse(z_2, p, ctx);
    BigNum result = BigNum::modMul(x_2, z2_inv, p, ctx);

    return result;
}

Bytes x25519(const Bytes &k, const Bytes &u) {
    BigNum _k = decodeScalar(k);
    BigNum _u = loadU(u);
    BigNum res = scalarMul(_k, _u);

    Bytes out = res.toBytes();
    std::reverse(out.begin(), out.end());
    out.resize(32, 0x00);
    return out;
}

} // namespace Curve25519
