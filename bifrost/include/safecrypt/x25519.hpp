#pragma once

#include "BG.hpp"
#include "Types.hpp"

namespace Curve25519 {
// v^2 = u^3 + A * u^2 + u
const BigNum &P();
const BigNum &A();
const Bytes &Gx();
const int FIELD_BITS = 255;

BigNum loadU(const Bytes &inp);
BigNum decodeScalar(const Bytes &scal);
BigNum scalarMul(const BigNum &k, const BigNum &u);
Bytes x25519(const Bytes &k, const Bytes &u);

} // namespace Curve25519
