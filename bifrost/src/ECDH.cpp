#include <ECDH.hpp>
#include <MathFns.hpp>
#include <Random.hpp>
#include <iostream>

namespace crypto {

namespace ecdh {

Point Point::operator+(Point const &q) {
    Point r(c);
    num_t s;
    if (x == q.x && y != q.y)
        return Point(x, y, c);
    if (x == q.x) {
        s = ((3 * x * x + c.a) * modularInverse(2 * y, c.p)) % c.p;
    } else
        s = ((q.y - y) * modularInverse(q.x - x, c.p)) % c.p;
    r.x = (s * s - x - q.x) % c.p;
    r.y = (s * (x - r.x) - y) % c.p;

    return r;
}

Point operator*(const num_t &k, const Point &p) {
    if (k == 1) {
        return p;
    }
    Point q = (k / 2) * p;
    return k % 2 == 1 ? q + q + p : q + q;
}

std::ostream &operator<<(std::ostream &os, const Point &p) {
    os << "(" << p.x << ", " << p.y << ")";
    return os;
}

// Point getPointFromX(const num_t& x, const Curve& c) {
//     num_t ysqr = x * x * x + c.a * x + c.b;
//     num_t y = modularSqrt(ysqr, c.p);
//     return Point(x, y, c);
// }

Curve brainpoolP256r1(
    num_t("0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9"),
    num_t("0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6"),
    num_t(
        "0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377"));
Point brainpoolP256r1Generator(
    num_t("0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262"),
    num_t("0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997"),
    brainpoolP256r1);

ECDH::ECDH(std::string c) {
    if (c == "brainpoolP256r1") {
        curve = brainpoolP256r1;
        generator = brainpoolP256r1Generator;
    }
}

void ECDH::generateKeys() {
    privateKey = Random::generatePrimeNum(128);
    publicKey = privateKey * generator;
}

num_t ECDH::getPublicKey() const { return publicKey.x; }

num_t ECDH::getPrivateKey() const { return privateKey; }

Point ECDH::getPublicKeyPoint() const { return publicKey; }

Curve ECDH::getCurve() const { return curve; }

Point ECDH::getGenerator() const { return generator; }

} // namespace ecdh

} // namespace crypto
