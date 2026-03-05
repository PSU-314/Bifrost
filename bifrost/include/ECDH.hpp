#pragma once

#include "TypeDefs.hpp"

namespace crypto {

namespace ecdh {

typedef struct Curve {
        num_t a, b, p;
        Curve(num_t a, num_t b, num_t p)
            : a(a),
              b(b),
              p(p) {}
        Curve() {}
} Curve;

class Point {
    public:
        num_t x, y;
        Curve c;
        Point(num_t x, num_t y, Curve c)
            : x(x),
              y(y),
              c(c) {}
        Point(Curve c)
            : c(c) {}
        Point() {}

        Point operator+(Point const &q);
        friend Point operator*(const num_t &k, const Point &P);
};
std::ostream &operator<<(std::ostream &os, const Point &p);

extern Curve brainpoolP256r1;
extern Point brainpoolP256r1Generator;

class ECDH {
    private:
        Curve curve;
        Point generator;
        Point publicKey;
        num_t privateKey;

    public:
        ECDH(std::string c);

        void generateKeys();
        num_t getPublicKey() const;
        num_t getPrivateKey() const;
        Point getPublicKeyPoint() const;
        Curve getCurve() const;
        Point getGenerator() const;
};

} // namespace ecdh

} // namespace crypto
