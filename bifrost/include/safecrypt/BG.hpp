#pragma once
#include "Types.hpp"
#include <openssl/bn.h>
#include <string>

// --- RAII wrapper for BN_CTX ---
class BnContext {
    public:
        BnContext();
        ~BnContext();

        BN_CTX *get() const;

        BnContext(const BnContext &) = delete;
        BnContext &operator=(const BnContext &) = delete;

    private:
        BN_CTX *ctx_;
};

// --- Main BigNum class ---
class BigNum {
    public:
        // ---- Constructors ----
        BigNum();
        explicit BigNum(unsigned long val);
        explicit BigNum(const std::string &hex);
        static BigNum fromBytes(const unsigned char *data, int len);

        // ---- Copy & Move ----
        BigNum(const BigNum &other);
        BigNum &operator=(const BigNum &other);
        BigNum(BigNum &&other) noexcept;
        BigNum &operator=(BigNum &&other) noexcept;

        // ---- Destructor ----
        ~BigNum();

        // ---- Raw access ----
        BIGNUM *get();
        const BIGNUM *get() const;

        // ---- Conversions ----
        std::string toHex() const;
        std::string toDec() const;
        Bytes toBytes() const;

        // ---- Queries ----
        int numBits() const;
        int numBytes() const;
        bool bit(int n) const;
        bool isZero() const;
        bool isOne() const;
        bool isNegative() const;

        // ---- Comparison ----
        int compare(const BigNum &other) const;
        bool operator==(const BigNum &o) const;
        bool operator!=(const BigNum &o) const;
        bool operator<(const BigNum &o) const;
        bool operator<=(const BigNum &o) const;
        bool operator>(const BigNum &o) const;
        bool operator>=(const BigNum &o) const;

        // ---- Arithmetic ----
        BigNum operator+(const BigNum &rhs) const;
        BigNum operator-(const BigNum &rhs) const;
        BigNum operator*(const BigNum &rhs) const;
        BigNum operator/(const BigNum &rhs) const;
        BigNum operator%(const BigNum &rhs) const;

        BigNum &operator+=(const BigNum &rhs);
        BigNum &operator-=(const BigNum &rhs);
        BigNum &operator*=(const BigNum &rhs);
        BigNum &operator/=(const BigNum &rhs);
        BigNum &operator%=(const BigNum &rhs);

        BigNum operator<<(int n) const;
        BigNum operator>>(int n) const;

        BigNum sqr(const BnContext &ctx = BnContext()) const;

        static BigNum sqr(const BigNum &a, const BnContext &ctx = BnContext());

        // ---- Cryptographic operations ----
        static BigNum modExp(const BigNum &base, const BigNum &exp,
                             const BigNum &mod,
                             const BnContext &ctx = BnContext());
        static BigNum modInverse(const BigNum &a, const BigNum &m,
                                 const BnContext &ctx = BnContext());
        static BigNum modSqr(const BigNum &a, const BigNum &p,
                             const BnContext &ctx = BnContext());
        static BigNum modSqrt(const BigNum &a, const BigNum &p,
                              const BnContext &ctx = BnContext());
        static BigNum modMul(const BigNum &a, const BigNum &b, const BigNum &p,
                             const BnContext &ctx = BnContext());
        static BigNum modAdd(const BigNum &a, const BigNum &b, const BigNum &p,
                             const BnContext &ctx = BnContext());
        static BigNum modSub(const BigNum &a, const BigNum &b, const BigNum &p,
                             const BnContext &ctx = BnContext());

        static BigNum gcd(const BigNum &a, const BigNum &b,
                          const BnContext &ctx = BnContext());
        static BigNum random(int bits, bool topBitSet = true);
        static BigNum randomRange(const BigNum &range);
        static BigNum generatePrime(int bits, bool safe = true);

        static void cswap(BigNum &a, BigNum &b, int swapBit, int bits);

        bool isPrime(const BnContext &ctx = BnContext()) const;

    private:
        BIGNUM *bn_;
};
