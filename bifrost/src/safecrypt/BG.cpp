#include <openssl/bn.h>
#include <safecrypt/BG.hpp>
#include <stdexcept>

// ============================================================
// BnContext
// ============================================================

BnContext::BnContext()
    : ctx_(BN_CTX_new()) {
    if (!ctx_)
        throw std::runtime_error("BN_CTX_new failed");
}

BnContext::~BnContext() { BN_CTX_free(ctx_); }

BN_CTX *BnContext::get() const { return ctx_; }

// ============================================================
// BigNum — Constructors
// ============================================================

BigNum::BigNum()
    : bn_(BN_new()) {
    if (!bn_)
        throw std::runtime_error("BN_new failed");
}

BigNum::BigNum(unsigned long val)
    : BigNum() {
    if (!BN_set_word(bn_, val))
        throw std::runtime_error("BN_set_word failed");
}

BigNum::BigNum(const std::string &hex)
    : BigNum() {
    BIGNUM *tmp = bn_;
    if (!BN_hex2bn(&tmp, hex.c_str()))
        throw std::runtime_error("BN_hex2bn failed: invalid hex string");
    bn_ = tmp;
}

BigNum BigNum::fromBytes(const unsigned char *data, int len) {
    BigNum result;
    if (!BN_bin2bn(data, len, result.bn_))
        throw std::runtime_error("BN_bin2bn failed");
    return result;
}

// ============================================================
// BigNum — Copy & Move
// ============================================================

BigNum::BigNum(const BigNum &other)
    : bn_(BN_dup(other.bn_)) {
    if (!bn_)
        throw std::runtime_error("BN_dup failed");
}

BigNum &BigNum::operator=(const BigNum &other) {
    if (this != &other) {
        BIGNUM *dup = BN_dup(other.bn_);
        if (!dup)
            throw std::runtime_error("BN_dup failed");
        BN_free(bn_);
        bn_ = dup;
    }
    return *this;
}

BigNum::BigNum(BigNum &&other) noexcept
    : bn_(other.bn_) {
    other.bn_ = nullptr;
}

BigNum &BigNum::operator=(BigNum &&other) noexcept {
    if (this != &other) {
        BN_free(bn_);
        bn_ = other.bn_;
        other.bn_ = nullptr;
    }
    return *this;
}

// ============================================================
// BigNum — Destructor
// ============================================================

BigNum::~BigNum() {
    BN_free(bn_); // BN_free is null-safe
}

// ============================================================
// BigNum — Raw access
// ============================================================

BIGNUM *BigNum::get() { return bn_; }

const BIGNUM *BigNum::get() const { return bn_; }

// ============================================================
// BigNum — Conversions
// ============================================================

std::string BigNum::toHex() const {
    char *hex = BN_bn2hex(bn_);
    if (!hex)
        throw std::runtime_error("BN_bn2hex failed");
    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

std::string BigNum::toDec() const {
    char *dec = BN_bn2dec(bn_);
    if (!dec)
        throw std::runtime_error("BN_bn2dec failed");
    std::string result(dec);
    OPENSSL_free(dec);
    return result;
}

Bytes BigNum::toBytes() const {
    int len = BN_num_bytes(bn_);
    std::vector<unsigned char> buf(len);
    BN_bn2bin(bn_, buf.data());
    return buf;
}

// ============================================================
// BigNum — Queries
// ============================================================

int BigNum::numBits() const { return BN_num_bits(bn_); }
int BigNum::numBytes() const { return BN_num_bytes(bn_); }
bool BigNum::bit(int n) const { return BN_is_bit_set(bn_, n); }
bool BigNum::isZero() const { return BN_is_zero(bn_); }
bool BigNum::isOne() const { return BN_is_one(bn_); }
bool BigNum::isNegative() const { return BN_is_negative(bn_); }

// ============================================================
// BigNum — Comparison
// ============================================================

int BigNum::compare(const BigNum &other) const {
    return BN_cmp(bn_, other.bn_);
}

bool BigNum::operator==(const BigNum &o) const {
    return BN_cmp(bn_, o.bn_) == 0;
}
bool BigNum::operator!=(const BigNum &o) const { return !(*this == o); }
bool BigNum::operator<(const BigNum &o) const { return BN_cmp(bn_, o.bn_) < 0; }
bool BigNum::operator<=(const BigNum &o) const {
    return BN_cmp(bn_, o.bn_) <= 0;
}
bool BigNum::operator>(const BigNum &o) const { return BN_cmp(bn_, o.bn_) > 0; }
bool BigNum::operator>=(const BigNum &o) const {
    return BN_cmp(bn_, o.bn_) >= 0;
}

// ============================================================
// BigNum — Arithmetic
// ============================================================

BigNum BigNum::operator+(const BigNum &rhs) const {
    BigNum result;
    if (!BN_add(result.bn_, bn_, rhs.bn_))
        throw std::runtime_error("BN_add failed");
    return result;
}

BigNum BigNum::operator-(const BigNum &rhs) const {
    BigNum result;
    if (!BN_sub(result.bn_, bn_, rhs.bn_))
        throw std::runtime_error("BN_sub failed");
    return result;
}

BigNum BigNum::operator*(const BigNum &rhs) const {
    BigNum result;
    BnContext ctx;
    if (!BN_mul(result.bn_, bn_, rhs.bn_, ctx.get()))
        throw std::runtime_error("BN_mul failed");
    return result;
}

BigNum BigNum::operator/(const BigNum &rhs) const {
    if (rhs.isZero())
        throw std::domain_error("BigNum division by zero");
    BigNum quotient;
    BnContext ctx;
    if (!BN_div(quotient.bn_, nullptr, bn_, rhs.bn_, ctx.get()))
        throw std::runtime_error("BN_div failed");
    return quotient;
}

BigNum BigNum::operator%(const BigNum &rhs) const {
    if (rhs.isZero())
        throw std::domain_error("BigNum modulo by zero");
    BigNum remainder;
    BnContext ctx;
    if (!BN_mod(remainder.bn_, bn_, rhs.bn_, ctx.get()))
        throw std::runtime_error("BN_mod failed");
    return remainder;
}

BigNum &BigNum::operator+=(const BigNum &rhs) {
    if (!BN_add(bn_, bn_, rhs.bn_))
        throw std::runtime_error("BN_add failed");
    return *this;
}

BigNum &BigNum::operator-=(const BigNum &rhs) {
    if (!BN_sub(bn_, bn_, rhs.bn_))
        throw std::runtime_error("BN_add failed");
    return *this;
}

BigNum &BigNum::operator*=(const BigNum &rhs) {
    BnContext ctx;
    if (!BN_mul(bn_, bn_, rhs.bn_, ctx.get()))
        throw std::runtime_error("BN_add failed");
    return *this;
}

BigNum &BigNum::operator/=(const BigNum &rhs) {
    BnContext ctx;
    if (!BN_div(bn_, nullptr, bn_, rhs.bn_, ctx.get()))
        throw std::runtime_error("BN_add failed");
    return *this;
}

BigNum &BigNum::operator%=(const BigNum &rhs) {
    if (rhs.isZero())
        throw std::domain_error("BigNum modulo by zero");
    BnContext ctx;
    if (!BN_mod(bn_, bn_, rhs.bn_, ctx.get()))
        throw std::runtime_error("BN_mod failed");
    return *this;
}

BigNum BigNum::operator<<(int n) const {
    BigNum result;
    if (!BN_lshift(result.bn_, bn_, n))
        throw std::runtime_error("BN_lshift failed");
    return result;
}

BigNum BigNum::operator>>(int n) const {
    BigNum result;
    if (!BN_rshift(result.bn_, bn_, n))
        throw std::runtime_error("BN_rshift failed");
    return result;
}

BigNum BigNum::sqr(const BnContext &ctx) const {
    BigNum result;
    if (!BN_sqr(result.bn_, bn_, ctx.get()))
        throw std::runtime_error("BN_sqr failed");
    return result;
}

BigNum BigNum::sqr(const BigNum &a, const BnContext &ctx) { return a.sqr(ctx); }

// ============================================================
// BigNum — Cryptographic operations
// ============================================================

BigNum BigNum::modExp(const BigNum &base, const BigNum &exp, const BigNum &mod,
                      const BnContext &ctx) {
    if (mod.isZero())
        throw std::domain_error("modExp: modulus is zero");
    BigNum result;
    if (!BN_mod_exp(result.bn_, base.bn_, exp.bn_, mod.bn_, ctx.get()))
        throw std::runtime_error("BN_mod_exp failed");
    return result;
}

BigNum BigNum::modInverse(const BigNum &a, const BigNum &m,
                          const BnContext &ctx) {
    BigNum result;
    if (!BN_mod_inverse(result.bn_, a.bn_, m.bn_, ctx.get()))
        throw std::runtime_error("BN_mod_inverse failed: no inverse exists");
    return result;
}

BigNum BigNum::modSqr(const BigNum &a, const BigNum &p, const BnContext &ctx) {
    BigNum result;
    if (!BN_mod_sqr(result.bn_, a.bn_, p.bn_, ctx.get()))
        throw std::runtime_error("BN_mod_sqr faled");
    return result;
}

BigNum BigNum::modSqrt(const BigNum &a, const BigNum &p, const BnContext &ctx) {
    BigNum result;
    if (!BN_mod_sqrt(result.bn_, a.bn_, p.bn_, ctx.get()))
        throw std::runtime_error("BN_mod_sqrt failed: no sqrt exists");
    return result;
}

BigNum BigNum::modMul(const BigNum &a, const BigNum &b, const BigNum &p,
                      const BnContext &ctx) {
    BigNum result;
    if (!BN_mod_mul(result.bn_, a.bn_, b.bn_, p.bn_, ctx.get()))
        throw std::runtime_error(
            "BN_mod_mul faild: could not perform multiplication");
    return result;
}

BigNum BigNum::modAdd(const BigNum &a, const BigNum &b, const BigNum &p,
                      const BnContext &ctx) {
    BigNum result;
    if (!BN_mod_add(result.bn_, a.bn_, b.bn_, p.bn_, ctx.get()))
        throw std::runtime_error(
            "BN_mod_add faild: could not perform addition");
    return result;
}

BigNum BigNum::modSub(const BigNum &a, const BigNum &b, const BigNum &p,
                      const BnContext &ctx) {
    BigNum result;
    if (!BN_mod_sub(result.bn_, a.bn_, b.bn_, p.bn_, ctx.get()))
        throw std::runtime_error(
            "BN_mod_sub faild: could not perform subtraction");
    return result;
}

BigNum BigNum::gcd(const BigNum &a, const BigNum &b, const BnContext &ctx) {
    BigNum result;
    if (!BN_gcd(result.bn_, a.bn_, b.bn_, ctx.get()))
        throw std::runtime_error("BN_gcd failed");
    return result;
}

BigNum BigNum::random(int bits, bool topBitSet) {
    BigNum result;
    int top = topBitSet ? BN_RAND_TOP_ONE : BN_RAND_TOP_ANY;
    if (!BN_rand(result.bn_, bits, top, BN_RAND_BOTTOM_ANY))
        throw std::runtime_error("BN_rand failed");
    return result;
}

BigNum BigNum::randomRange(const BigNum &range) {
    BigNum result;
    if (!BN_rand_range(result.bn_, range.bn_))
        throw std::runtime_error("BN_rand_range failed");
    return result;
}

void BigNum::cswap(BigNum &a, BigNum &b, int swapBit, int bits) {
    const int nBytes = (bits + 7) / 8;
    Bytes bufA(nBytes, 0x00);
    Bytes bufB(nBytes, 0x00);

    if (BN_bn2binpad(a.bn_, bufA.data(), nBytes) < 0)
        throw std::runtime_error("BN_bn2binpad failed for a");
    if (BN_bn2binpad(b.bn_, bufB.data(), nBytes) < 0)
        throw std::runtime_error("BN_bn2binpad failed for b");

    const volatile Byte mask = static_cast<Byte>(-(swapBit & 1));
    for (int i = 0; i < nBytes; i++) {
        Byte diff = mask & (bufA[i] ^ bufB[i]);
        bufA[i] ^= diff;
        bufB[i] ^= diff;
    }

    if (!BN_bin2bn(bufA.data(), nBytes, a.bn_))
        throw std::runtime_error("BN_bin2bn failed for a");
    if (!BN_bin2bn(bufB.data(), nBytes, b.bn_))
        throw std::runtime_error("BN_bin2bn failed for a");
}

bool BigNum::isPrime(const BnContext &ctx) const {
    int result = BN_check_prime(bn_, ctx.get(), nullptr);
    if (result < 0)
        throw std::runtime_error("BN_check_prime failed");
    return result == 1;
}

BigNum BigNum::generatePrime(int bits, bool safe) {
    BigNum result;
    if (!BN_generate_prime_ex(result.bn_, bits, safe ? 1 : 0, nullptr, nullptr,
                              nullptr))
        throw std::runtime_error("BN_generate_prime_ex failed");
    return result;
}
