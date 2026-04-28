#include <MathFns.hpp>
#include <TypeDefs.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <iostream>
#include <stdexcept>

void printBytes(std::ostream &stream, const Bytes &bytes, bool shorten) {
    if (bytes.size() == 0)
        return;

    std::ios_base::fmtflags oldFlags = stream.flags();

    stream << "[" << bytes.size() << "]: ";
    if (shorten && bytes.size() >= 8) {
        for (size_t i = 0; i < 4; i++)
            stream << std::hex << ((bytes[i] & 0xF0) >> 4) << (bytes[i] & 0x0F);
        stream << std::dec << "..[" << bytes.size() - 8 << "]..";
        for (size_t i = bytes.size() - 4; i < bytes.size(); i++)
            stream << std::hex << ((bytes[i] & 0xF0) >> 4) << (bytes[i] & 0x0F);
    } else {
        for (Byte b : bytes)
            stream << std::hex << ((b & 0xF0) >> 4) << (b & 0x0F);
    }

    stream.flags(oldFlags);
    stream << std::dec;
}

Bytes numToBytes(num_t n, size_t targetBytes) {
    Bytes num;
    boost::multiprecision::export_bits(n, std::back_inserter(num), 8);

    if (num.size() > targetBytes)
        throw std::overflow_error("Number is too large for byte size");

    Bytes paddedNum(targetBytes - num.size(), 0x00);
    paddedNum.insert(paddedNum.end(), num.begin(), num.end());
    return paddedNum;
}

num_t bytesToNum(const Bytes &bytes) {
    num_t n;
    boost::multiprecision::import_bits(n, bytes.begin(), bytes.end());
    return n;
}

num_t powMod(num_t a, num_t b, num_t p) {
    num_t res = 1;
    a %= p;
    if (a == 0)
        return 0;

    while (b > 0) {
        if (b % 2 == 1)
            res = (res * a) % p;
        b /= 2;
        a = (a * a) % p;
    }

    return res;
}

num_t modularInverse(num_t a, num_t m) {
    if (m <= 1)
        throw std::domain_error("Modulus must be > 1");
    if (a == 0)
        throw std::domain_error("0 has no modular inverse");

    using signed_t = boost::multiprecision::cpp_int;
    signed_t x = 1, x1 = 0;
    signed_t a1 = static_cast<signed_t>(a);
    signed_t m1 = static_cast<signed_t>(m);
    signed_t m0 = m1;

    while (m1 > 0) {
        signed_t q = a1 / m1;
        std::tie(x, x1) = std::make_tuple(x1, x - q * x1);
        std::tie(a1, m1) = std::make_tuple(m1, a1 - q * m1);
    }

    if (a1 != 1)
        throw std::domain_error("Modular inverse does not exist");

    return static_cast<num_t>((x % m0 + m0) % m0);
}

num_t mod(const num_t &n, const num_t &p) {
    num_t r = n % p;
    return r < 0 ? r + p : r;
}

num_t addmod(const num_t &a, const num_t &b, const num_t &p) {
    return mod(a + b, p);
}
num_t submod(const num_t &a, const num_t &b, const num_t &p) {
    return mod(a - b, p);
}

num_t mulmod(const num_t &a, const num_t &b, const num_t &p) {
    return mod(a * b, p);
}

bool is_quadratic_residue(const num_t &n, const num_t &p) {
    if (mod(n, p) == 0)
        return true;
    return powMod(n, (p - 1) / 2, p) == 1;
}

std::pair<num_t, num_t> modularSqrt(num_t n, num_t p) {
    num_t nn = mod(n, p);

    // Trivial
    if (nn == 0)
        return {0, 0};

    // Not a quadratic residue → x is not on the curve
    // if (!is_quadratic_residue(nn, p))
    //     return std::nullopt;
    assert(is_quadratic_residue(nn, p) &&
           "Given X does not belong on the curve");

    // Fast path: p ≡ 3 (mod 4)
    if (p % 4 == 3) {
        num_t y = powMod(nn, (p + 1) / 4, p);
        return std::make_pair(y, submod(p, y, p));
    }

    // General Tonelli-Shanks for p ≡ 1 (mod 4)
    // Step 1: write p-1 = Q * 2^S
    num_t Q = p - 1;
    num_t S = 0;
    while (Q % 2 == 0) {
        Q /= 2;
        S += 1;
    }

    // Step 2: find a quadratic non-residue z
    num_t z = 2;
    while (is_quadratic_residue(z, p))
        z += 1;

    // Step 3: initialise
    num_t M = S;
    num_t c = powMod(z, Q, p);
    num_t t = powMod(nn, Q, p);
    num_t R = powMod(nn, (Q + 1) / 2, p);

    // Step 4: iterate
    while (true) {
        if (t == 1)
            return std::make_pair(R, submod(p, R, p));

        // Find least i > 0 such that t^(2^i) ≡ 1
        num_t i = 1;
        num_t tmp = mulmod(t, t, p);
        while (tmp != 1) {
            tmp = mulmod(tmp, tmp, p);
            i += 1;
        }

        // b = c^(2^(M-i-1)) mod p
        num_t exp = num_t(1) << static_cast<unsigned>(M - i - 1);
        num_t b = powMod(c, exp, p);

        M = i;
        c = mulmod(b, b, p);
        t = mulmod(t, c, p);
        R = mulmod(R, b, p);
    }
}
