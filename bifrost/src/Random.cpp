#include <Random.hpp>
#include <TypeDefs.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <openssl/rand.h>

namespace crypto {

void Random::generateBytes(Bytes &buffer, size_t count) {
    buffer.resize(count);
    RAND_bytes(buffer.data(), count);
}

Bytes Random::generateBytes(size_t count) {
    Bytes result;
    generateBytes(result, count);
    return result;
}

num_t Random::generateNum(size_t bitSize) {
    size_t byteSize = (bitSize + 7) / 8;
    Bytes buf(byteSize);
    RAND_bytes(buf.data(), byteSize);

    num_t result = 0;
    for (size_t i = 0; i < byteSize; i++)
        result = (result << 8) | buf[i];

    result |= (num_t(1) << (bitSize - 1));
    result &= (boost::multiprecision::pow(num_t(2), bitSize) - 1);
    return result;
}

num_t Random::generatePrimeNum(size_t bitSize) {
    num_t candidate;
    while (true) {
        candidate = generateNum(bitSize);
        if (boost::multiprecision::miller_rabin_test(candidate, 60))
            return candidate;
    }
}

} // namespace crypto
