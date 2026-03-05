#include <Random.hpp>
#include <TypeDefs.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <random>

namespace crypto {

void Random::generateBytes(Bytes &buffer, size_t count) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);

    buffer.resize(count);
    for (size_t i = 0; i < count; i++)
        buffer[i] = static_cast<Byte>(distrib(gen));
}

Bytes Random::generateBytes(size_t count) {
    Bytes result;
    generateBytes(result, count);
    return result;
}

num_t Random::generateNum(size_t bitSize) {
    boost::random::mt19937 gen{std::random_device{}()};
    boost::random::uniform_int_distribution<num_t> distrib(
        boost::multiprecision::pow(num_t(2), bitSize - 1),
        boost::multiprecision::pow(num_t(2), bitSize) - 1);
    return distrib(gen);
}

num_t Random::generatePrimeNum(size_t bitSize) {
    num_t candidate;
    while (true) {
        candidate = generateNum(bitSize);
        if (boost::multiprecision::miller_rabin_test(candidate, 25))
            return candidate;
    }
}

} // namespace crypto
