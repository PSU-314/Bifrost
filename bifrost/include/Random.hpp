#pragma once

#include "TypeDefs.hpp"

namespace crypto {

class Random {
    public:
        static void generateBytes(Bytes &buffer, size_t count);
        static Bytes generateBytes(size_t count);
        static num_t generateNum(size_t bitSize);
        static num_t generatePrimeNum(size_t bitSize);
};

} // namespace crypto
