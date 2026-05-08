#include <TypeDefs.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility.hpp>

void printBytes(std::ostream &stream, const Bytes &bytes, bool shorten) {
    if (bytes.size() == 0)
        return;
    stream << "[" << bytes.size() << "]: ";
    if (shorten) {
        for (size_t i = 0; i < 4; i++)
            stream << std::hex << ((bytes[i] & 0xF0) >> 4) << (bytes[i] & 0x0F);
        stream << std::dec << "..[" << bytes.size() - 8 << "]..";
        for (size_t i = bytes.size() - 4; i < bytes.size(); i++)
            stream << std::hex << ((bytes[i] & 0xF0) >> 4) << (bytes[i] & 0x0F);
    } else {
        for (Byte b : bytes)
            stream << std::hex << ((b & 0xF0) >> 4) << (b & 0x0F);
    }
    stream << std::dec;
}

Bytes numToBytes(num_t n, size_t bytes) {
    Bytes num;
    boost::multiprecision::export_bits(n, std::back_inserter(num), 8);
    return num;
}

std::string bytesToHex(const Bytes &bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (Byte b : bytes)
        ss << std::setw(2) << static_cast<int>(b);
    return ss.str();
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
