#include <TypeDefs.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <utility.hpp>

constexpr int hex_char_to_int(char c) noexcept {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

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

Bytes hexToBytes(std::string_view hex) {
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex.remove_prefix(2);
    }

    if (hex.size() % 2 != 0)
        throw std::runtime_error("Given hex string has odd number of literals");

    Bytes bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        int high_nibble = hex_char_to_int(hex[i]);
        int low_nibble = hex_char_to_int(hex[i + 1]);

        if (high_nibble == -1 || low_nibble == -1)
            throw std::runtime_error("Given hex string has invalid characters");

        bytes.push_back(static_cast<uint8_t>((high_nibble << 4) | low_nibble));
    }

    return bytes;
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
