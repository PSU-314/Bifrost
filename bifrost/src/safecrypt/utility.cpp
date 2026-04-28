#include <iomanip>
#include <iostream>
#include <safecrypt/utility.hpp>
#include <stdexcept>

Byte hexCharToNibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    throw std::invalid_argument("Invalid hex character");
}

Bytes hexToBytes(const std::string &hex) {
    std::string _hex = (hex.length() & 1) ? "0" + hex : hex;

    Bytes bytes;
    bytes.reserve(hex.length() / 2);

    for (size_t i = 0; i < _hex.length(); i += 2) {
        Byte high = hexCharToNibble(_hex[i]);
        Byte low = hexCharToNibble(_hex[i + 1]);
        bytes.push_back((high << 4) | low);
    }

    return bytes;
}

std::string bytesToHex(const Bytes &bytes, bool uppercase,
                       const std::string sep) {
    if (bytes.empty())
        return "";

    std::ostringstream oss;
    oss << (uppercase ? std::uppercase : std::nouppercase) << std::hex
        << std::setfill('0');

    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0 && !sep.empty())
            oss << sep;
        oss << std::setw(2) << static_cast<int>(bytes[i]);
    }

    return oss.str();
}

void printBytes(const Bytes &bytes) {
    std::ios state(nullptr);
    state.copyfmt(std::cout);

    std::cout << std::hex << std::setfill('0');
    for (Byte b : bytes)
        std::cout << std::setw(2) << static_cast<int>(b);

    std::cout.copyfmt(state);
}
