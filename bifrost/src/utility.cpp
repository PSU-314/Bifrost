#include <TypeDefs.hpp>
#include <fcntl.h>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <utility.hpp>
using namespace fs;

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

Bytes timeToBytes(const std::time_t time) {
    Bytes bytes;
    bytes.reserve(8);

    std::time_t t = time;
    for (int b = 0; b < 8; b++) {
        bytes[b] = static_cast<Byte>(t & 0xFF);
        t >>= 8;
    }

    return bytes;
}

void writeu32(Bytes &out, uint32_t v) {
    out.push_back(static_cast<Byte>(v & 0xFF));
    out.push_back(static_cast<Byte>((v >> 8) & 0xFF));
    out.push_back(static_cast<Byte>((v >> 16) & 0xFF));
    out.push_back(static_cast<Byte>((v >> 24) & 0xFF));
}

uint32_t readu32(const Byte *p) {
    return static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1] << 8) |
           static_cast<uint32_t>(p[2] << 16) |
           static_cast<uint32_t>(p[3] << 24);
}

Bytes readField(const Bytes &data, size_t &offset) {
    if (offset + 4 > data.size())
        throw std::runtime_error("Truncated length prefix");
    uint32_t len = readu32(data.data() + offset);
    offset += 4;

    if (len > data.size() - offset)
        throw std::runtime_error("Field length exceeds remaining buffer");

    Bytes field(data.begin() + offset, data.begin() + offset + len);
    offset += len;
    return field;
}

void writeAtomic(const fs::path &path, const Bytes &data, uint32_t perms) {
    fs::path tmp(path.string() + ".tmp");

    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, perms);
    if (fd < 0)
        throw std::runtime_error("Failed to open tmp file for atomic write: " +
                                 tmp.string());

    ssize_t written = ::write(fd, data.data(), data.size());
    if (written < 0 || static_cast<size_t>(written) != data.size()) {
        ::close(fd);
        throw std::runtime_error(
            "Failed to write to tmp file for atomic write");
    }

    if (::fsync(fd) != 0) {
        ::close(fd);
        throw std::runtime_error("fsync failed on tmp file");
    }
    ::close(fd);

    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec)
        throw std::runtime_error("Atomic rename failed");

    int dirfd = ::open(path.parent_path().c_str(), O_RDONLY);
    if (dirfd >= 0) {
        ::fsync(dirfd);
        ::close(dirfd);
    }
}

Bytes readAtomic(const fs::path &path) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0)
        throw std::runtime_error("Failed to open file for atomic read: " +
                                 path.string());

    std::error_code ec;
    uintmax_t size = fs::file_size(path, ec);
    if (ec) {
        ::close(fd);
        throw std::runtime_error("Failed to stat file for atomic read: " +
                                 path.string());
    }

    Bytes data;
    if (size > 0)
        data.resize(static_cast<size_t>(size));

    size_t total = 0;
    while (total < data.size()) {
        ssize_t n = ::read(fd, data.data() + total, data.size() - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            ::close(fd);
            throw std::runtime_error("Failed to read file for atomic read: " +
                                     path.string());
        }
        if (n == 0)
            break; // file shrank concurrently; stop at actual EOF
        total += static_cast<size_t>(n);
    }
    data.resize(total);

    ::close(fd);
    return data;
}
