#include <bifrost.hpp>
#include <fcntl.h>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <utility.hpp>

using namespace fs;

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

// Convert a hex character to its 0–15 nibble value, or -1 on bad input.
int hexNibble(char c) noexcept {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

void printBytes(std::ostream &stream, const Bytes &bytes, bool shorten) {
    if (bytes.empty())
        return;

    // Format: [total_size]: <hex bytes>
    stream << "[" << bytes.size() << "]: ";

    if (shorten) {
        // Show first 4 and last 4 bytes with an ellipsis in the middle.
        for (size_t i = 0; i < 4; ++i)
            stream << std::hex << ((bytes[i] & 0xF0) >> 4) << (bytes[i] & 0x0F);
        stream << std::dec << "..[" << bytes.size() - 8 << "]..";
        for (size_t i = bytes.size() - 4; i < bytes.size(); ++i)
            stream << std::hex << ((bytes[i] & 0xF0) >> 4) << (bytes[i] & 0x0F);
    } else {
        for (Byte b : bytes)
            stream << std::hex << ((b & 0xF0) >> 4) << (b & 0x0F);
    }
    stream << std::dec;
}

Bytes hexToBytes(std::string_view hex) {
    // Strip optional "0x" / "0X" prefix.
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        hex.remove_prefix(2);

    if (hex.size() % 2 != 0)
        throw std::runtime_error("hex string has odd number of characters");

    Bytes bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hexNibble(hex[i]);
        int lo = hexNibble(hex[i + 1]);
        if (hi == -1 || lo == -1)
            throw std::runtime_error("hex string contains invalid character");
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return bytes;
}

std::string bytesToHex(const Bytes &bytes) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (Byte b : bytes)
        ss << std::setw(2) << static_cast<int>(b);
    return ss.str();
}

// ---------------------------------------------------------------------------
// TOTP time encoding
// ---------------------------------------------------------------------------

// Encode a Unix timestamp as a big-endian 8-byte counter, per RFC 6238.
Bytes timeToBytes(const std::time_t time) {
    Bytes bytes(8);
    uint64_t t = static_cast<uint64_t>(time);
    // Fill from the least-significant byte upward (index 7 → 0).
    for (int b = 7; b >= 0; --b) {
        bytes[static_cast<size_t>(b)] = static_cast<Byte>(t & 0xFF);
        t >>= 8;
    }
    return bytes;
}

// ---------------------------------------------------------------------------
// Binary serialisation helpers (little-endian uint32)
// ---------------------------------------------------------------------------

// Append a uint32 as four little-endian bytes.
void writeu32(Bytes &out, uint32_t v) {
    out.push_back(static_cast<Byte>(v & 0xFF));
    out.push_back(static_cast<Byte>((v >> 8) & 0xFF));
    out.push_back(static_cast<Byte>((v >> 16) & 0xFF));
    out.push_back(static_cast<Byte>((v >> 24) & 0xFF));
}

// Read a little-endian uint32 from an unaligned pointer.
uint32_t readu32(const Byte *p) {
    // Shift-and-OR avoids aliasing / alignment UB vs. memcpy-then-ntohl.
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

// Read a length-prefixed blob [uint32 len][len bytes] from data at offset.
// Advances offset past the consumed bytes; throws on truncated input.
Bytes readField(const Bytes &data, size_t &offset) {
    if (offset + 4 > data.size())
        throw std::runtime_error("readField: truncated length prefix");

    uint32_t len = readu32(data.data() + offset);
    offset += 4;

    if (len > data.size() - offset)
        throw std::runtime_error("readField: field length exceeds buffer");

    Bytes field(data.begin() + static_cast<ptrdiff_t>(offset),
                data.begin() + static_cast<ptrdiff_t>(offset + len));
    offset += len;
    return field;
}

// ---------------------------------------------------------------------------
// Atomic file I/O
// ---------------------------------------------------------------------------

// Write data to path safely: write to a .tmp sibling, fsync, rename.
// A power failure before the rename leaves the old file intact; after it,
// the new file is guaranteed complete.  The parent directory is also fsynced
// so the rename entry is durable.
void writeAtomic(const fs::path &path, const Bytes &data, uint32_t perms) {
    fs::path tmp(path.string() + ".tmp");

    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC,
                    static_cast<mode_t>(perms));
    if (fd < 0)
        throw std::runtime_error("writeAtomic: open failed for " +
                                 tmp.string());

    ssize_t written = ::write(fd, data.data(), data.size());
    if (written < 0 || static_cast<size_t>(written) != data.size()) {
        ::close(fd);
        throw std::runtime_error("writeAtomic: write failed for " +
                                 tmp.string());
    }

    if (::fsync(fd) != 0) {
        ::close(fd);
        throw std::runtime_error("writeAtomic: fsync failed for " +
                                 tmp.string());
    }
    ::close(fd);

    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec)
        throw std::runtime_error("writeAtomic: rename failed: " + ec.message());

    // Fsync the parent directory so the directory entry update is durable.
    int dirfd = ::open(path.parent_path().c_str(), O_RDONLY);
    if (dirfd >= 0) {
        ::fsync(dirfd);
        ::close(dirfd);
    }
}

// Read the contents of path into a Bytes buffer.  Retries on EINTR; tolerates
// a file that shrinks between stat and read (stops at actual EOF).
Bytes readAtomic(const fs::path &path) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0)
        throw std::runtime_error("readAtomic: open failed for " +
                                 path.string());

    std::error_code ec;
    uintmax_t size = fs::file_size(path, ec);
    if (ec) {
        ::close(fd);
        throw std::runtime_error("readAtomic: stat failed for " +
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
            throw std::runtime_error("readAtomic: read failed for " +
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

// ---------------------------------------------------------------------------
// URL query-string parser
// ---------------------------------------------------------------------------

// Split url into key=value pairs separated by kvDelim.  Returns string_view
// slices into url, so url must remain valid for the lifetime of the result.
[[nodiscard]]
std::unordered_map<std::string_view, std::string_view>
parseURLParams(const std::string_view url, const char kvDelim,
               const char valDelim) {
    std::unordered_map<std::string_view, std::string_view> params;
    size_t pos = 0;
    size_t size = url.size();

    while (pos < size) {
        size_t pairEnd = url.find(kvDelim, pos);
        if (pairEnd == std::string_view::npos)
            pairEnd = size;

        std::string_view segment = url.substr(pos, pairEnd - pos);
        size_t eqPos = segment.find(valDelim);

        if (eqPos != std::string_view::npos)
            params[segment.substr(0, eqPos)] = segment.substr(eqPos + 1);
        else if (!segment.empty())
            params[segment] = {}; // key with no value

        pos = pairEnd + 1;
    }
    return params;
}
