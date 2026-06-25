#pragma once

#include <bifrost.hpp>
#include <functional>
#include <iostream>
#include <string_view>
#include <unordered_map>

// ---------------------------------------------------------------------------
// BytesHash — FNV/std hash over Bytes via string_view, used by KeyStore's
// unordered_map.  Reinterpret-cast is safe because Byte is unsigned char.
// ---------------------------------------------------------------------------
struct BytesHash {
        std::size_t operator()(const Bytes &bytes) const noexcept {
            std::string_view sv(reinterpret_cast<const char *>(bytes.data()),
                                bytes.size());
            return std::hash<std::string_view>{}(sv);
        }
};

// Hex helpers
int hexNibble(char c) noexcept;
void printBytes(std::ostream &stream, const Bytes &bytes, bool shorten = true);
Bytes hexToBytes(std::string_view hex);
std::string bytesToHex(const Bytes &bytes);

// TOTP time encoding: big-endian 8-byte counter per RFC 6238 / HOTP spec.
Bytes timeToBytes(std::time_t time);

// Little-endian uint32 read/write used by the KeyStore serialisation format.
void writeu32(Bytes &out, uint32_t v);
uint32_t readu32(const Byte *p);

// Length-prefixed field reader used by Key and EncryptedBlob deserialisation.
Bytes readField(const Bytes &data, size_t &offset);

// Atomic file I/O: write goes through a .tmp + rename to avoid partial writes;
// read retries on EINTR and handles files that shrink between stat and read.
void writeAtomic(const fs::path &path, const Bytes &data,
                 uint32_t perms = 0644);
Bytes readAtomic(const fs::path &path);

// URL query-string parser.  Returns string_view slices into the input; the
// caller must keep the input alive for the lifetime of the returned map.
// [[nodiscard]] because silently discarding the result is always a mistake.
[[nodiscard]]
std::unordered_map<std::string_view, std::string_view>
parseURLParams(std::string_view url, char kvDelim = '&', char valDelim = '=');
