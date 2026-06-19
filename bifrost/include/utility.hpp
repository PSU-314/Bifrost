#pragma once

#include <TypeDefs.hpp>
#include <functional>
#include <iostream>
#include <string_view>

struct BytesHash {
        std::size_t operator()(const Bytes &bytes) const {
            std::string_view sv(reinterpret_cast<const char *>(bytes.data()),
                                bytes.size());
            return std::hash<std::string_view>{}(sv);
        }
};

void printBytes(std::ostream &stream, const Bytes &bytes, bool shorten = true);
Bytes hexToBytes(std::string_view hex);
std::string bytesToHex(const Bytes &bytes);
Bytes timeToBytes(const std::time_t time);

void writeu32(Bytes &out, uint32_t v);
uint32_t readu32(const Byte *p);
Bytes readField(const Bytes &data, size_t &offset);

void writeAtomic(const fs::path &path, const Bytes &data,
                 uint32_t perms = 0644);
Bytes readAtomic(const fs::path &path);
