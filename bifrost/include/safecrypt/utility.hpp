#pragma once

#include "Types.hpp"
#include <string>

Bytes strToBytes(const std::string &str);
Bytes hexToBytes(const std::string &hex);
std::string bytesToHex(const Bytes &bytes, bool uppercase = false,
                       const std::string sep = "");
void printBytes(const Bytes &bytes);
