#pragma once

#include "TypeDefs.hpp"
#include <iostream>

void printBytes(std::ostream &stream, const Bytes &bytes, bool shorten = true);

Bytes numToBytes(num_t n, size_t bytes = 32);
num_t bytesToNum(const Bytes &bytes);

num_t powMod(num_t a, num_t b, num_t p);
num_t modularInverse(num_t a, num_t m);

num_t mod(const num_t &n, const num_t &p);
num_t addmod(const num_t &a, const num_t &b, const num_t &p);
num_t submod(const num_t &a, const num_t &b, const num_t &p);
num_t mulmod(const num_t &a, const num_t &b, const num_t &p);
bool is_quadratic_residue(const num_t &n, const num_t &p);
std::pair<num_t, num_t> modularSqrt(num_t n, num_t p);
