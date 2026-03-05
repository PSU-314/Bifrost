#pragma once

#include "TypeDefs.hpp"

#define PRIVATE_SECRET_LENGTH 30

namespace crypto {
namespace dh {

num_t generatePrivateSecret();
num_t generateSharedSecret(num_t privateSecret, num_t publicSecret, num_t n);

} // namespace dh
} // namespace crypto
