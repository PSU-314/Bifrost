#include <DiffieHellman.hpp>
#include <MathFns.hpp>
#include <Random.hpp>
#include <TypeDefs.hpp>

namespace crypto {
namespace dh {

num_t generatePrivateSecret() {
    return Random::generatePrimeNum(PRIVATE_SECRET_LENGTH);
}

num_t generateSharedSecret(num_t privateSecret, num_t publicSecret, num_t n) {
    return powMod(publicSecret, privateSecret, n);
}

} // namespace dh
} // namespace crypto
