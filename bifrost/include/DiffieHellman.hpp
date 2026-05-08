#pragma once

#include "TypeDefs.hpp"

#define PRIVATE_SECRET_LENGTH 30

#define DH_GEN 23
#define DH_PRIME 775145549137931

#define SERVER_URL "http://localhost:8000/signup/"

num_t generatePrivateSecret();
num_t getServerPublicKey(const num_t &pubKey, const std::string &serverRegCode);
num_t generateSharedSecret(const std::string &serveRegCode);
