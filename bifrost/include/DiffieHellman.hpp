#pragma once

#include "TypeDefs.hpp"

#define PRIVATE_SECRET_LENGTH 30
#define KEY_SIZE 8

#define DH_GEN 23
#define DH_PRIME 775145549137931

#define SERVER_URL "http://localhost:5000/signup/"

Bytes generatePrivateSecret();
Bytes getServerPublicKey(const Bytes &pubKey, const std::string &serverRegCode);
Bytes generateSharedSecret(const std::string &serveRegCode);
Bytes resizeKey(const Bytes &key, const int nBytes);
