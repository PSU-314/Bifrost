#include <HMAC-SHA1.hpp>
#include <MathFns.hpp>
#include <TypeDefs.hpp>
#include <boost/lexical_cast.hpp>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <safecrypt/BG.hpp>
#include <safecrypt/utility.hpp>
#include <safecrypt/x25519.hpp>
#include <string>

namespace fs = std::filesystem;

#define TIME_WINDOW 30
#define OTP_SIZE 6

uint32_t genSample(std::string &key, std::time_t time) {
    Bytes hash = generate_hmac_sha1(key, std::to_string(time));
    printBytes(std::cout, hash);
    std::cout << std::endl;
    Byte offset = hash.back() & 0x0F;
    int32_t sample = (hash[offset] << 24) | (hash[offset + 1] << 16) |
                     (hash[offset + 2] << 8) | hash[offset + 3];
    sample &= 0x7FFFFFFF;
    return sample;
}

uint32_t generateOTP(std::string &key) {
    std::time_t epoch = std::time(nullptr);
    std::time_t curtime = epoch / TIME_WINDOW;

    std::cout << "Key: " << key << std::endl;
    std::cout << "Time: " << epoch << std::endl;
    std::cout << "Expires in: " << TIME_WINDOW - epoch % TIME_WINDOW
              << std::endl
              << std::endl;

    return genSample(key, curtime) % (uint32_t)std::pow(10, OTP_SIZE);
}

Bytes secretKey_ECDH() {
    Bytes secretKey = BigNum::random(256).toBytes();
    Bytes publicKey = Curve25519::x25519(secretKey, Curve25519::Gx());

    std::cout << "Bifrost Public Key: 0x";
    printBytes(publicKey);
    std::cout << std::endl;

    std::cout << "Enter server public key: ";
    std::string serverKeys;
    std::cin >> serverKeys;

    if (serverKeys.substr(0, 2) == "0x")
        serverKeys = serverKeys.substr(2);
    Bytes serverKey = hexToBytes(serverKeys);
    Bytes sharedSecret = Curve25519::x25519(secretKey, serverKey);

    std::cout << "Computed shared secret: ";
    printBytes(sharedSecret);
    std::cout << std::endl;
    return sharedSecret;
}

int main(int argc, char **argv) {
    bool loadSK = true;
    if (!fs::exists("secret.key") || argc > 1) {
        loadSK = false;
    }

    Bytes secretKey;
    std::string secretKeyStr;
    if (loadSK) {
        std::ifstream skfile("secret.key");
        std::getline(skfile, secretKeyStr);
        skfile.close();
        secretKey = hexToBytes(secretKeyStr);
    } else {
        secretKey = secretKey_ECDH();
        std::ofstream skfile("secret.key");
        printBytes(skfile, secretKey);
        skfile.close();
    }

    secretKeyStr = bytesToHex(secretKey);
    uint32_t otp = generateOTP(secretKeyStr);
    std::cout << "OTP: " << otp << std::endl;
}
