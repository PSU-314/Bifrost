#include <DiffieHellman.hpp>
#include <HMAC-SHA1.hpp>
#include <TypeDefs.hpp>
#include <boost/lexical_cast.hpp>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <utility.hpp>

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

int main(int argc, char **argv) {
    bool loadSK = true;
    if (!fs::exists("secret.key") || argc > 1) {
        loadSK = false;
    }

    std::string secretKey;
    if (loadSK) {
        std::cout << "Using existing secret found" << std::endl;
        std::ifstream skfile("secret.key");
        std::getline(skfile, secretKey);
        skfile.close();
    } else {
        std::cout << "No existing secret found, starting new "
                     "registration.\nEnter the server registration code: ";
        std::string serverRegCode;
        std::cin >> serverRegCode;

        secretKey = boost::lexical_cast<std::string>(
            generateSharedSecret(serverRegCode));

        std::ofstream skfile("secret.key");
        skfile << secretKey;
        skfile.close();
    }

    uint32_t otp = generateOTP(secretKey);
    std::cout << "OTP: " << otp << std::endl;
}
