#include <math.h>
#include <totp.hpp>

uint32_t genSample(const Bytes &key, std::time_t time) {
    Bytes hash = generate_hmac_sha1(key, std::to_string(time));
    std::cout << std::endl;
    Byte offset = hash.back() & 0x0F;
    int32_t sample = (hash[offset] << 24) | (hash[offset + 1] << 16) |
                     (hash[offset + 2] << 8) | hash[offset + 3];
    sample &= 0x7FFFFFFF;
    return sample;
}

uint32_t generateOTP(const Bytes &key) {
    std::time_t epoch = std::time(nullptr);
    std::time_t curtime = epoch / TIME_WINDOW;

    std::cout << "Key: ";
    printBytes(std::cout, key);
    std::cout << std::endl << "Time: " << epoch << std::endl;
    std::cout << "Expires in: " << TIME_WINDOW - epoch % TIME_WINDOW
              << std::endl
              << std::endl;

    return genSample(key, curtime) % (uint32_t)std::pow(10, OTP_SIZE);
}
