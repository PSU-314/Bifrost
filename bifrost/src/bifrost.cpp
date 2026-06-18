#include <HMAC-SHA1.hpp>
#include <TypeDefs.hpp>
#include <boost/lexical_cast.hpp>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <pty.h> // openpty
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <tls.hpp>
#include <unistd.h>
#include <utility.hpp>

namespace fs = std::filesystem;

#define TIME_WINDOW 30
#define OTP_SIZE 6
#define TOTP_KEY_FILE "totp.key"
#define TOTP_KEY_LEN 32

const std::string FIFO_PATH = "/tmp/bifrost-term-fifo";
const std::string SENTINEL_FLAG = "--in-terminal";

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

void launchInTerminal(const std::string selfPath, int argc, char **argv) {
    std::string innerCmd = "\"" + selfPath + "\" " + SENTINEL_FLAG;
    for (int i = 1; i < argc; i++)
        innerCmd += " \"" + std::string(argv[i]) + "\"";
    execlp("terminator", "terminator", "-e", innerCmd.c_str(), (char *)nullptr);
    std::perror("Failed to exec terminal emulator");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    bool inTerminal =
        (argc > 1 && std::strcmp(argv[1], SENTINEL_FLAG.c_str()) == 0);
    if (!inTerminal) {
        char selfPath[4096];
        ssize_t len =
            readlink("/proc/self/exe", selfPath, sizeof(selfPath) - 1);
        if (len == -1) {
            std::perror("readlink(/proc/self/exe) failed");
            return EXIT_FAILURE;
        }
        selfPath[len] = 0;

        pid_t pid = fork();
        if (pid == -1) {
            std::perror("fork failed");
            return EXIT_FAILURE;
        }
        if (pid == 0)
            launchInTerminal(selfPath, argc, argv);
        return EXIT_SUCCESS;
    }

    Bytes totpKey;
    if (!fs::exists(TOTP_KEY_FILE) || argc > 1) {
        std::cout << "No existing secret found, starting new "
                     "registration.\nEnter the server registration code: ";
        std::string serverRegCode;
        std::cin >> serverRegCode;

        totpKey = establishTOTPKey(serverRegCode, TOTP_KEY_LEN);
        if (totpKey.empty()) {
            std::cout << "Key Exchange with server failed. Aborting TOTP setup"
                      << std::endl;
            return 1;
        }

        std::ofstream skfile(TOTP_KEY_FILE, std::ios::binary);
        skfile.write(reinterpret_cast<const char *>(totpKey.data()),
                     totpKey.size());
        skfile.close();
    } else {
        std::ifstream skfile(TOTP_KEY_FILE, std::ios::binary);
        totpKey.resize(TOTP_KEY_LEN);
        skfile.read(reinterpret_cast<char *>(totpKey.data()), TOTP_KEY_LEN);
        skfile.close();
    }

    uint32_t otp = generateOTP(totpKey);
    std::cout << "OTP: " << otp << std::endl;
}
