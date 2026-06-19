#include <HMAC-SHA1.hpp>
#include <TypeDefs.hpp>
#include <boost/lexical_cast.hpp>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <tls.hpp>
#include <totp.hpp>
#include <unistd.h>
#include <utility.hpp>

namespace fs = std::filesystem;

const fs::path DATA_DIR = "~/.local/share/bifrost";
const fs::path KEY_STORAGE = DATA_DIR / "totp.keys";
const std::string SENTINEL_FLAG = "--in-terminal";

void launchInTerminal(const std::string selfPath, int argc, char **argv) {
    std::string innerCmd = "\"" + selfPath + "\" " + SENTINEL_FLAG;
    for (int i = 1; i < argc; i++)
        innerCmd += " \"" + std::string(argv[i]) + "\"";
    execlp("terminator", "terminator", "-e", innerCmd.c_str(), (char *)nullptr);
    std::perror("Failed to exec terminal emulator");
    exit(EXIT_FAILURE);
}

void setupDirectories() {
    if (!fs::exists(DATA_DIR)) {
        fs::create_directories(DATA_DIR);
        std::cout << "Created bifrost data directories" << std::endl;
    }
    std::cout << fs::exists(DATA_DIR) << std::endl;
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
    setupDirectories();
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
