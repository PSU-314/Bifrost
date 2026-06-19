#include <HMAC-SHA1.hpp>
#include <KeyStore.hpp>
#include <TypeDefs.hpp>
#include <boost/lexical_cast.hpp>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/sha.h>
#include <securebytes.hpp>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <tls.hpp>
#include <totp.hpp>
#include <unistd.h>
#include <utility.hpp>

namespace fs = std::filesystem;

const std::string SENTINEL_FLAG = "--in-terminal";

void launchInTerminal(const std::string selfPath, int argc, char **argv) {
    std::string innerCmd = "bash -c '\"" + selfPath + "\" " + SENTINEL_FLAG;
    for (int i = 1; i < argc; i++)
        innerCmd += " \"" + std::string(argv[i]) + "\"";
    innerCmd += " ; exec bash'";
    execlp("terminator", "terminator", "-x", innerCmd.c_str(), (char *)nullptr);
    std::perror("Failed to exec terminal emulator");
    exit(EXIT_FAILURE);
}

void unlockBifrost() {
    Bytes encKey;
    if (fs::exists(Paths::keyfile()))
        std::cout << "Enter Bifrost password: ";
    else
        std::cout << "Setup Bifrost password: ";

    std::string passwd;
    std::cin >> passwd;

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)passwd.data(), passwd.size(), digest);
    encKey = Bytes(digest, digest + SHA256_DIGEST_LENGTH);
    KeyStore::init(encKey);
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

    Paths::init();
    unlockBifrost();

    std::cout << "\033[2J\033[1;1H" << std::flush;

    std::cout << "Current Keys: " << std::endl;
    auto keys = KeyStore::getAllKeys();
    for (auto key : keys) {
        std::cout << key->commonName << ": \n";
        std::cout << "    fingerprint: ";
        printBytes(std::cout, key->fingerprint);
        std::cout << "\n    SANs: ";
        for (auto s : key->sans)
            std::cout << s << " ";
        std::cout << std::endl;
    }
    std::cout << std::endl;

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
