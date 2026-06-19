#include <HMAC-SHA1.hpp>
#include <KeyStore.hpp>
#include <TypeDefs.hpp>
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
#include <terminal-launch.hpp>
#include <tls.hpp>
#include <totp.hpp>
#include <unistd.h>
#include <utility.hpp>

namespace fs = std::filesystem;

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
        std::string selfPath;
        try {
            selfPath = getSelfPath();
        } catch (const std::exception &e) {
            std::fprintf(stderr, "%s\n", e.what());
            return EXIT_FAILURE;
        }

#if defined(_WIN32)
        launchInTerminal(selfPath, argc, argv);
        return EXIT_SUCCESS;
#else
        pid_t pid = fork();
        if (pid == -1) {
            std::perror("fork failed");
            return EXIT_FAILURE;
        }
        if (pid == 0)
            launchInTerminal(selfPath, argc, argv);
        return EXIT_SUCCESS;
#endif
    }

    Paths::init();
    unlockBifrost();

    std::cout << "\033[2J\033[1;1H" << std::flush;

    std::cout << "Current Keys: " << std::endl;
    auto keys = KeyStore::getAllKeys();
    std::cout << keys.size() << std::endl;
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

    // Bytes fg = hexToBytes(
    //     "1d5b3b8ab3ef69cc680d105be88aec702125b7eba47e58ac630e2277b35be03a");
    // Key k;
    // k.fingerprint = fg;
    // k.commonName = "test2";
    // k.sans.push_back("san3");
    // k.sans.push_back("san4");
    // k.secret = SecureBytes(hexToBytes("a615e4c7ab8ac4530ff1160f138c881b"));
    // KeyStore::store(k);
    // KeyStore::saveStore();
    // return 0;

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
