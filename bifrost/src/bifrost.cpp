#include <KeyStore.hpp>
#include <TypeDefs.hpp>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <ios>
#include <iostream>
#include <limits>
#include <openssl/sha.h>
#include <securebytes.hpp>
#include <stdexcept>
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

void printProgressBar(float percentage, int totalLen) {
    percentage = std::clamp(percentage, 0.0f, 1.0f);
    std::cout << "[";
    int nFilled = static_cast<int>(percentage * totalLen);
    for (int i = 0; i < nFilled; i++)
        std::cout << "#";
    for (int i = 0; i < totalLen - nFilled; i++)
        std::cout << "-";
    std::cout << "]";
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

    try {
        KeyStore::init(encKey);
    } catch (const std::runtime_error &e) {
        std::cerr << "Incorrect password! KeyStore Decryption failed"
                  << std::endl;
        exit(EXIT_FAILURE);
    }
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
    std::cout << "\n";

    // Bytes fg = hexToBytes(
    //     "1d5b3b8ab3ef69cc680d105be88aec702125b7eba47e58ac630e2277b35be03a");
    // Key k;
    // k.accinfo = "ntronyx";
    // k.fingerprint = fg;
    // k.commonName = "test2";
    // k.sans.push_back("san3");
    // k.sans.push_back("san4");
    // k.secret = SecureBytes(hexToBytes("a615e4c7ab8ac4530ff1160f138c881b"));
    // KeyStore::store(k);
    // KeyStore::saveStore();
    // return 0;

    if (argc > 2) {
        ConnInfo connInfo = getConnInfo(argv[2]);
        std::cout << "Connecting to\nHost: " << connInfo.host
                  << "\nPort: " << connInfo.port << "\n"
                  << std::endl;
        auto key = registerBifrost(connInfo);
        KeyStore::store(key);
        KeyStore::saveStore();
        std::cout << "\n\n Press Enter to continue...";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
    }

    auto keys = KeyStore::getAllKeys();

    while (true) {
        std::cout << "\033[2J\033[1;1H" << std::flush;
        std::cout << "Current Keys: " << std::endl;
        for (auto key : keys) {
            std::cout << "Account: " << key->accinfo << "\n";
            std::cout << "    Server CN: " << key->commonName << "\n";
            std::cout << "    fingerprint: ";
            printBytes(std::cout, key->fingerprint);
            std::cout << "\n    SANs: ";
            for (auto s : key->sans)
                std::cout << s << " ";
            std::cout << std::endl;
            auto [otp, validity] = generateOTP(key->secret);
            std::cout << "    TOTP: " << otp << std::endl;
            std::cout << "    Validity: " << validity << "s\n    ";
            printProgressBar((float)validity / TIME_WINDOW, 30);
            std::cout << std::endl << std::endl;
        }
        std::cout << std::endl;
        usleep(500000);
    }
}
