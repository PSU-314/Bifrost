// Bifrost CLI entry point: relaunches itself in a visible terminal on first
// run, unlocks the KeyStore with a password prompt, optionally registers a
// new key from a bifrost-totp:// URL passed as an argument, then loops
// rendering all stored accounts' live TOTP codes.

#include <KeyStore.hpp>
#include <algorithm>
#include <bifrost.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <securebytes.hpp>
#include <stdexcept>
#include <string>
#include <terminal-launch.hpp>
#include <tls.hpp>
#include <totp.hpp>
#include <unistd.h>
#include <utility.hpp>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

// Render a simple ASCII progress bar of totalLen characters filled to
// percentage (0.0–1.0).
void printProgressBar(float percentage, int totalLen) {
    percentage = std::clamp(percentage, 0.0f, 1.0f);
    int nFilled = static_cast<int>(percentage * static_cast<float>(totalLen));

    std::cout << '[';
    for (int i = 0; i < nFilled; ++i)
        std::cout << '#';
    for (int i = nFilled; i < totalLen; ++i)
        std::cout << '-';
    std::cout << ']';
}

// ---------------------------------------------------------------------------
// Password unlock
// ---------------------------------------------------------------------------

// Prompt for the Bifrost password, derive the key, and load the store.
// On failure the error is printed and the process exits — there is no
// meaningful recovery if we cannot access the key store.
void unlockBifrost() {
    if (fs::exists(Paths::keyfile()))
        std::cout << "Enter Bifrost password: ";
    else
        std::cout << "Setup Bifrost password: ";

    std::string passwd;
    std::cin >> passwd;

    try {
        KeyStore::init(passwd);
    } catch (const std::runtime_error &e) {
        std::cerr << "Incorrect password or corrupted keyfile: " << e.what()
                  << "\n";
        exit(EXIT_FAILURE);
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main(int argc, char **argv) {
    // argv[1] == SENTINEL_FLAG means we were re-launched inside a terminal.
    bool inTerminal =
        (argc > 1 && std::strcmp(argv[1], SENTINEL_FLAG.data()) == 0);

    if (!inTerminal) {
        // First launch (no terminal): fork a child, let it re-exec inside a
        // terminal emulator, and exit the parent immediately.  On Windows we
        // use CreateProcess instead (handled by launchInTerminal).
        std::string selfPath;
        try {
            selfPath = getSelfPath();
        } catch (const std::exception &e) {
            std::cerr << e.what() << std::endl;
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
        // Parent exits; child exec-replaces itself with the terminal emulator.
        return EXIT_SUCCESS;
#endif
    }

    // ── Initialise paths and unlock the key store ───────────────────────────
    Paths::init();
    unlockBifrost();
    std::cout << "\n";

    // ── Optional registration via a bifrost-totp:// URL ─────────────────────
    // argv[1] is SENTINEL_FLAG; the URL is at argv[2] when present.
    if (argc > 2) {
        ConnInfo connInfo = getConnInfo(argv[2]);
        std::cout << "Connecting to\n"
                  << "  Host: " << connInfo.host << "\n"
                  << "  Port: " << connInfo.port << "\n\n";

        Key key = registerBifrost(connInfo);
        KeyStore::store(key);
        KeyStore::saveStore();

        // Pause so the user can read any registration output before the
        // display loop clears the screen.
        std::cout << "\n\nPress Enter to continue...";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
    }

    // ── TOTP display loop ───────────────────────────────────────────────────
    auto keys = KeyStore::getAllKeys();

    while (true) {
        // Clear screen and move cursor to top-left (VT100).
        std::cout << "\033[2J\033[1;1H" << std::flush;
        std::cout << "Current Keys:\n";

        for (const auto *key : keys) {
            std::cout << "Account: " << key->accinfo << "\n";
            std::cout << "  Server CN   : " << key->commonName << "\n";
            std::cout << "  Fingerprint : ";
            printBytes(std::cout, key->fingerprint);
            std::cout << "\n  SANs        :";
            for (const auto &s : key->sans)
                std::cout << " " << s;
            std::cout << "\n";

            auto [otp, validity] = generateOTP(key->secret);
            std::cout << "  TOTP        : " << std::setfill('0')
                      << std::setw(OTP_SIZE) << otp << "\n";
            std::cout << "  Validity    : " << validity << "s  ";
            printProgressBar(static_cast<float>(validity) / TIME_WINDOW, 30);
            std::cout << "\n\n";
        }

        std::cout << std::endl;
        usleep(500'000); // refresh twice per second
    }
}
