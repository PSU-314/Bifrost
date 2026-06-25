#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <terminal-launch.hpp>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <unistd.h>
#endif

// ---------------------------------------------------------------------------
// getSelfPath
// ---------------------------------------------------------------------------

std::string getSelfPath() {
#if defined(_WIN32)
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (len == 0 || len == MAX_PATH)
        throw std::runtime_error("getSelfPath: GetModuleFileNameA failed");
    return std::string(buf, len);

#elif defined(__APPLE__)
    char buf[4096];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) != 0)
        throw std::runtime_error(
            "getSelfPath: _NSGetExecutablePath buffer too small");
    return std::string(buf);

#else
    char buf[4096];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len == -1) {
        std::perror("getSelfPath: readlink failed");
        throw std::runtime_error("getSelfPath: readlink failed");
    }
    buf[len] = '\0';
    return std::string(buf);
#endif
}

// ---------------------------------------------------------------------------
// shQuote
// ---------------------------------------------------------------------------

// Single-quote–escape a string for safe embedding inside a POSIX 'sh -c' arg.
// Technique: close the quote, emit \', reopen the quote.
// Example: "it's"  →  'it'\''s'
std::string shQuote(const std::string &s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'')
            out += "'\\''";
        else
            out.push_back(c);
    }
    out += "'";
    return out;
}

// ---------------------------------------------------------------------------
// launchInTerminal
// ---------------------------------------------------------------------------

void launchInTerminal(const std::string &selfPath, int argc, char **argv) {
#if defined(_WIN32)
    // Build:  cmd.exe /K "<selfPath>" --__in_terminal__ "arg1" "arg2" ...
    std::string inner = "\"" + selfPath + "\" " + std::string(SENTINEL_FLAG);
    for (int i = 1; i < argc; ++i)
        inner += " \"" + std::string(argv[i]) + "\"";

    std::string cmdLine = "cmd.exe /K \"" + inner + "\"";

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    if (!CreateProcessA(nullptr, cmdLine.data(), nullptr, nullptr, FALSE,
                        CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
        std::fprintf(stderr, "launchInTerminal: CreateProcess error %lu\n",
                     GetLastError());
        exit(EXIT_FAILURE);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    exit(EXIT_SUCCESS);

#elif defined(__APPLE__)
    // Drive Terminal.app via AppleScript; execlp replaces this process.
    std::string shellCmd = shQuote(selfPath) + " " + std::string(SENTINEL_FLAG);
    for (int i = 1; i < argc; ++i)
        shellCmd += " " + shQuote(argv[i]);

    // Escape backslashes and double-quotes for embedding in an AppleScript
    // double-quoted string literal.
    std::string escaped;
    escaped.reserve(shellCmd.size());
    for (char c : shellCmd) {
        if (c == '\\' || c == '"')
            escaped.push_back('\\');
        escaped.push_back(c);
    }

    std::string osa =
        "tell application \"Terminal\" to do script \"" + escaped + "\"";

    execlp("osascript", "osascript", "-e", osa.c_str(),
           static_cast<char *>(nullptr));
    std::perror("launchInTerminal: exec osascript failed");
    exit(EXIT_FAILURE);

#else
    // Linux / BSD: build a properly-quoted shell command, then try a priority
    // list of terminal emulators, falling back if the first isn't installed.
    std::string innerCmd = shQuote(selfPath) + " " + std::string(SENTINEL_FLAG);
    for (int i = 1; i < argc; ++i)
        innerCmd += " " + shQuote(argv[i]);
    innerCmd += "; exec bash"; // keep the terminal open after the process exits

    // gnome-terminal / terminator use "--" as the separator before the command;
    // all others use "-e".
    static const char *terminals[] = {
        "x-terminal-emulator", "gnome-terminal", "konsole",    "xfce4-terminal",
        "alacritty",           "kitty",          "terminator", "xterm",
    };

    for (const char *term : terminals) {
        bool uses_dash_dash = (std::strcmp(term, "gnome-terminal") == 0 ||
                               std::strcmp(term, "terminator") == 0);
        const char *sep = uses_dash_dash ? "--" : "-e";

        execlp(term, term, sep, "bash", "-c", innerCmd.c_str(),
               static_cast<char *>(nullptr));
        // execlp only returns on failure — try the next candidate.
    }

    std::perror("launchInTerminal: no terminal emulator found");
    exit(EXIT_FAILURE);
#endif
}
