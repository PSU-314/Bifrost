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

// ---------------------------------------------------------------------
// Resolve the path to the currently running executable.
// ---------------------------------------------------------------------
std::string getSelfPath() {
#if defined(_WIN32)
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (len == 0 || len == MAX_PATH)
        throw std::runtime_error(
            "GetModuleFileNameA failed to resolve self path");
    return std::string(buf, len);

#elif defined(__APPLE__)
    char buf[4096];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) != 0)
        throw std::runtime_error("_NSGetExecutablePath buffer too small");
    return std::string(buf);

#else
    char buf[4096];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len == -1) {
        std::perror("readlink(/proc/self/exe) failed");
        throw std::runtime_error("readlink failed to resolve self path");
    }
    buf[len] = 0;
    return std::string(buf);
#endif
}

// ---------------------------------------------------------------------
// Single-quote-escape a string for safe embedding inside a 'sh -c' arg.
// Standard technique: close quote, insert escaped quote, reopen quote.
// ---------------------------------------------------------------------
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

// ---------------------------------------------------------------------
// Launch the current executable inside a visible terminal window,
// re-invoking it with SENTINEL_FLAG + the original argv forwarded.
// ---------------------------------------------------------------------
void launchInTerminal(const std::string &selfPath, int argc, char **argv) {
#if defined(_WIN32)
    // Build: cmd /K ""selfPath" --__in_terminal__ "arg1" "arg2" ..."
    std::string inner = "\"" + selfPath + "\" " + SENTINEL_FLAG;
    for (int i = 1; i < argc; i++)
        inner += " \"" + std::string(argv[i]) + "\"";

    std::string cmdLine = "cmd.exe /K \"" + inner + "\"";

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    if (!CreateProcessA(
            nullptr,
            cmdLine.data(), // mutable buffer required by CreateProcessA
            nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &si,
            &pi)) {
        std::fprintf(stderr,
                     "Failed to launch terminal (CreateProcess error %lu)\n",
                     GetLastError());
        exit(EXIT_FAILURE);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    exit(EXIT_SUCCESS);

#elif defined(__APPLE__)
    // Build a properly-quoted shell command, then drive Terminal.app via
    // AppleScript.
    std::string shellCmd = shQuote(selfPath) + " " + SENTINEL_FLAG;
    for (int i = 1; i < argc; i++)
        shellCmd += " " + shQuote(argv[i]);

    // Escape for embedding inside the AppleScript double-quoted string.
    std::string escaped;
    for (char c : shellCmd) {
        if (c == '\\' || c == '"')
            escaped.push_back('\\');
        escaped.push_back(c);
    }

    std::string osa =
        "tell application \"Terminal\" to do script \"" + escaped + "\"";

    execlp("osascript", "osascript", "-e", osa.c_str(), (char *)nullptr);
    std::perror("Failed to exec osascript");
    exit(EXIT_FAILURE);

#else
    // Linux/BSD: properly quote each arg, try a list of terminal emulators
    // in order, falling back if the first choice isn't installed.
    std::string innerCmd = shQuote(selfPath) + " " + SENTINEL_FLAG;
    for (int i = 1; i < argc; i++)
        innerCmd += " " + shQuote(argv[i]);
    innerCmd += "; exec bash";

    static const char *terminals[] = {
        "x-terminal-emulator", "gnome-terminal", "konsole",    "xfce4-terminal",
        "alacritty",           "kitty",          "terminator", "xterm"};

    for (const char *term : terminals) {
        std::string sep = (std::strcmp(term, "gnome-terminal") == 0 ||
                           std::strcmp(term, "terminator") == 0)
                              ? "--"
                              : "-e";

        // Separate argv entries: term, sep, "bash", "-c", innerCmd
        execlp(term, term, sep.c_str(), "bash", "-c", innerCmd.c_str(),
               (char *)nullptr);
        // execlp only returns on failure — try the next terminal
    }

    std::perror("Failed to exec any terminal emulator");
    exit(EXIT_FAILURE);
#endif
}
