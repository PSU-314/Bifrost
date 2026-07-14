// Re-launches Bifrost inside a visible terminal window on first run (Bifrost
// is a TUI app typically started by double-click / URL handler, not from an
// existing terminal). Provides self-path resolution, POSIX shell quoting,
// and the platform-specific relaunch logic (terminal emulator on Linux,
// Terminal.app via AppleScript on macOS, cmd.exe on Windows).

#pragma once

#include <string>
#include <string_view>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <unistd.h>
#endif

// Checked by main() to detect re-entry after terminal launch.
// Defined as string_view rather than a C-string macro so call sites convert
// it explicitly as needed (e.g. .data() for strcmp, std::string(...) for
// concatenation) and comparisons work without strlen.
inline constexpr std::string_view SENTINEL_FLAG{"--__in_terminal__"};

// Resolve the absolute path of the currently running executable.
// Throws std::runtime_error on failure (platform API error or buffer too
// small).
std::string getSelfPath();

// Single-quote–escape a string for safe embedding inside a POSIX 'sh -c' arg.
// Technique: close quote, emit escaped quote, reopen quote.
std::string shQuote(const std::string &s);

// Re-launch the current process inside a visible terminal window, passing
// SENTINEL_FLAG as argv[1] followed by the original arguments.
// Never returns on success (execlp / CreateProcess + exit).
void launchInTerminal(const std::string &selfPath, int argc, char **argv);
