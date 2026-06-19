#pragma once

#include <string>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <unistd.h>
#endif

const std::string SENTINEL_FLAG = "--__in_terminal__";

// ---------------------------------------------------------------------
// Resolve the path to the currently running executable.
// ---------------------------------------------------------------------
std::string getSelfPath();

// ---------------------------------------------------------------------
// Single-quote-escape a string for safe embedding inside a 'sh -c' arg.
// Standard technique: close quote, insert escaped quote, reopen quote.
// ---------------------------------------------------------------------
std::string shQuote(const std::string &s);

// ---------------------------------------------------------------------
// Launch the current executable inside a visible terminal window,
// re-invoking it with SENTINEL_FLAG + the original argv forwarded.
// ---------------------------------------------------------------------
void launchInTerminal(const std::string &selfPath, int argc, char **argv);
