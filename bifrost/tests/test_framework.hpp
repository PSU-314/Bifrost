// ---------------------------------------------------------------------------
// test_framework.hpp — minimal, dependency-free unit test framework for
// Bifrost's test suite.
//
// This header implements the macro contract already assumed by
// test_keystore.cpp, test_utility.cpp, test_kdf.cpp, and test_totp.cpp:
//
//   REGISTER_TEST("module.behavior.case") {
//       ... test body ...
//   }
//   END_TEST
//
//   EXPECT_TRUE(expr)
//   EXPECT_EQ(actual, expected)
//   EXPECT_BYTES_EQ(actual, expected)      // Bytes / byte-range comparison
//   EXPECT_THROWS_MSG(expr, "substring")   // expr must throw; if substring
//                                          // is non-empty, what() must
//                                          // contain it
//   EXPECT_NO_THROW(expr)
//
//   BIFROST_TEST_MAIN()                    // expands to main(); place once
//                                          // at file scope, after all tests
//
// Design notes:
//   • No external dependencies (no GoogleTest/Catch2) — keeps the build
//     hermetic and fast, matching the "single header" comment already in
//     tests/CMakeLists.txt.
//   • A failed EXPECT_* records the failure and lets the test continue
//     running (soft assertion), matching how test_keystore.cpp chains
//     multiple EXPECT_EQ calls in one test body expecting all of them to be
//     individually reported rather than stopping at the first failure.
//   • Each REGISTER_TEST block becomes a distinct function, registered into
//     a static list at static-init time via a helper struct's constructor —
//     this is what lets BIFROST_TEST_MAIN() discover and run every test
//     with zero manual registration boilerplate.
//   • Exit code: 0 if every test passes, 1 if any test recorded a failure —
//     required for ctest (via add_test) to correctly mark a binary as
//     PASSED/FAILED.
// ---------------------------------------------------------------------------

#ifndef BIFROST_TEST_FRAMEWORK_HPP
#define BIFROST_TEST_FRAMEWORK_HPP

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <functional>
#include <string>
#include <vector>

namespace bifrost_test {

// ---------------------------------------------------------------------------
// Global test registry
// ---------------------------------------------------------------------------

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

// Meyer's-singleton accessor avoids static initialization order fiasco
// between this vector and the TestRegistrar instances defined in each test
// translation unit (each .cpp file's REGISTER_TEST blocks run their static
// constructors independently; order across files is unspecified, but each
// only needs to append to this vector, which works regardless of order).
inline std::vector<TestCase> &registry() {
    static std::vector<TestCase> tests;
    return tests;
}

// Registers a test at static-init time. One instance per REGISTER_TEST call.
struct TestRegistrar {
    TestRegistrar(const std::string &name, std::function<void()> fn) {
        registry().push_back(TestCase{name, std::move(fn)});
    }
};

// ---------------------------------------------------------------------------
// Per-test failure tracking
// ---------------------------------------------------------------------------

// Set to true by any failed EXPECT_* within the currently running test body.
// Reset before each test runs. Kept as a plain global (not thread_local) —
// this framework assumes serial test execution, matching how
// tests/CMakeLists.txt registers each test binary as its own CTest entry
// rather than parallelizing test *cases* within a binary.
inline bool &current_test_failed() {
    static bool failed = false;
    return failed;
}

inline int &total_failures() {
    static int failures = 0;
    return failures;
}

inline void report_failure(const std::string &file, int line,
                           const std::string &message) {
    current_test_failed() = true;
    std::fprintf(stderr, "    FAILED (%s:%d): %s\n", file.c_str(), line,
                message.c_str());
}

} // namespace bifrost_test

// ---------------------------------------------------------------------------
// REGISTER_TEST / END_TEST
// ---------------------------------------------------------------------------
//
// Expands to a free function plus a file-scope TestRegistrar instance whose
// constructor appends {name, function} to the global registry.
//
// __COUNTER__ guarantees a unique function/variable name per invocation even
// when multiple REGISTER_TEST calls appear in the same file, without
// requiring the caller to supply a C++-identifier-safe name (test names use
// dots, e.g. "kdf.hkdf_sha256.rfc5869_test_case_1_basic", which is not a
// valid identifier on its own).

#define BIFROST_TEST_CONCAT_INNER(a, b) a##b
#define BIFROST_TEST_CONCAT(a, b) BIFROST_TEST_CONCAT_INNER(a, b)

// __COUNTER__ increments on every expansion, including multiple references
// within the same macro body — so REGISTER_TEST cannot reference __COUNTER__
// directly more than once (that would produce three different names for
// what must be the same function). Instead, __COUNTER__ is expanded exactly
// once here, captured as `id`, and BIFROST_TEST_IMPL reuses that single
// value for the forward declaration, the registrar, and the definition.
#define REGISTER_TEST(test_name) BIFROST_TEST_IMPL(test_name, __COUNTER__)

#define BIFROST_TEST_IMPL(test_name, id)                                     \
    static void BIFROST_TEST_CONCAT(bifrost_test_fn_, id)();                \
    namespace {                                                              \
    static ::bifrost_test::TestRegistrar BIFROST_TEST_CONCAT(                \
        bifrost_test_registrar_, id)(                                       \
        test_name, BIFROST_TEST_CONCAT(bifrost_test_fn_, id));              \
    }                                                                        \
    static void BIFROST_TEST_CONCAT(bifrost_test_fn_, id)()

#define END_TEST

// ---------------------------------------------------------------------------
// EXPECT_* assertion macros
// ---------------------------------------------------------------------------
// All EXPECT_* macros are "soft" — a failure is recorded and execution
// continues to the next statement in the test body, rather than throwing or
// aborting. This matches test_keystore.cpp's style of chaining several
// EXPECT_EQ calls in a single test and expecting to see every failure
// reported in one run, not just the first.

#define EXPECT_TRUE(expr)                                                    \
    do {                                                                     \
        if (!(expr)) {                                                       \
            ::bifrost_test::report_failure(__FILE__, __LINE__,               \
                                           "EXPECT_TRUE(" #expr ") failed"); \
        }                                                                     \
    } while (0)

#define EXPECT_EQ(actual, expected)                                          \
    do {                                                                     \
        auto bifrost_test_actual_val = (actual);                            \
        auto bifrost_test_expected_val = (expected);                        \
        if (!(bifrost_test_actual_val == bifrost_test_expected_val)) {       \
            ::bifrost_test::report_failure(                                  \
                __FILE__, __LINE__,                                         \
                "EXPECT_EQ(" #actual ", " #expected ") failed");            \
        }                                                                     \
    } while (0)

// Byte-range equality: works for Bytes (std::vector<uint8_t>-like) and any
// container supporting size()/operator[] with comparable element types.
// Reports index-level detail on mismatch (size or first differing byte)
// rather than just "not equal", since a raw hex dump of two 64-byte buffers
// is not useful for spotting a 1-byte KDF/crypto bug by eye.
#define EXPECT_BYTES_EQ(actual, expected)                                    \
    do {                                                                     \
        const auto &bifrost_test_a = (actual);                              \
        const auto &bifrost_test_b = (expected);                            \
        bool bifrost_test_eq = (bifrost_test_a.size() == bifrost_test_b.size()); \
        size_t bifrost_test_diff_idx = 0;                                   \
        if (bifrost_test_eq) {                                              \
            for (size_t bifrost_test_i = 0;                                 \
                bifrost_test_i < bifrost_test_a.size(); ++bifrost_test_i) { \
                if (!(bifrost_test_a[bifrost_test_i] ==                     \
                      bifrost_test_b[bifrost_test_i])) {                    \
                    bifrost_test_eq = false;                                \
                    bifrost_test_diff_idx = bifrost_test_i;                 \
                    break;                                                  \
                }                                                            \
            }                                                                \
        }                                                                    \
        if (!bifrost_test_eq) {                                             \
            char bifrost_test_msg[256];                                    \
            if (bifrost_test_a.size() != bifrost_test_b.size()) {           \
                std::snprintf(bifrost_test_msg, sizeof(bifrost_test_msg),   \
                              "EXPECT_BYTES_EQ(" #actual ", " #expected     \
                              "): size mismatch (%zu vs %zu)",              \
                              bifrost_test_a.size(), bifrost_test_b.size()); \
            } else {                                                        \
                std::snprintf(                                              \
                    bifrost_test_msg, sizeof(bifrost_test_msg),            \
                    "EXPECT_BYTES_EQ(" #actual ", " #expected               \
                    "): differ at index %zu (0x%02x vs 0x%02x)",           \
                    bifrost_test_diff_idx,                                  \
                    static_cast<unsigned>(bifrost_test_a[bifrost_test_diff_idx]), \
                    static_cast<unsigned>(bifrost_test_b[bifrost_test_diff_idx])); \
            }                                                                \
            ::bifrost_test::report_failure(__FILE__, __LINE__,             \
                                           bifrost_test_msg);               \
        }                                                                    \
    } while (0)

// expr must throw an exception derived from std::exception. If msg_substr
// is non-empty, the caught exception's what() must contain it as a
// substring (matching test_keystore.cpp's use, e.g.
// EXPECT_THROWS_MSG(Key::deserialize(serial), "trailing")). Pass "" to
// assert only that *some* exception was thrown, without checking the
// message text.
#define EXPECT_THROWS_MSG(expr, msg_substr)                                  \
    do {                                                                     \
        bool bifrost_test_threw = false;                                    \
        std::string bifrost_test_what;                                     \
        try {                                                                \
            (void)(expr);                                                   \
        } catch (const std::exception &bifrost_test_e) {                   \
            bifrost_test_threw = true;                                     \
            bifrost_test_what = bifrost_test_e.what();                     \
        } catch (...) {                                                     \
            bifrost_test_threw = true;                                     \
        }                                                                    \
        if (!bifrost_test_threw) {                                          \
            ::bifrost_test::report_failure(                                 \
                __FILE__, __LINE__,                                        \
                "EXPECT_THROWS_MSG(" #expr "): expected an exception, "    \
                "none was thrown");                                         \
        } else if (std::string(msg_substr).size() > 0 &&                   \
                  bifrost_test_what.find(msg_substr) == std::string::npos) { \
            char bifrost_test_msg[512];                                    \
            std::snprintf(                                                  \
                bifrost_test_msg, sizeof(bifrost_test_msg),                \
                "EXPECT_THROWS_MSG(" #expr "): exception message \"%s\" "  \
                "does not contain \"%s\"",                                  \
                bifrost_test_what.c_str(),                                  \
                std::string(msg_substr).c_str());                          \
            ::bifrost_test::report_failure(__FILE__, __LINE__,             \
                                           bifrost_test_msg);               \
        }                                                                    \
    } while (0)

// expr must NOT throw. Reports the caught exception's what() on failure so
// a regression is immediately diagnosable from CTest output alone.
#define EXPECT_NO_THROW(expr)                                                \
    do {                                                                     \
        try {                                                                \
            (void)(expr);                                                   \
        } catch (const std::exception &bifrost_test_e) {                   \
            char bifrost_test_msg[512];                                    \
            std::snprintf(bifrost_test_msg, sizeof(bifrost_test_msg),      \
                          "EXPECT_NO_THROW(" #expr "): threw: %s",         \
                          bifrost_test_e.what());                          \
            ::bifrost_test::report_failure(__FILE__, __LINE__,             \
                                           bifrost_test_msg);               \
        } catch (...) {                                                     \
            ::bifrost_test::report_failure(                                 \
                __FILE__, __LINE__,                                        \
                "EXPECT_NO_THROW(" #expr "): threw an unknown exception"); \
        }                                                                    \
    } while (0)

// ---------------------------------------------------------------------------
// BIFROST_TEST_MAIN — runs every registered test, prints a summary, and
// returns a process exit code CTest can act on.
// ---------------------------------------------------------------------------

#define BIFROST_TEST_MAIN()                                                  \
    int main() {                                                             \
        auto &tests = ::bifrost_test::registry();                          \
        int passed = 0;                                                     \
        int failed = 0;                                                     \
        for (const auto &t : tests) {                                       \
            ::bifrost_test::current_test_failed() = false;                 \
            std::printf("[ RUN      ] %s\n", t.name.c_str());              \
            try {                                                            \
                t.fn();                                                     \
            } catch (const std::exception &e) {                            \
                ::bifrost_test::report_failure(                            \
                    "test_framework.hpp", __LINE__,                       \
                    (std::string("uncaught exception escaped test body: ") + \
                     e.what()));                                            \
            } catch (...) {                                                 \
                ::bifrost_test::report_failure(                            \
                    "test_framework.hpp", __LINE__,                       \
                    "uncaught unknown exception escaped test body");       \
            }                                                                \
            if (::bifrost_test::current_test_failed()) {                  \
                std::printf("[  FAILED  ] %s\n", t.name.c_str());          \
                ++failed;                                                   \
            } else {                                                        \
                std::printf("[       OK ] %s\n", t.name.c_str());          \
                ++passed;                                                   \
            }                                                                \
        }                                                                    \
        std::printf("\n[==========] %d test(s) ran.\n",                   \
                    static_cast<int>(tests.size()));                       \
        std::printf("[  PASSED  ] %d test(s).\n", passed);                 \
        if (failed > 0) {                                                   \
            std::printf("[  FAILED  ] %d test(s).\n", failed);             \
        }                                                                    \
        return failed > 0 ? 1 : 0;                                          \
    }

#endif // BIFROST_TEST_FRAMEWORK_HPP
