# ---------------------------------------------------------------------------
# tests/CMakeLists.txt
#
# Professional-grade test integration for Bifrost.
#
# Design decisions:
#   • One binary per tested module (test_utility, test_totp, test_kdf; a
#     test_keystore binary is scaffolded below but not yet enabled).
#     Separate binaries mean:
#       – a crash in one module does not prevent other tests from running,
#       – CTest reports per-module pass/fail clearly,
#       – parallel execution via `ctest -j4` is safe (no shared state).
#   • A single header (test_framework.hpp) provides REGISTER_TEST / EXPECT_*
#     macros with no external dependencies — no FetchContent, no internet
#     access required at CI time.
#   • All test targets inherit the same compiler warnings and hardening flags
#     as the production library, so sanitiser builds catch test-induced bugs.
#   • Sanitiser support (ASAN + UBSAN) is wired through the existing
#     ENABLE_SANITIZERS option — just pass -DENABLE_SANITIZERS=ON.
#   • CTest labels allow selective runs:
#       ctest -L unit          # all unit tests
#       ctest -L kdf           # just KDF tests
#       ctest --rerun-failed   # re-run only failing tests
# ---------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.28)

# ---------------------------------------------------------------------------
# Helper: declare one test binary, link it, register it with CTest.
# ---------------------------------------------------------------------------
function(bifrost_add_test target source_file labels)
    add_executable(${target} ${source_file})

    target_include_directories(${target} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}   # finds test_framework.hpp
    )

    # Link against the library under test.  bifrost::lib already pulls in
    # OpenSSL::Crypto and Threads::Threads transitively.
    target_link_libraries(${target} PRIVATE bifrost::lib)

    # Same hardening and warning flags as production code.
    set_project_warnings(${target})
    set_security_flags(${target})

    # Register with CTest.  The test is named identically to the binary so
    # `ctest -R test_kdf` selects exactly the KDF binary.
    add_test(NAME ${target} COMMAND ${target})

    # A non-zero exit code from the binary is the failure signal.
    set_tests_properties(${target} PROPERTIES
        LABELS               "${labels}"
        TIMEOUT              60          # fail if a test hangs for > 60 s
        FAIL_REGULAR_EXPRESSION "^$"    # empty output is never a reason to fail
    )
endfunction()

# ---------------------------------------------------------------------------
# Test binaries
# ---------------------------------------------------------------------------

# utility.cpp: hex helpers, timeToBytes, writeu32/readu32, readField,
# parseURLParams.  No OpenSSL crypto calls — fastest test to run.
bifrost_add_test(test_utility  test_utility.cpp  "unit;utility")

# totp.cpp: HMAC-SHA256 (RFC 4231 vectors), genSample (RFC 6238 Appendix B,
# SHA256 column), generateOTP (wall-clock integration).
bifrost_add_test(test_totp     test_totp.cpp     "unit;totp")

# KDF.cpp: HKDF-SHA256 (RFC 5869 Appendix A), PBKDF2-SHA256 (RFC 6070).
bifrost_add_test(test_kdf      test_kdf.cpp      "unit;kdf")

# KeyStore.cpp: Key/EncryptedBlob serde, UKID, in-memory mutations,
# AES-256-GCM encrypt/decrypt round-trip.
# bifrost_add_test(test_keystore test_keystore.cpp "unit;keystore")
