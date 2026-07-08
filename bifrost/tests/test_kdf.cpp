// ---------------------------------------------------------------------------
// test_kdf.cpp — Unit tests for KDF.cpp
//
// Scope:
//   • hkdf_sha256   — RFC 5869 Appendix A official test vectors (A.1-A.3)
//   • pbkdf2_sha256 — RFC 6070 vectors are defined for PBKDF2-HMAC-SHA1, NOT
//                     SHA256, so they cannot be reused here (see note below).
//                     Instead we test against the KeyStore-mandated iteration
//                     count, output length, determinism, and sensitivity to
//                     each input, which are the properties Bifrost actually
//                     depends on.
//
// Why RFC vectors matter more here than in most modules: HKDF and PBKDF2 are
// the two functions standing between a user's password / mTLS exporter
// secret and the derived TOTP key. A subtly wrong implementation (e.g. HMAC
// key/message swapped, salt and IKM swapped, wrong hash length) will not
// crash and will not look wrong in casual testing — it will just silently
// produce a different, deterministic, wrong key. Testing against numbers
// published by a third party (not derived from our own code) is the only way
// to catch that class of bug.
//
// NOT tested here: KeyStore's use of these functions (PBKDF2_N_ITERATIONS,
// integration with KeyStore's encryption key derivation) — that belongs to
// test_keystore.cpp / the integration test binary, not this module-level
// suite.
// ---------------------------------------------------------------------------

#include "test_framework.hpp"
#include <KDF.hpp>
#include <securebytes.hpp>
#include <utility.hpp>

// Small helper: build a SecureBytes from a hex string, since SecureBytes is
// non-copyable and test vectors are most naturally expressed as hex.
static SecureBytes secureFromHex(const std::string &hex) {
    Bytes b = hexToBytes(hex);
    return SecureBytes(b.data(), b.size());
}

// Small helper: build a Bytes (plain, copyable) from a hex string — used for
// the "info" parameter of hkdf_sha256, which is typed as Bytes, not
// SecureBytes.
static Bytes bytesFromHex(const std::string &hex) { return hexToBytes(hex); }

// ===========================================================================
// hkdf_sha256 — RFC 5869 Appendix A test vectors
// ===========================================================================

REGISTER_TEST("kdf.hkdf_sha256.rfc5869_test_case_1_basic") {
    // RFC 5869 A.1: Basic test case with SHA-256.
    // IKM  = 0x0b repeated 22 times
    // salt = 000102030405060708090a0b0c
    // info = f0f1f2f3f4f5f6f7f8f9
    // L    = 42
    // Expected OKM (first 42 bytes) =
    //   3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
    SecureBytes ikm =
        secureFromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    SecureBytes salt = secureFromHex("000102030405060708090a0b0c");
    Bytes info = bytesFromHex("f0f1f2f3f4f5f6f7f8f9");

    SecureBytes okm;
    hkdf_sha256(ikm, salt, info, 42, okm);

    Bytes result(okm.begin(), okm.end());
    Bytes expected = hexToBytes(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5b"
        "f34007208d5b887185865");
    EXPECT_BYTES_EQ(result, expected);
}
END_TEST

REGISTER_TEST("kdf.hkdf_sha256.rfc5869_test_case_2_longer_inputs") {
    // RFC 5869 A.2: Test with SHA-256 and longer inputs/outputs (L = 82).
    // Using longer IKM (80 octets), salt (80 octets), info (80 octets).
    SecureBytes ikm = secureFromHex("000102030405060708090a0b0c0d0e0f"
                                    "101112131415161718191a1b1c1d1e1f"
                                    "202122232425262728292a2b2c2d2e2f"
                                    "303132333435363738393a3b3c3d3e3f"
                                    "404142434445464748494a4b4c4d4e4f");
    SecureBytes salt = secureFromHex("606162636465666768696a6b6c6d6e6f"
                                     "707172737475767778797a7b7c7d7e7f"
                                     "808182838485868788898a8b8c8d8e8f"
                                     "909192939495969798999a9b9c9d9e9f"
                                     "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    Bytes info = bytesFromHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                              "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                              "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                              "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                              "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    SecureBytes okm;
    hkdf_sha256(ikm, salt, info, 82, okm);

    Bytes result(okm.begin(), okm.end());
    Bytes expected = hexToBytes("b11e398dc80327a1c8e7f78c596a4934"
                                "4f012eda2d4efad8a050cc4c19afa97c"
                                "59045a99cac7827271cb41c65e590e09"
                                "da3275600c2f09b8367793a9aca3db71"
                                "cc30c58179ec3e87c14c01d5c1f3434f1d87");
    EXPECT_BYTES_EQ(result, expected);
}
END_TEST

REGISTER_TEST("kdf.hkdf_sha256.rfc5869_test_case_3_zero_length_salt_and_info") {
    // RFC 5869 A.3: Test with SHA-256 and zero-length salt/info.
    // Confirms empty SecureBytes/Bytes are handled correctly rather than
    // crashing or defaulting to some other behavior — HKDF's spec requires
    // an empty salt to be treated as a string of HashLen zero bytes.
    SecureBytes ikm =
        secureFromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    SecureBytes salt; // zero-length
    Bytes info;       // zero-length

    SecureBytes okm;
    hkdf_sha256(ikm, salt, info, 42, okm);

    Bytes result(okm.begin(), okm.end());
    Bytes expected = hexToBytes(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2"
        "d9d201395faa4b61a96c8");
    EXPECT_BYTES_EQ(result, expected);
}
END_TEST

REGISTER_TEST("kdf.hkdf_sha256.output_length_matches_requested") {
    SecureBytes ikm = secureFromHex("aabbccdd");
    SecureBytes salt = secureFromHex("1122");
    Bytes info = bytesFromHex("33");

    SecureBytes okm16, okm32, okm64;
    hkdf_sha256(ikm, salt, info, 16, okm16);
    hkdf_sha256(ikm, salt, info, 32, okm32);
    hkdf_sha256(ikm, salt, info, 64, okm64);

    EXPECT_EQ(okm16.size(), 16u);
    EXPECT_EQ(okm32.size(), 32u);
    EXPECT_EQ(okm64.size(), 64u);
}
END_TEST

REGISTER_TEST("kdf.hkdf_sha256.different_info_yields_different_output") {
    // The "info" parameter is Bifrost's binding of the derived key to the
    // mTLS exporter context — if two different info strings produced the
    // same output, that binding would be worthless.
    SecureBytes ikm = secureFromHex("000112233445566778899aabbccddeeff0");
    SecureBytes salt = secureFromHex("0102030405");

    SecureBytes okmA, okmB;
    hkdf_sha256(ikm, salt, bytesFromHex("aa"), 32, okmA);
    hkdf_sha256(ikm, salt, bytesFromHex("bb"), 32, okmB);

    Bytes a(okmA.begin(), okmA.end());
    Bytes b(okmB.begin(), okmB.end());
    EXPECT_TRUE(a != b);
}
END_TEST

REGISTER_TEST("kdf.hkdf_sha256.deterministic_for_same_inputs") {
    SecureBytes ikm = secureFromHex("deadbeef");
    SecureBytes salt = secureFromHex("cafe");
    Bytes info = bytesFromHex("beef");

    SecureBytes okm1, okm2;
    hkdf_sha256(ikm, salt, info, 32, okm1);
    hkdf_sha256(ikm, salt, info, 32, okm2);

    Bytes a(okm1.begin(), okm1.end());
    Bytes b(okm2.begin(), okm2.end());
    EXPECT_BYTES_EQ(a, b);
}
END_TEST

// ===========================================================================
// pbkdf2_sha256
//
// NOTE ON TEST VECTORS: RFC 6070's published vectors are for
// PBKDF2-HMAC-SHA1, not SHA256 — they cannot be used to validate a SHA256
// instantiation. There is no equivalent widely-cited RFC for PBKDF2-SHA256
// specifically; the closest authoritative source is NIST/community vector
// sets (e.g. those embedded in Python's hashlib test suite or RFC 7914's
// Appendix, which target scrypt, not PBKDF2-SHA256 directly).
//
// Rather than hard-code an unverified "known-good" hex string here — which
// would give false confidence if the constant were ever wrong — these tests
// check the properties that Bifrost's security actually depends on:
// determinism, sensitivity to every input, and fixed output length. If you
// later want vector-level certainty, generate a reference value with a
// separate, trusted implementation (e.g. `python3 -c "import hashlib;
// print(hashlib.pbkdf2_hmac('sha256', b'password', b'salt',
// 600000).hex())"`) and hard-code that as an additional regression test.
// ===========================================================================

REGISTER_TEST("kdf.pbkdf2_sha256.output_is_32_bytes") {
    // include/KDF.hpp documents: "derived — output buffer; resized to
    // SHA256_DIGEST_LENGTH (32) bytes." — this is a stated contract, so it's
    // worth asserting directly.
    SecureBytes password = secureFromHex("70617373776f7264"); // "password"
    SecureBytes salt = secureFromHex("73616c74");             // "salt"

    SecureBytes derived;
    pbkdf2_sha256(password, salt, 1000, derived);

    EXPECT_EQ(derived.size(), 32u);
}
END_TEST

REGISTER_TEST("kdf.pbkdf2_sha256.deterministic_for_same_inputs") {
    SecureBytes password = secureFromHex("70617373776f7264");
    SecureBytes salt = secureFromHex("73616c74");

    SecureBytes d1, d2;
    pbkdf2_sha256(password, salt, 1000, d1);
    pbkdf2_sha256(password, salt, 1000, d2);

    Bytes a(d1.begin(), d1.end());
    Bytes b(d2.begin(), d2.end());
    EXPECT_BYTES_EQ(a, b);
}
END_TEST

REGISTER_TEST("kdf.pbkdf2_sha256.different_password_yields_different_key") {
    SecureBytes salt = secureFromHex("73616c74");
    SecureBytes d1, d2;
    pbkdf2_sha256(secureFromHex("70617373776f726431"), salt, 1000,
                  d1); // "password1"
    pbkdf2_sha256(secureFromHex("70617373776f726432"), salt, 1000,
                  d2); // "password2"

    Bytes a(d1.begin(), d1.end());
    Bytes b(d2.begin(), d2.end());
    EXPECT_TRUE(a != b);
}
END_TEST

REGISTER_TEST("kdf.pbkdf2_sha256.different_salt_yields_different_key") {
    // This is the property that makes rainbow-table attacks impractical —
    // worth testing explicitly, not just assuming OpenSSL gets it right.
    SecureBytes password = secureFromHex("70617373776f7264");
    SecureBytes d1, d2;
    pbkdf2_sha256(password, secureFromHex("73616c7431"), 1000, d1); // salt1
    pbkdf2_sha256(password, secureFromHex("73616c7432"), 1000, d2); // salt2

    Bytes a(d1.begin(), d1.end());
    Bytes b(d2.begin(), d2.end());
    EXPECT_TRUE(a != b);
}
END_TEST

REGISTER_TEST(
    "kdf.pbkdf2_sha256.different_iteration_count_yields_different_key") {
    SecureBytes password = secureFromHex("70617373776f7264");
    SecureBytes salt = secureFromHex("73616c74");
    SecureBytes d1, d2;
    pbkdf2_sha256(password, salt, 1000, d1);
    pbkdf2_sha256(password, salt, 2000, d2);

    Bytes a(d1.begin(), d1.end());
    Bytes b(d2.begin(), d2.end());
    EXPECT_TRUE(a != b);
}
END_TEST

REGISTER_TEST("kdf.pbkdf2_sha256.empty_password_does_not_throw") {
    // An empty password is a legitimate (if weak) input; the KDF itself
    // should not crash or throw on it — validation of "is this a good
    // password" belongs to a higher layer, not the primitive.
    SecureBytes password; // empty
    SecureBytes salt = secureFromHex("73616c74");
    SecureBytes derived;
    EXPECT_NO_THROW(pbkdf2_sha256(password, salt, 1000, derived));
    EXPECT_EQ(derived.size(), 32u);
}
END_TEST

REGISTER_TEST("kdf.pbkdf2_sha256.production_iteration_count_completes") {
    // Sanity check at the actual iteration count Bifrost uses in production
    // (KeyStore.hpp: PBKDF2_N_ITERATIONS = 600'000, the OWASP 2023
    // recommendation). This mainly guards against a regression that makes
    // the function hang or throw at realistic cost — timing/performance is
    // NOT asserted here (that would make the test flaky across machines);
    // the 60s CTest TIMEOUT set in tests/CMakeLists.txt is the backstop.
    SecureBytes password = secureFromHex("70617373776f7264");
    SecureBytes salt = secureFromHex("73616c74");
    SecureBytes derived;
    EXPECT_NO_THROW(pbkdf2_sha256(password, salt, 600000, derived));
    EXPECT_EQ(derived.size(), 32u);
}
END_TEST

BIFROST_TEST_MAIN()
