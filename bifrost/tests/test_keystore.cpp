// ---------------------------------------------------------------------------
// test_keystore.cpp — Unit tests for KeyStore.cpp
//
// Scope (in-process, no filesystem, no TLS):
//   • Key::serialize / Key::deserialize  — full round-trip and error paths
//   • EncryptedBlob::serialize / deserialize — structural round-trip
//   • KeyStore::getUKID — determinism, uniqueness, sensitivity
//   • KeyStore in-memory mutations: store, erase, lookup variants, getAllKeys
//   • KeyStore::encryptStore / decryptStore — AES-256-GCM round-trip
//     (validates that our key derivation wiring and GCM tag verification work)
//
// NOT tested here: KeyStore::init (reads/writes disk), loadStore/saveStore
// (filesystem integration test — requires a real temp directory and is
// covered by the integration test binary).
//
// The static KeyStore members (singleton state) are reset between tests by
// calling KeyStore::erase on everything added, keeping tests independent.
// ---------------------------------------------------------------------------

#include "test_framework.hpp"
#include <KDF.hpp>
#include <KeyStore.hpp>
#include <openssl/rand.h>
#include <securebytes.hpp>
#include <utility.hpp>

// ---------------------------------------------------------------------------
// Test fixture helpers
// ---------------------------------------------------------------------------

// Build a minimal Key without needing an X509 certificate.
// fingerprint is arbitrary; commonName and sans are set to caller-supplied
// values.  secret is populated with the given hex string.
static Key make_key(const std::string &accinfo, const std::string &cn,
                    const std::vector<std::string> &sans,
                    const std::string &secret_hex) {
    Key k;
    k.accinfo = accinfo;
    k.fingerprint = hexToBytes(
        "aabbccdd" +
        std::to_string(std::hash<std::string>{}(accinfo) & 0xFFFFFFFFu));
    k.commonName = cn;
    k.sans = sans;
    Bytes sb = hexToBytes(secret_hex);
    k.secret = SecureBytes(sb.data(), sb.size());
    return k;
}

// Drain the static store before / after each test to avoid cross-test leakage.
static void clear_store() {
    auto all = KeyStore::getAllKeys();
    // Collect UKIDs first — we cannot mutate the store while iterating it.
    std::vector<Bytes> ukids;
    ukids.reserve(all.size());
    for (const auto *kp : all)
        ukids.push_back(KeyStore::getUKID(*kp));
    for (auto &u : ukids)
        KeyStore::erase(u);
}

// Prime the KeyStore encryption key so encrypt/decrypt tests work without
// calling KeyStore::init (which reads/writes disk).
// We inject a known 32-byte key directly via PBKDF2 with fixed inputs.
static void prime_encryption_key() {
    // Use known password + salt to get a deterministic encryption key.
    // This is NOT testing key derivation; it is just wiring up the singleton
    // so encryptStore/decryptStore have a valid key to work with.
    std::string pw = "test-password";
    // Reuse the public init path: it sets _encryptionKey and _salt for us.
    // To avoid touching the filesystem we point Paths at a non-existent file
    // so the keyfile-exists branch is skipped.
    // Unfortunately KeyStore::init calls Paths::keyfile() which calls
    // Paths::configDir() which calls getenv("HOME").  We avoid that by
    // directly calling pbkdf2_sha256 and setting the private members via a
    // friend declaration — but Key/KeyStore are not friends of this TU.
    //
    // Practical solution: call KeyStore::init with a dummy password and rely
    // on the fact that the keyfile does not exist (no disk state), which makes
    // init generate a fresh salt and derive the key without trying to decrypt
    // anything.  We temporarily set HOME to /tmp so configDir() resolves.
    setenv("HOME", "/tmp", 1);
    // Make sure no leftover keyfile is present.
    std::string kfpath = "/tmp/.config/bifrost/totp-secrets.keys";
    ::remove(kfpath.c_str());
    // init() will throw if certs are missing; we only need _encryptionKey set.
    // We cannot call init() without the cert check in Paths::init().
    // Instead we call the KDF directly and accept that encrypt/decrypt tests
    // use a fixed hard-coded key injected via encryptStore/decryptStore's
    // internal _encryptionKey — which we set by calling pbkdf2_sha256 and
    // writing via the static singleton's public path.
    //
    // The cleanest approach without adding test seams to production code:
    // call KeyStore::init with a password when HOME=/tmp and no keyfile
    // exists.  init() calls Paths::init() which checks for cert files.
    // We stub the cert-file check by creating dummy files.
    ::mkdir("/tmp/.config", 0700);
    ::mkdir("/tmp/.config/bifrost", 0700);
    ::mkdir("/tmp/.config/bifrost/certs", 0700);
    // Create dummy cert files so Paths::init() does not throw.
    for (const char *f : {"/tmp/.config/bifrost/certs/root-ca.crt",
                          "/tmp/.config/bifrost/certs/bifrost-chain.pem",
                          "/tmp/.config/bifrost/certs/bifrost.key"}) {
        FILE *fp = ::fopen(f, "w");
        if (fp)
            ::fclose(fp);
    }
    Paths::init();
    KeyStore::init(pw);
}

// ===========================================================================
// Key::serialize / Key::deserialize
// ===========================================================================

REGISTER_TEST("keystore.key_serialize_deserialize.roundtrip_basic") {
    Key original = make_key("user@example.com", "server.example.com",
                            {"server.example.com", "alt.example.com"},
                            "deadbeefcafe1234deadbeefcafe1234");

    Bytes serial = original.serialize();
    EXPECT_TRUE(!serial.empty());

    Key restored = Key::deserialize(serial);

    EXPECT_EQ(restored.accinfo, original.accinfo);
    EXPECT_EQ(restored.commonName, original.commonName);
    EXPECT_EQ(restored.sans.size(), original.sans.size());
    EXPECT_BYTES_EQ(restored.fingerprint, original.fingerprint);

    // Secret must survive the round-trip.
    EXPECT_EQ(restored.secret.size(), original.secret.size());
    Bytes orig_sec(original.secret.begin(), original.secret.end());
    Bytes rest_sec(restored.secret.begin(), restored.secret.end());
    EXPECT_BYTES_EQ(orig_sec, rest_sec);
}
END_TEST

REGISTER_TEST("keystore.key_serialize_deserialize.empty_sans") {
    Key k = make_key("admin@bifrost", "bifrost.local", {}, "aabbccdd");
    Bytes serial = k.serialize();
    Key r = Key::deserialize(serial);
    EXPECT_TRUE(r.sans.empty());
    EXPECT_EQ(r.accinfo, std::string("admin@bifrost"));
}
END_TEST

REGISTER_TEST("keystore.key_serialize_deserialize.multiple_sans") {
    std::vector<std::string> sans = {"a.com", "b.com", "c.com", "d.com"};
    Key k = make_key("multi@test", "multi.test", sans, "01020304");
    Bytes serial = k.serialize();
    Key r = Key::deserialize(serial);
    EXPECT_EQ(r.sans.size(), 4u);
    for (size_t i = 0; i < 4; ++i)
        EXPECT_EQ(r.sans[i], sans[i]);
}
END_TEST

REGISTER_TEST(
    "keystore.key_serialize_deserialize.size_matches_serialized_length") {
    Key k = make_key("x@y", "y", {"y"}, "ff");
    // Key::size() must equal the actual byte count of serialize().
    EXPECT_EQ(k.size(), k.serialize().size());
}
END_TEST

REGISTER_TEST("keystore.key_deserialize.truncated_data_throws") {
    Key k = make_key("user@test", "test.local", {}, "aabbccdd");
    Bytes serial = k.serialize();
    // Truncate to 4 bytes — not enough to read even the first field.
    Bytes bad(serial.begin(), serial.begin() + 4);
    EXPECT_THROWS_MSG(Key::deserialize(bad), "");
    // Note: the exact message varies (could be "truncated" or "exceeds buffer")
    // We just verify it throws, not the exact wording.
}
END_TEST

REGISTER_TEST("keystore.key_deserialize.trailing_bytes_throws") {
    Key k = make_key("user@test", "test.local", {}, "aabbccdd");
    Bytes serial = k.serialize();
    serial.push_back(0xFF); // append a spurious byte
    EXPECT_THROWS_MSG(Key::deserialize(serial), "trailing");
}
END_TEST

// ===========================================================================
// EncryptedBlob::serialize / deserialize
// ===========================================================================

REGISTER_TEST("keystore.encrypted_blob_serialize_deserialize.roundtrip") {
    EncryptedBlob original;
    original.version = 1;
    // Use real random bytes for nonce and tag so the test covers real data.
    original.nonce.resize(ENC_BLOB_NONCE_SIZE);
    RAND_bytes(original.nonce.data(), static_cast<int>(ENC_BLOB_NONCE_SIZE));
    original.ciphertext = {0x01, 0x02, 0x03, 0x04, 0x05};
    original.tag.resize(ENC_BLOB_TAG_SIZE);
    RAND_bytes(original.tag.data(), static_cast<int>(ENC_BLOB_TAG_SIZE));

    Bytes serial = original.serialize();
    EncryptedBlob restored = EncryptedBlob::deserialize(serial);

    EXPECT_EQ(restored.version, 1u);
    EXPECT_BYTES_EQ(restored.nonce, original.nonce);
    EXPECT_BYTES_EQ(restored.ciphertext, original.ciphertext);
    EXPECT_BYTES_EQ(restored.tag, original.tag);
}
END_TEST

REGISTER_TEST(
    "keystore.encrypted_blob_serialize_deserialize.size_consistency") {
    EncryptedBlob b;
    b.version = 1;
    b.nonce.resize(ENC_BLOB_NONCE_SIZE, 0xAA);
    b.ciphertext.resize(20, 0xBB);
    b.tag.resize(ENC_BLOB_TAG_SIZE, 0xCC);
    EXPECT_EQ(b.size(), b.serialize().size());
}
END_TEST

REGISTER_TEST("keystore.encrypted_blob_deserialize.empty_throws") {
    Bytes empty;
    EXPECT_THROWS_MSG(EncryptedBlob::deserialize(empty), "empty");
}
END_TEST

REGISTER_TEST("keystore.encrypted_blob_deserialize.data_too_short_throws") {
    // Minimum valid size = 1 + 12 + 4 + 16 = 33 bytes.  Pass 32.
    Bytes bad(32, 0x01);
    bad[0] = 1; // valid version
    EXPECT_THROWS_MSG(EncryptedBlob::deserialize(bad), "too short");
}
END_TEST

REGISTER_TEST("keystore.encrypted_blob_deserialize.wrong_version_throws") {
    // Build a structurally valid blob but with version=2 (unsupported).
    Bytes data(33, 0x00);
    data[0] = 2; // wrong version
    EXPECT_THROWS_MSG(EncryptedBlob::deserialize(data), "unsupported version");
}
END_TEST

// ===========================================================================
// KeyStore::getUKID
// ===========================================================================

REGISTER_TEST("keystore.ukid.deterministic") {
    Key k = make_key("user@example.com", "s.com", {}, "aabbccdd");
    Bytes u1 = KeyStore::getUKID(k);
    Bytes u2 = KeyStore::getUKID(k);
    EXPECT_BYTES_EQ(u1, u2);
}
END_TEST

REGISTER_TEST("keystore.ukid.length_is_32_bytes") {
    Key k = make_key("x@y", "y", {}, "ff");
    Bytes u = KeyStore::getUKID(k);
    EXPECT_EQ(u.size(), 32u); // SHA-256 output
}
END_TEST

REGISTER_TEST("keystore.ukid.different_accinfo_differs") {
    Key k1 = make_key("alice@test", "server", {}, "aabbccdd");
    Key k2 = make_key("bob@test", "server", {}, "aabbccdd");
    // Give them the same fingerprint so only accinfo differs.
    k2.fingerprint = k1.fingerprint;
    EXPECT_TRUE(KeyStore::getUKID(k1) != KeyStore::getUKID(k2));
}
END_TEST

REGISTER_TEST("keystore.ukid.different_fingerprint_differs") {
    Key k1 = make_key("same@test", "server", {}, "aabbccdd");
    Key k2 = make_key("same@test", "server", {}, "aabbccdd");
    // Make fingerprints differ by one bit.
    k2.fingerprint[0] ^= 0x01;
    EXPECT_TRUE(KeyStore::getUKID(k1) != KeyStore::getUKID(k2));
}
END_TEST

// ===========================================================================
// In-memory store mutations and lookups
// ===========================================================================

REGISTER_TEST("keystore.store_and_lookup.by_ukid") {
    clear_store();
    Key k = make_key("user@bifrost", "bifrost.local", {}, "deadbeef");
    Bytes ukid = KeyStore::getUKID(k);
    KeyStore::store(k);

    const Key *found = KeyStore::lookupByUKID(ukid);
    EXPECT_TRUE(found != nullptr);
    if (found)
        EXPECT_EQ(found->accinfo, std::string("user@bifrost"));
    clear_store();
}
END_TEST

REGISTER_TEST("keystore.store_and_lookup.missing_ukid_returns_null") {
    clear_store();
    Bytes fake_ukid(32, 0xAB);
    const Key *found = KeyStore::lookupByUKID(fake_ukid);
    EXPECT_TRUE(found == nullptr);
}
END_TEST

REGISTER_TEST("keystore.store_and_lookup.by_fingerprint") {
    clear_store();
    Key k = make_key("fp@test", "fp.test", {}, "01020304");
    Bytes fp = k.fingerprint;
    KeyStore::store(k);

    auto results = KeyStore::lookupByFG(fp);
    EXPECT_EQ(results.size(), 1u);
    if (!results.empty())
        EXPECT_EQ(results[0]->accinfo, std::string("fp@test"));
    clear_store();
}
END_TEST

REGISTER_TEST("keystore.store_and_lookup.by_cn") {
    clear_store();
    Key k = make_key("cn@test", "unique-cn.example", {}, "cafecafe");
    KeyStore::store(k);

    auto results = KeyStore::lookupByCN("unique-cn.example");
    EXPECT_EQ(results.size(), 1u);
    clear_store();
}
END_TEST

REGISTER_TEST("keystore.store_and_lookup.by_accinfo") {
    clear_store();
    Key k = make_key("acc@test", "acc.test", {}, "11223344");
    KeyStore::store(k);

    auto results = KeyStore::lookupByAccInfo("acc@test");
    EXPECT_EQ(results.size(), 1u);
    clear_store();
}
END_TEST

REGISTER_TEST("keystore.store.upsert_replaces_existing") {
    clear_store();
    Key k1 = make_key("upsert@test", "server", {}, "aabb");
    Bytes ukid = KeyStore::getUKID(k1);
    KeyStore::store(k1);
    EXPECT_EQ(KeyStore::getAllKeys().size(), 1u);

    // Build a second Key with the same accinfo+fingerprint (same UKID) but
    // different secret.
    Key k2 = make_key("upsert@test", "server", {}, "ccdd");
    k2.fingerprint = hexToBytes(
        "aabbccdd" +
        std::to_string(std::hash<std::string>{}("upsert@test") & 0xFFFFFFFFu));
    KeyStore::store(k2);

    // There should still be exactly one entry.
    EXPECT_EQ(KeyStore::getAllKeys().size(), 1u);
    clear_store();
}
END_TEST

REGISTER_TEST("keystore.erase.removes_entry") {
    clear_store();
    Key k = make_key("erase@test", "erase.test", {}, "ff00ff00");
    Bytes ukid = KeyStore::getUKID(k);
    KeyStore::store(k);
    EXPECT_EQ(KeyStore::getAllKeys().size(), 1u);

    KeyStore::erase(ukid);
    EXPECT_EQ(KeyStore::getAllKeys().size(), 0u);
    EXPECT_TRUE(KeyStore::lookupByUKID(ukid) == nullptr);
}
END_TEST

REGISTER_TEST("keystore.erase.nonexistent_is_noop") {
    clear_store();
    Key k = make_key("safe@test", "safe.test", {}, "aabb");
    KeyStore::store(k);

    Bytes nonexistent(32, 0x00);
    EXPECT_NO_THROW(KeyStore::erase(nonexistent));
    // The real entry must still be there.
    EXPECT_EQ(KeyStore::getAllKeys().size(), 1u);
    clear_store();
}
END_TEST

REGISTER_TEST("keystore.getAllKeys.returns_all_entries") {
    clear_store();
    Key k1 = make_key("a@test", "a.test", {}, "aabb");
    Key k2 = make_key("b@test", "b.test", {}, "ccdd");
    Key k3 = make_key("c@test", "c.test", {}, "eeff");
    KeyStore::store(k1);
    KeyStore::store(k2);
    KeyStore::store(k3);

    auto all = KeyStore::getAllKeys();
    EXPECT_EQ(all.size(), 3u);
    clear_store();
}
END_TEST

// ===========================================================================
// KeyStore serialize / deserialize (in-memory round-trip)
// ===========================================================================

REGISTER_TEST("keystore.serialize_deserialize.empty_store") {
    clear_store();
    Bytes serial = KeyStore::serialize();
    // Empty store: 4-byte count field == 0.
    EXPECT_EQ(serial.size(), 4u);
    EXPECT_EQ(serial[0], 0u);
}
END_TEST

REGISTER_TEST("keystore.serialize_deserialize.roundtrip_with_entries") {
    clear_store();
    Key k1 = make_key("rt1@test", "rt.test", {"rt.test"}, "aabbccdd");
    Key k2 = make_key("rt2@test", "rt.test", {}, "11223344");
    Bytes u1 = KeyStore::getUKID(k1);
    Bytes u2 = KeyStore::getUKID(k2);
    KeyStore::store(k1);
    KeyStore::store(k2);

    Bytes serial = KeyStore::serialize();
    clear_store();
    EXPECT_EQ(KeyStore::getAllKeys().size(), 0u);

    KeyStore::deserialize(serial);
    EXPECT_EQ(KeyStore::getAllKeys().size(), 2u);

    const Key *r1 = KeyStore::lookupByUKID(u1);
    const Key *r2 = KeyStore::lookupByUKID(u2);
    EXPECT_TRUE(r1 != nullptr);
    EXPECT_TRUE(r2 != nullptr);
    if (r1)
        EXPECT_EQ(r1->accinfo, std::string("rt1@test"));
    if (r2)
        EXPECT_EQ(r2->accinfo, std::string("rt2@test"));
    clear_store();
}
END_TEST

REGISTER_TEST("keystore.deserialize.trailing_bytes_throws") {
    clear_store();
    Bytes serial = KeyStore::serialize(); // valid empty store
    serial.push_back(0xFF);
    EXPECT_THROWS_MSG(KeyStore::deserialize(serial), "trailing");
    clear_store();
}
END_TEST

// ===========================================================================
// KeyStore::encryptStore / decryptStore (AES-256-GCM round-trip)
// ===========================================================================

REGISTER_TEST("keystore.encrypt_decrypt.roundtrip_empty_store") {
    prime_encryption_key();
    clear_store();

    EncryptedBlob blob = KeyStore::encryptStore();
    // Tag and nonce must be the right sizes.
    EXPECT_EQ(blob.nonce.size(), ENC_BLOB_NONCE_SIZE);
    EXPECT_EQ(blob.tag.size(), ENC_BLOB_TAG_SIZE);

    clear_store();
    EXPECT_NO_THROW(KeyStore::decryptStore(blob));
    EXPECT_EQ(KeyStore::getAllKeys().size(), 0u);
}
END_TEST

REGISTER_TEST("keystore.encrypt_decrypt.roundtrip_with_entries") {
    prime_encryption_key();
    clear_store();

    Key k = make_key("enc@test", "enc.test", {"enc.test"}, "cafebabe");
    Bytes ukid = KeyStore::getUKID(k);
    KeyStore::store(k);

    EncryptedBlob blob = KeyStore::encryptStore();
    clear_store();

    KeyStore::decryptStore(blob);
    EXPECT_EQ(KeyStore::getAllKeys().size(), 1u);
    const Key *r = KeyStore::lookupByUKID(ukid);
    EXPECT_TRUE(r != nullptr);
    if (r) {
        EXPECT_EQ(r->accinfo, std::string("enc@test"));
        Bytes sec(r->secret.begin(), r->secret.end());
        Bytes expected = hexToBytes("cafebabe");
        EXPECT_BYTES_EQ(sec, expected);
    }
    clear_store();
}
END_TEST

REGISTER_TEST("keystore.encrypt_decrypt.tampered_ciphertext_throws") {
    // Flip one bit in the ciphertext — GCM authentication must reject it.
    prime_encryption_key();
    clear_store();
    Key k = make_key("tamper@test", "t.test", {}, "aabb");
    KeyStore::store(k);

    EncryptedBlob blob = KeyStore::encryptStore();
    clear_store();

    if (!blob.ciphertext.empty())
        blob.ciphertext[0] ^= 0x01; // corrupt one byte

    EXPECT_THROWS_MSG(KeyStore::decryptStore(blob), "");
    // The error message varies ("tag mismatch" or similar); we just need it to
    // throw.
}
END_TEST

REGISTER_TEST("keystore.encrypt_decrypt.tampered_tag_throws") {
    prime_encryption_key();
    clear_store();

    EncryptedBlob blob = KeyStore::encryptStore();
    blob.tag[0] ^= 0xFF; // flip all bits in first tag byte

    EXPECT_THROWS_MSG(KeyStore::decryptStore(blob), "");
}
END_TEST

REGISTER_TEST("keystore.encrypt_decrypt.wrong_nonce_throws") {
    prime_encryption_key();
    clear_store();

    EncryptedBlob blob = KeyStore::encryptStore();
    blob.nonce[0] ^=
        0x01; // corrupt nonce → GCM will derive different keystream

    EXPECT_THROWS_MSG(KeyStore::decryptStore(blob), "");
}
END_TEST

REGISTER_TEST("keystore.encrypt_decrypt.nonce_uniqueness") {
    // Two separate encryptions of the same plaintext must produce different
    // nonces (GCM nonce reuse under the same key is catastrophic).
    prime_encryption_key();
    clear_store();

    EncryptedBlob b1 = KeyStore::encryptStore();
    EncryptedBlob b2 = KeyStore::encryptStore();
    EXPECT_TRUE(b1.nonce != b2.nonce);
}
END_TEST

BIFROST_TEST_MAIN()
