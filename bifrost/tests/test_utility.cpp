// ---------------------------------------------------------------------------
// test_utility.cpp — Unit tests for utility.cpp
//
// Scope (pure functions, no OpenSSL, no filesystem, no network):
//   • hexNibble          — single hex-character decode, valid + invalid input
//   • hexToBytes / bytesToHex — round-trip and known-vector checks
//   • writeu32 / readu32 — little-endian 32-bit encode/decode, boundary values
//   • readField          — length-prefixed field reader used by (de)serialise
//   • timeToBytes        — big-endian 8-byte counter encoding (RFC 6238 style)
//   • parseURLParams     — query-string parsing, delimiters, edge cases
//
// NOT tested here: writeAtomic / readAtomic (filesystem integration test —
// requires a real temp directory and is covered by the integration test
// binary, matching the convention set in test_keystore.cpp for KeyStore::init
// and loadStore/saveStore).
//
// This file follows the same structure as test_keystore.cpp: one
// REGISTER_TEST block per behavior, named "module.function.case", with no
// shared mutable state between tests (all functions here are pure, so no
// clear_store()-style fixture is needed).
// ---------------------------------------------------------------------------

#include "test_framework.hpp"
#include <utility.hpp>

// ===========================================================================
// hexNibble
// ===========================================================================

REGISTER_TEST("utility.hexNibble.decimal_digits") {
    EXPECT_EQ(hexNibble('0'), 0);
    EXPECT_EQ(hexNibble('5'), 5);
    EXPECT_EQ(hexNibble('9'), 9);
}
END_TEST

REGISTER_TEST("utility.hexNibble.lowercase_letters") {
    EXPECT_EQ(hexNibble('a'), 10);
    EXPECT_EQ(hexNibble('f'), 15);
}
END_TEST

REGISTER_TEST("utility.hexNibble.uppercase_letters") {
    EXPECT_EQ(hexNibble('A'), 10);
    EXPECT_EQ(hexNibble('F'), 15);
}
END_TEST

REGISTER_TEST("utility.hexNibble.invalid_char_returns_negative") {
    // 'g' is not a hex digit; the function should signal failure rather than
    // silently returning a plausible-looking value.
    EXPECT_TRUE(hexNibble('g') < 0);
    EXPECT_TRUE(hexNibble('!') < 0);
    EXPECT_TRUE(hexNibble(' ') < 0);
}
END_TEST

// ===========================================================================
// hexToBytes / bytesToHex
// ===========================================================================

REGISTER_TEST("utility.hexToBytes.known_vector") {
    Bytes b = hexToBytes("deadbeef");
    Bytes expected = {0xde, 0xad, 0xbe, 0xef};
    EXPECT_BYTES_EQ(b, expected);
}
END_TEST

REGISTER_TEST("utility.hexToBytes.empty_string") {
    Bytes b = hexToBytes("");
    EXPECT_TRUE(b.empty());
}
END_TEST

REGISTER_TEST("utility.hexToBytes.uppercase_and_lowercase_mixed") {
    Bytes lower = hexToBytes("aabbcc");
    Bytes upper = hexToBytes("AABBCC");
    Bytes mixed = hexToBytes("AaBbCc");
    EXPECT_BYTES_EQ(lower, upper);
    EXPECT_BYTES_EQ(lower, mixed);
}
END_TEST

REGISTER_TEST("utility.bytesToHex.known_vector") {
    Bytes b = {0xde, 0xad, 0xbe, 0xef};
    EXPECT_EQ(bytesToHex(b), std::string("deadbeef"));
}
END_TEST

REGISTER_TEST("utility.hexToBytes_bytesToHex.roundtrip") {
    // Round-trip through both directions for a value that exercises every
    // nibble 0x0-0xF at least once.
    std::string original = "0123456789abcdef";
    Bytes b = hexToBytes(original);
    std::string back = bytesToHex(b);
    EXPECT_EQ(back, original);
}
END_TEST

REGISTER_TEST("utility.bytesToHex.empty_bytes") {
    Bytes b;
    EXPECT_EQ(bytesToHex(b), std::string(""));
}
END_TEST

REGISTER_TEST("utility.hexToBytes.strips_0x_prefix") {
    // Confirmed in utility.cpp: an optional "0x"/"0X" prefix is stripped
    // before decoding. Worth testing directly since it's an easy thing to
    // silently break (e.g. if someone "simplifies" the function later) with
    // no compiler warning to catch it.
    Bytes withPrefix = hexToBytes("0xdeadbeef");
    Bytes withoutPrefix = hexToBytes("deadbeef");
    EXPECT_BYTES_EQ(withPrefix, withoutPrefix);
}
END_TEST

REGISTER_TEST("utility.hexToBytes.strips_uppercase_0X_prefix") {
    Bytes withPrefix = hexToBytes("0XDEADBEEF");
    Bytes expected = {0xde, 0xad, 0xbe, 0xef};
    EXPECT_BYTES_EQ(withPrefix, expected);
}
END_TEST

REGISTER_TEST("utility.hexToBytes.odd_length_throws") {
    // Confirmed in utility.cpp: hex.size() % 2 != 0 throws explicitly rather
    // than silently truncating or padding the last nibble.
    EXPECT_THROWS_MSG(hexToBytes("abc"), "");
}
END_TEST

REGISTER_TEST("utility.hexToBytes.invalid_character_throws") {
    EXPECT_THROWS_MSG(hexToBytes("zz"), "");
}
END_TEST

// ===========================================================================
// writeu32 / readu32  (little-endian, per KeyStore serialisation format)
// ===========================================================================

REGISTER_TEST("utility.writeu32_readu32.roundtrip_zero") {
    Bytes out;
    writeu32(out, 0u);
    EXPECT_EQ(out.size(), 4u);
    EXPECT_EQ(readu32(out.data()), 0u);
}
END_TEST

REGISTER_TEST("utility.writeu32_readu32.roundtrip_max") {
    Bytes out;
    writeu32(out, 0xFFFFFFFFu);
    EXPECT_EQ(readu32(out.data()), 0xFFFFFFFFu);
}
END_TEST

REGISTER_TEST("utility.writeu32_readu32.roundtrip_arbitrary") {
    Bytes out;
    writeu32(out, 0x12345678u);
    EXPECT_EQ(readu32(out.data()), 0x12345678u);
}
END_TEST

REGISTER_TEST("utility.writeu32.little_endian_byte_order") {
    // Pin down the wire format explicitly: least-significant byte first.
    // This is a deliberate format guarantee (KeyStore's on-disk layout
    // depends on it), so the byte order itself is worth asserting, not just
    // the round-trip.
    Bytes out;
    writeu32(out, 0x12345678u);
    Bytes expected = {0x78, 0x56, 0x34, 0x12};
    EXPECT_BYTES_EQ(out, expected);
}
END_TEST

REGISTER_TEST("utility.writeu32.appends_without_clearing") {
    // writeu32 takes Bytes& out and should append, not overwrite — callers
    // build up serialized records by calling it multiple times.
    Bytes out = {0xAA};
    writeu32(out, 1u);
    EXPECT_EQ(out.size(), 5u);
    EXPECT_EQ(out[0], 0xAAu);
}
END_TEST

// ===========================================================================
// readField — length-prefixed field reader
// ===========================================================================

REGISTER_TEST("utility.readField.basic_extraction") {
    // Build a manual [u32 length][payload] record.
    Bytes data;
    writeu32(data, 3u);
    data.push_back('a');
    data.push_back('b');
    data.push_back('c');

    size_t offset = 0;
    Bytes field = readField(data, offset);

    Bytes expected = {'a', 'b', 'c'};
    EXPECT_BYTES_EQ(field, expected);
    // offset must advance past the 4-byte length prefix AND the payload.
    EXPECT_EQ(offset, 7u);
}
END_TEST

REGISTER_TEST("utility.readField.empty_field") {
    Bytes data;
    writeu32(data, 0u);

    size_t offset = 0;
    Bytes field = readField(data, offset);

    EXPECT_TRUE(field.empty());
    EXPECT_EQ(offset, 4u);
}
END_TEST

REGISTER_TEST("utility.readField.advances_offset_for_sequential_reads") {
    // Two fields back-to-back; offset must be threaded through correctly so
    // the second readField call picks up exactly where the first left off.
    Bytes data;
    writeu32(data, 2u);
    data.push_back('h');
    data.push_back('i');
    writeu32(data, 3u);
    data.push_back('b');
    data.push_back('y');
    data.push_back('e');

    size_t offset = 0;
    Bytes first = readField(data, offset);
    Bytes second = readField(data, offset);

    Bytes expectedFirst = {'h', 'i'};
    Bytes expectedSecond = {'b', 'y', 'e'};
    EXPECT_BYTES_EQ(first, expectedFirst);
    EXPECT_BYTES_EQ(second, expectedSecond);
    EXPECT_EQ(offset, data.size());
}
END_TEST

REGISTER_TEST("utility.readField.truncated_length_prefix_throws") {
    // Fewer than 4 bytes available — not even enough for the length prefix.
    Bytes data = {0x01, 0x02};
    size_t offset = 0;
    EXPECT_THROWS_MSG(readField(data, offset), "");
}
END_TEST

REGISTER_TEST("utility.readField.length_exceeds_buffer_throws") {
    // Length prefix claims more payload bytes than actually follow.
    Bytes data;
    writeu32(data, 100u); // claims 100 bytes of payload
    data.push_back('x');  // only 1 byte actually present

    size_t offset = 0;
    EXPECT_THROWS_MSG(readField(data, offset), "");
}
END_TEST

// ===========================================================================
// timeToBytes — big-endian 8-byte counter (RFC 6238 / HOTP wire format)
// ===========================================================================

REGISTER_TEST("utility.timeToBytes.size_is_eight_bytes") {
    Bytes b = timeToBytes(static_cast<std::time_t>(59));
    EXPECT_EQ(b.size(), 8u);
}
END_TEST

REGISTER_TEST("utility.timeToBytes.zero") {
    Bytes b = timeToBytes(static_cast<std::time_t>(0));
    Bytes expected = {0, 0, 0, 0, 0, 0, 0, 0};
    EXPECT_BYTES_EQ(b, expected);
}
END_TEST

REGISTER_TEST("utility.timeToBytes.rfc6238_known_value") {
    // RFC 6238 Appendix B uses T = 1 (i.e. time step counter value 1) as its
    // first test vector's derived counter. The 8-byte big-endian encoding of
    // 1 is 00 00 00 00 00 00 00 01 — this pins down byte order, which
    // genSample()/generateOTP() depend on for correct HMAC input.
    Bytes b = timeToBytes(static_cast<std::time_t>(1));
    Bytes expected = {0, 0, 0, 0, 0, 0, 0, 1};
    EXPECT_BYTES_EQ(b, expected);
}
END_TEST

REGISTER_TEST("utility.timeToBytes.big_endian_byte_order") {
    // 0x0000000000000100 = 256. Big-endian means the 0x01 byte lands second
    // from the end, not first.
    Bytes b = timeToBytes(static_cast<std::time_t>(256));
    Bytes expected = {0, 0, 0, 0, 0, 0, 1, 0};
    EXPECT_BYTES_EQ(b, expected);
}
END_TEST

// ===========================================================================
// parseURLParams
// ===========================================================================

REGISTER_TEST("utility.parseURLParams.single_param") {
    auto params = parseURLParams("key=value");
    EXPECT_EQ(params.size(), 1u);
    EXPECT_TRUE(params.count("key") == 1);
    EXPECT_EQ(std::string(params.at("key")), std::string("value"));
}
END_TEST

REGISTER_TEST("utility.parseURLParams.multiple_params") {
    auto params = parseURLParams("a=1&b=2&c=3");
    EXPECT_EQ(params.size(), 3u);
    EXPECT_EQ(std::string(params.at("a")), std::string("1"));
    EXPECT_EQ(std::string(params.at("b")), std::string("2"));
    EXPECT_EQ(std::string(params.at("c")), std::string("3"));
}
END_TEST

REGISTER_TEST("utility.parseURLParams.custom_delimiters") {
    // Bifrost's TOTP URL scheme may not use standard &/= — verify the
    // delimiter parameters actually take effect.
    auto params = parseURLParams("a:1;b:2", ';', ':');
    EXPECT_EQ(params.size(), 2u);
    EXPECT_EQ(std::string(params.at("a")), std::string("1"));
    EXPECT_EQ(std::string(params.at("b")), std::string("2"));
}
END_TEST

REGISTER_TEST("utility.parseURLParams.empty_string") {
    auto params = parseURLParams("");
    EXPECT_TRUE(params.empty());
}
END_TEST

REGISTER_TEST(
    "utility.parseURLParams.pair_with_no_value_delim_gets_empty_value") {
    // Confirmed against utility.cpp: a segment with no valDelim ('=') is
    // still inserted as a key, mapped to an empty string_view — it is NOT
    // dropped. This matters because bifrost-totp:// URLs come from an
    // external process (xdg-open / the desktop file's %u), so a caller
    // passing a bare flag-style param (no "=value") must not silently
    // disappear from the result map.
    auto params = parseURLParams("standalone&key=value");
    EXPECT_EQ(params.size(), 2u);
    EXPECT_TRUE(params.count("standalone") == 1);
    EXPECT_EQ(std::string(params.at("standalone")), std::string(""));
    EXPECT_TRUE(params.count("key") == 1);
    EXPECT_EQ(std::string(params.at("key")), std::string("value"));
}
END_TEST

REGISTER_TEST(
    "utility.parseURLParams.value_with_equals_in_value_splits_on_first") {
    // segment.find(valDelim) locates the FIRST '=' only; a value that itself
    // contains '=' (e.g. base64url padding is rare but not impossible in a
    // future param) is not re-split. Pin this down explicitly since it's a
    // one-line implementation detail with no test otherwise.
    auto params = parseURLParams("key=a=b=c");
    EXPECT_EQ(params.size(), 1u);
    EXPECT_EQ(std::string(params.at("key")), std::string("a=b=c"));
}
END_TEST

REGISTER_TEST("utility.parseURLParams.trailing_delimiter_no_extra_entry") {
    // A trailing '&' with nothing after it must not produce a spurious
    // empty-string key. pos == size on the final loop iteration, so the
    // while(pos < size) guard should stop before processing anything past
    // the last real pair.
    auto params = parseURLParams("key=value&");
    EXPECT_EQ(params.size(), 1u);
    EXPECT_EQ(std::string(params.at("key")), std::string("value"));
}
END_TEST

BIFROST_TEST_MAIN()
