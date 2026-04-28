"""
X25519 Elliptic Curve Diffie-Hellman function.
Implemented strictly per RFC 7748, Section 5.
https://datatracker.ietf.org/doc/html/rfc7748

Only standard Python libraries are used.
"""

import os

# ---------------------------------------------------------------------------
# Curve25519 constants (RFC 7748, Section 4.1)
# ---------------------------------------------------------------------------
P = 2**255 - 19  # Field prime
A24 = 121665  # (486662 - 2) / 4
BITS = 255
BYTES = 32  # (BITS + 7) // 8


# ---------------------------------------------------------------------------
# Encoding / decoding (RFC 7748, Section 5)
# ---------------------------------------------------------------------------


def _decode_u_coordinate(u_bytes: bytes) -> int:
    """
    Decode a 32-byte little-endian u-coordinate.
    The most significant bit of the final byte is masked out (X25519 only).
    Non-canonical values are accepted and reduced modulo p implicitly by
    the field arithmetic.
    """
    u_list = list(u_bytes)
    u_list[31] &= 0x7F  # mask the unused MSB (RFC 7748 §5)
    return int.from_bytes(u_list, "little")


def _encode_u_coordinate(u: int) -> bytes:
    """
    Encode an integer as a 32-byte little-endian u-coordinate.
    The unused MSB is zero by construction (u is already reduced mod p < 2^255).
    """
    return (u % P).to_bytes(BYTES, "little")


def _decode_scalar(k_bytes: bytes) -> int:
    """
    Clamp and decode a 32-byte scalar (RFC 7748 §5):
      - Clear the 3 LSBs of byte 0   (makes scalar a multiple of cofactor 8)
      - Clear the MSB of byte 31     (keeps scalar < 2^255)
      - Set bit 254 of byte 31       (ensures scalar >= 2^254)
    """
    k_list = list(k_bytes)
    k_list[0] &= 0xF8  # clear bits 0-2
    k_list[31] &= 0x7F  # clear bit 255
    k_list[31] |= 0x40  # set   bit 254
    return int.from_bytes(k_list, "little")


# ---------------------------------------------------------------------------
# Montgomery ladder (RFC 7748, Section 5)
# ---------------------------------------------------------------------------


def _clamp_swap(swap: int, a: int, b: int):
    """Constant-time conditional swap over integers (RFC 7748 §5.1)."""
    # mask is all-1s when swap==1, all-0s when swap==0
    mask = -swap & ((1 << (BITS + 1)) - 1)
    dummy = mask & (a ^ b)
    return a ^ dummy, b ^ dummy


def _montgomery_ladder(k: int, u: int) -> int:
    """
    Perform scalar multiplication k*u on Curve25519 using the Montgomery
    ladder (RFC 7748, Section 5).  All arithmetic is in GF(p).
    """
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0

    for t in range(BITS - 1, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = _clamp_swap(swap, x_2, x_3)
        z_2, z_3 = _clamp_swap(swap, z_2, z_3)
        swap = k_t

        A = (x_2 + z_2) % P
        AA = (A * A) % P
        B = (x_2 - z_2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x_3 + z_3) % P
        D = (x_3 - z_3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x_3 = pow(DA + CB, 2, P)
        z_3 = x_1 * pow(DA - CB, 2, P) % P
        x_2 = AA * BB % P
        z_2 = E * (AA + A24 * E) % P

    x_2, x_3 = _clamp_swap(swap, x_2, x_3)
    z_2, z_3 = _clamp_swap(swap, z_2, z_3)

    # Return x_2 / z_2  in GF(p) via Fermat's little theorem: z^(p-2) = z^(-1)
    return x_2 * pow(z_2, P - 2, P) % P


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Base point u-coordinate = 9, encoded as 32 bytes little-endian
BASE_POINT: bytes = b"\x09" + b"\x00" * 31


def x25519(k_bytes: bytes, u_bytes: bytes) -> bytes:
    """
    X25519(k, u) — RFC 7748, Section 5.

    Args:
        k_bytes: 32-byte scalar (private key or ephemeral secret).
        u_bytes: 32-byte u-coordinate (public key or base point).

    Returns:
        32-byte u-coordinate result.
    """
    if len(k_bytes) != BYTES:
        raise ValueError(f"Scalar must be {BYTES} bytes, got {len(k_bytes)}")
    if len(u_bytes) != BYTES:
        raise ValueError(f"U-coordinate must be {BYTES} bytes, got {len(u_bytes)}")

    k = _decode_scalar(k_bytes)
    u = _decode_u_coordinate(u_bytes)
    result = _montgomery_ladder(k, u)
    return _encode_u_coordinate(result)


def generate_private_key() -> bytes:
    """Generate a random 32-byte private key."""
    return os.urandom(BYTES)


def public_key(private_key_bytes: bytes) -> bytes:
    """
    Derive the public key from a private key.
    Equivalent to X25519(private_key, BASE_POINT).
    """
    return x25519(private_key_bytes, BASE_POINT)


def diffie_hellman(private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
    """
    Compute the X25519 shared secret.
    Returns the 32-byte shared secret; callers SHOULD check for the
    all-zero result and abort (RFC 7748, Section 6.1).
    """
    secret = x25519(private_key_bytes, peer_public_key_bytes)
    if secret == b"\x00" * BYTES:
        raise ValueError("Shared secret is all-zero (small-order point)")
    return secret


# ---------------------------------------------------------------------------
# Tests against all RFC 7748 test vectors
# ---------------------------------------------------------------------------


def _h(hex_str: str) -> bytes:
    """Decode a compact hex string to bytes."""
    return bytes.fromhex(hex_str.replace(" ", "").replace("\n", ""))


def run_tests():
    passed = 0
    failed = 0

    def check(name: str, got: bytes, expected: bytes):
        nonlocal passed, failed
        if got == expected:
            print(f"  PASS  {name}")
            passed += 1
        else:
            print(f"  FAIL  {name}")
            print(f"        expected: {expected.hex()}")
            print(f"        got:      {got.hex()}")
            failed += 1

    # ------------------------------------------------------------------
    # RFC 7748 §5.2 — Single-call test vectors
    # ------------------------------------------------------------------
    print("=== §5.2 single-call test vectors ===")

    check(
        "TV1",
        x25519(
            _h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            _h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
        ),
        _h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
    )

    check(
        "TV2",
        x25519(
            _h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            _h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
        ),
        _h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
    )

    # ------------------------------------------------------------------
    # RFC 7748 §5.2 — Iterated test vectors (1, 1 000, 1 000 000 rounds)
    # ------------------------------------------------------------------
    print("\n=== §5.2 iterated test vectors ===")

    k = _h("0900000000000000000000000000000000000000000000000000000000000000")
    u = _h("0900000000000000000000000000000000000000000000000000000000000000")

    for i in range(1_001):
        k, u = x25519(k, u), k

        if i + 1 == 1:
            check(
                "iter=1",
                k,
                _h("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"),
            )
        elif i + 1 == 1_000:
            check(
                "iter=1000",
                k,
                _h("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"),
            )
        elif i + 1 == 1_000_000:
            check(
                "iter=1000000",
                k,
                _h("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"),
            )

    # ------------------------------------------------------------------
    # RFC 7748 §6.1 — Full ECDH exchange test vector
    # ------------------------------------------------------------------
    print("\n=== §6.1 ECDH test vector ===")

    alice_priv = _h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    alice_pub = _h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    bob_priv = _h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    bob_pub = _h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    shared_k = _h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    check("Alice public key", public_key(alice_priv), alice_pub)
    check("Bob   public key", public_key(bob_priv), bob_pub)
    check("Shared secret (Alice side)", x25519(alice_priv, bob_pub), shared_k)
    check("Shared secret (Bob   side)", x25519(bob_priv, alice_pub), shared_k)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print(f"\n{'=' * 38}")
    print(f"  {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    pass

    privKey = generate_private_key()
    pubKey = public_key(privKey)
    print(f"Server Private Key: {privKey.hex()}")
    print(f"Server Public  Key: {pubKey.hex()}")

    bifrostKey = _h(input("Enter Bifrost Key: "))

    sharedKey = diffie_hellman(privKey, bifrostKey)
    print(f"Shared Secret Key: {sharedKey.hex()}")
