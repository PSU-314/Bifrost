"""
X25519 Elliptic Curve Diffie-Hellman — RFC 7748, Section 5.
https://datatracker.ietf.org/doc/html/rfc7748

Uses only the Python standard library.
"""

import os

# ---------------------------------------------------------------------------
# Curve25519 field constants  (RFC 7748 §4.1)
# ---------------------------------------------------------------------------
P    = 2**255 - 19   # Field prime
A24  = 121665        # (A - 2) / 4  where A = 486662
BITS = 255
BYTES = 32           # 256-bit keys stored as 32 bytes


# ---------------------------------------------------------------------------
# Coordinate / scalar encoding (RFC 7748 §5)
# ---------------------------------------------------------------------------

def _decode_u_coordinate(u_bytes: bytes) -> int:
    """
    Decode a 32-byte little-endian u-coordinate.
    Mask the unused MSB of the final byte (X25519 only, per RFC 7748 §5).
    Non-canonical values are reduced implicitly by field arithmetic.
    """
    u_list = list(u_bytes)
    u_list[31] &= 0x7F          # clear unused most-significant bit
    return int.from_bytes(u_list, "little")


def _encode_u_coordinate(u: int) -> bytes:
    """
    Encode an integer as a 32-byte little-endian u-coordinate.
    The value is reduced mod p before encoding so the MSB is always clear.
    """
    return (u % P).to_bytes(BYTES, "little")


def _decode_scalar(k_bytes: bytes) -> int:
    """
    Clamp and decode a 32-byte scalar (RFC 7748 §5):
      - Clear bits 0-2 of byte 0   → makes scalar a multiple of cofactor 8
      - Clear bit 7 of byte 31     → keeps scalar < 2^255
      - Set  bit 6 of byte 31      → keeps scalar >= 2^254
    """
    k_list = list(k_bytes)
    k_list[0]  &= 0xF8   # clear bits 0-2
    k_list[31] &= 0x7F   # clear bit 255
    k_list[31] |= 0x40   # set   bit 254
    return int.from_bytes(k_list, "little")


# ---------------------------------------------------------------------------
# Montgomery ladder (RFC 7748 §5)
# ---------------------------------------------------------------------------

def _cond_swap(swap: int, a: int, b: int):
    """Constant-time conditional swap of two integers (RFC 7748 §5.1)."""
    mask  = -swap & ((1 << (BITS + 1)) - 1)
    dummy = mask & (a ^ b)
    return a ^ dummy, b ^ dummy


def _montgomery_ladder(k: int, u: int) -> int:
    """
    Scalar multiplication k·u on Curve25519 via the Montgomery ladder.
    All arithmetic is in GF(p).  The ladder runs for exactly BITS iterations
    to keep execution time constant (no early exits).
    """
    x_1 = u
    x_2 = 1;  z_2 = 0
    x_3 = u;  z_3 = 1
    swap = 0

    for t in range(BITS - 1, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = _cond_swap(swap, x_2, x_3)
        z_2, z_3 = _cond_swap(swap, z_2, z_3)
        swap = k_t

        A  = (x_2 + z_2) % P
        AA = (A * A)      % P
        B  = (x_2 - z_2) % P
        BB = (B * B)      % P
        E  = (AA - BB)    % P
        C  = (x_3 + z_3) % P
        D  = (x_3 - z_3) % P
        DA = (D * A)      % P
        CB = (C * B)      % P
        x_3 = pow(DA + CB, 2, P)
        z_3 = x_1 * pow(DA - CB, 2, P) % P
        x_2 = AA * BB % P
        z_2 = E * (AA + A24 * E) % P

    x_2, x_3 = _cond_swap(swap, x_2, x_3)
    z_2, z_3 = _cond_swap(swap, z_2, z_3)

    # Compute x_2 / z_2 in GF(p) using Fermat's little theorem: z^(p-2) = z^(-1)
    return x_2 * pow(z_2, P - 2, P) % P


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# The canonical base point u = 9 (little-endian, 32 bytes)
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

    k      = _decode_scalar(k_bytes)
    u      = _decode_u_coordinate(u_bytes)
    result = _montgomery_ladder(k, u)
    return _encode_u_coordinate(result)


def generate_private_key() -> bytes:
    """Generate a cryptographically random 32-byte private key."""
    return os.urandom(BYTES)


def public_key(private_key_bytes: bytes) -> bytes:
    """Derive the X25519 public key from a private key (= X25519(k, BASE_POINT))."""
    return x25519(private_key_bytes, BASE_POINT)


def diffie_hellman(private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
    """
    Compute the X25519 shared secret.

    Raises ValueError if the result is the all-zero point (small-order peer key),
    as required by RFC 7748 §6.1.
    """
    secret = x25519(private_key_bytes, peer_public_key_bytes)
    if secret == b"\x00" * BYTES:
        raise ValueError("Shared secret is all-zero — peer sent a small-order point")
    return secret