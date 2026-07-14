"""
TOTP (Time-based One-Time Password) generation.

Loosely inspired by RFC 6238 / HOTP (RFC 4226), but uses a custom
HMAC-SHA256 construction that mirrors the original C++ implementation:
  - The HMAC *key*     is the hex-encoded shared secret (UTF-8 bytes).
  - The HMAC *message* is the current time-window index as a UTF-8 string.

This intentionally preserves backward-compatibility with the C++ version
rather than implementing strict RFC 6238.

NOTE: the "shared secret" received here is already the output of
HKDF-SHA256(salt=PW_KEY, ikm=TLS_exporter_secret, info="bifrost-totp-key"),
computed once in app.py's _handle_bifrost_connection() at registration time
and mirrored by the C++ client. This module does not perform key derivation
— it only computes HMAC-SHA1 over the already-derived secret, matching
totp.cpp's genSample(). TOTP_DIGEST_SIZE / HMAC-SHA256 is a known, tracked
deviation from RFC 6238 (see the TODO in totp.hpp); both sides must switch
to HMAC-SHA256 simultaneously if that migration happens.
"""

import hashlib
import hmac
import math
from datetime import datetime

# Each window is 30 seconds; OTP is 6 decimal digits.
TIME_WINDOW = 30
OTP_DIGITS = 6
_MODULUS = int(math.pow(10, OTP_DIGITS))  # 10^6 = 1_000_000


def _gen_sample(key_bytes: bytes, time_window_index: int) -> int:
    """
    Compute one HMAC-SHA256 sample for a given time-window index.

    The key fed to HMAC is the *hex string* of the raw secret (UTF-8),
    matching the original C++ behaviour.  The message is the window
    index rendered as a UTF-8 decimal string.

    Returns the 31-bit dynamic truncation value (RFC 4226 §5.3 style).
    """
    # Encode key as hex string bytes (mirrors C++ std::string key.hex())
    msg = time_window_index.to_bytes(8, byteorder="big")

    digest = hmac.new(key_bytes, msg, hashlib.sha256).digest()

    # Dynamic truncation: use the low 4 bits of the last byte as offset.
    offset = digest[-1] & 0x0F

    # Reconstruct a 32-bit big-endian integer from 4 bytes at the offset.
    sample = (
        (digest[offset] << 24)
        | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8)
        | digest[offset + 3]
    )

    # Strip the sign bit to get a 31-bit positive integer.
    return sample & 0x7FFF_FFFF


def generate_otp(shared_secret: bytes) -> list[str]:
    """
    Generate the three valid OTP codes for the current moment:
      - Current window  (valid now)
      - Next window     (30 s ahead, allows clock skew)
      - Previous window (30 s behind, allows clock skew)

    Returns a list of three zero-padded 6-digit strings.

    Raises ValueError if shared_secret is None or empty.
    """
    if not shared_secret:
        raise ValueError("shared_secret must be non-empty bytes")

    epoch = int(datetime.now().timestamp())
    cur_win = epoch // TIME_WINDOW

    codes = []
    for delta in (0, +1, -1):
        sample = _gen_sample(shared_secret, cur_win + delta)
        codes.append(f"{sample % _MODULUS:0{OTP_DIGITS}d}")

    return codes  # [current, next, previous]


def verify_otp(shared_secret: bytes, user_code: str) -> bool:
    """
    Return True if *user_code* matches any of the three valid OTP windows.
    Constant-time comparison is used to prevent timing attacks.
    """
    if not user_code or len(user_code) != OTP_DIGITS:
        return False

    expected_codes = generate_otp(shared_secret)
    return any(hmac.compare_digest(user_code, expected) for expected in expected_codes)
