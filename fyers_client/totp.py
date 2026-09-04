"""RFC 6238 TOTP generation, standard library only.

Implemented here rather than pulled in as a dependency so the algorithm can be
checked against the RFC's own test vectors (see tests/test_totp.py) -- a wrong
TOTP fails at the broker with an opaque "invalid OTP", which is miserable to
debug.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time

DIGEST_BY_NAME = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


class TotpError(ValueError):
    """Raised when a TOTP secret cannot be decoded."""


def decode_secret(secret: str) -> bytes:
    """Decode a base32 TOTP secret as printed by an authenticator app.

    Tolerates the spaces and lowercase that appear when a secret is copied out
    of a QR-code screen, and restores stripped padding.
    """
    cleaned = secret.strip().replace(" ", "").replace("-", "").upper()
    if not cleaned:
        raise TotpError("TOTP secret is empty")
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        key = base64.b32decode(cleaned, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise TotpError(
            "TOTP secret is not valid base32. Use the secret key Fyers shows "
            "when enabling TOTP, not the 6-digit code."
        ) from exc
    if not key:
        raise TotpError("TOTP secret decoded to zero bytes")
    return key


def hotp(key: bytes, counter: int, digits: int = 6, algorithm: str = "sha1") -> str:
    """RFC 4226 HOTP: dynamic truncation of an HMAC over the counter."""
    digest = hmac.new(key, struct.pack(">Q", counter), DIGEST_BY_NAME[algorithm]).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def generate_totp(
    secret: str,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "sha1",
    at: float | None = None,
) -> str:
    """Current TOTP for a base32 secret."""
    now = time.time() if at is None else at
    return hotp(decode_secret(secret), int(now // period), digits, algorithm)


def seconds_remaining(period: int = 30, at: float | None = None) -> float:
    """Seconds left before the current TOTP window rolls over."""
    now = time.time() if at is None else at
    return period - (now % period)


def fresh_totp(secret: str, min_validity: float = 5.0, period: int = 30) -> str:
    """TOTP guaranteed to stay valid for at least `min_validity` seconds.

    A code generated with a second left on the clock is often already stale by
    the time the broker validates it, so this waits for the next window instead
    of spending a login attempt on a code that cannot work.
    """
    remaining = seconds_remaining(period)
    if remaining < min_validity:
        time.sleep(remaining + 0.5)
    return generate_totp(secret, period=period)
