"""Time-based one-time passwords (RFC 6238, HMAC-SHA1, 6 digits, 30 s).

The parameters every authenticator app supports (Google Authenticator,
Microsoft Authenticator, 1Password, Authy). Standard library only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

DIGITS = 6
PERIOD_SECONDS = 30
SECRET_BYTES = 20
# Accept the previous and next step for clock drift between phone and server.
DRIFT_STEPS = 1


def generate_secret() -> str:
    """A new base32 secret (160 bits, no padding)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    padded = secret.upper() + "=" * (-len(secret) % 8)
    return base64.b32decode(padded)


def current_step(now: float | None = None) -> int:
    """Time step number for ``now`` (seconds since the epoch)."""
    return int((time.time() if now is None else now) // PERIOD_SECONDS)


def code_at(secret: str, step: int) -> str:
    """The code for ``secret`` at time step ``step``."""
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def normalize_code(code: str | None) -> str:
    """Strip spaces and dashes users type or paste around a code."""
    return "".join(ch for ch in str(code or "") if ch not in " -")


def matching_step(
    secret: str, code: str | None, after_step: int | None = None, now=None
) -> int | None:
    """The step ``code`` belongs to, within the drift window, or ``None``.

    Args:
        secret: Base32 secret.
        code: Code the user typed.
        after_step: Last step already used; codes at or before it are
            refused so a code cannot be replayed.
        now: Override of the current time, for tests.
    """
    code = normalize_code(code)
    if len(code) != DIGITS or not code.isdigit():
        return None
    step = current_step(now)
    for candidate in range(step - DRIFT_STEPS, step + DRIFT_STEPS + 1):
        if after_step is not None and candidate <= after_step:
            continue
        if hmac.compare_digest(code_at(secret, candidate), code):
            return candidate
    return None


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    """``otpauth://`` URI that authenticator apps read from a QR code."""
    label = quote(f"{issuer}:{account}")
    query = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": DIGITS,
            "period": PERIOD_SECONDS,
        }
    )
    return f"otpauth://totp/{label}?{query}"
