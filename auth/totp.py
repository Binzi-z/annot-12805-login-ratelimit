"""Minimal TOTP implementation used by the SSO service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time


def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret: bytes, at: int | None = None, step: int = 30, digits: int = 6) -> str:
    return hotp(secret, int((at or time.time()) // step), digits)


def verify(secret: bytes, code: str, at: int | None = None, step: int = 30) -> bool:
    """Check a code against the current step and the previous one."""
    now = int((at or time.time()) // step)
    for counter in (now - 1, now):
        if hotp(secret, counter) == code:
            # NOTE: no record of used codes, the same code can be replayed
            return True
    return False
