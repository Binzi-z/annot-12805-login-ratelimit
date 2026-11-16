"""Minimal TOTP implementation used by the SSO service."""

from __future__ import annotations

import hashlib
import hmac
import struct
import time

#: Counters that have already produced an accepted verification, keyed by
#: secret. A code whose counter is recorded here must never be accepted again.
_used_counters: dict[bytes, set[int]] = {}


def reset_replay_state() -> None:
    """Forget every consumed counter.

    Mainly intended for tests: production code keeps the state for the
    process lifetime so a captured code stays unusable across requests.
    """
    _used_counters.clear()


def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret: bytes, at: int | None = None, step: int = 30, digits: int = 6) -> str:
    return hotp(secret, int((at or time.time()) // step), digits)


def verify(secret: bytes, code: str, at: int | None = None, step: int = 30) -> bool:
    """Check a code against the current step and the previous one.

    A code may succeed at most once: the counter that matched is recorded and
    any later presentation of the same code (replay) is rejected. Wrong codes
    are not recorded, so failed guesses cannot burn a victim's valid counter.
    """
    now = int((at or time.time()) // step)
    used = _used_counters.setdefault(secret, set())
    for counter in (now - 1, now):
        candidate = hotp(secret, counter)
        if hmac.compare_digest(candidate, code):
            if counter in used:
                # Replay: this counter has already been consumed.
                return False
            used.add(counter)
            # Only retain counters that could still match a future window.
            _used_counters[secret] = {c for c in used if c >= now - 1}
            return True
    return False
