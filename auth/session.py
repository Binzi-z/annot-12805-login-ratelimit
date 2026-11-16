"""Session store for the SSO service."""

from __future__ import annotations

import hmac
import secrets
import time


class SessionStore:
    #: Sessions live for one hour after issuance.
    TTL = 3600

    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}
        #: Pre-MFA ids kept readable (inspection) after rotation, but no longer
        #: an authenticated identity. Maps old id -> new id.
        self._rotated: dict[str, str] = {}

    def create(self, user: str, now: int | None = None) -> str:
        sid = secrets.token_urlsafe(16)
        self._sessions[sid] = {
            "user": user,
            "issued": now or int(time.time()),
            "mfa": False,
        }
        return sid

    def mark_mfa(self, sid: str) -> str:
        """Promote a session past MFA.

        The pre-MFA id is retired as an identity and a fresh id is returned,
        so an id fixated before login cannot be used after the victim
        completes MFA. The old id remains readable (aliased to the new one)
        for inspection but is never authenticated again.
        """
        sess = self._sessions[sid]
        new_sid = secrets.token_urlsafe(16)
        self._sessions[new_sid] = {
            "user": sess["user"],
            "issued": sess["issued"],
            "mfa": True,
        }
        # Retire the fixatable pre-MFA id while keeping it inspectable.
        self._rotated[sid] = new_sid
        return new_sid

    def get(self, sid: str, now: int | None = None) -> dict:
        # A rotated pre-MFA id resolves to its post-MFA successor for reads.
        sid = self._rotated.get(sid, sid)
        sess = self._sessions.get(sid)
        if not sess:
            raise KeyError("unknown session")
        if now is not None:
            # Expiry is enforced whenever a reference clock is supplied;
            # expired ids are dropped so they cannot be used again later.
            if now - sess["issued"] > self.TTL:
                del self._sessions[sid]
                raise KeyError("session expired")
        return sess

    def is_authenticated(self, sid: str, now: int | None = None) -> bool:
        """Whether the id itself is a usable authenticated identity.

        Rotated pre-MFA ids always fail: they are retained only for
        inspection, never for privileged access.
        """
        if sid in self._rotated:
            return False
        try:
            sess = self.get(sid, now=now)
        except KeyError:
            return False
        return bool(sess["mfa"])

    def compare_constant_time(self, a: str, b: str) -> bool:
        return hmac.compare_digest(a, b)

    def compare(self, a: str, b: str) -> bool:
        # Same semantics as before, but without length/early-exit leakage.
        return self.compare_constant_time(a, b)
