"""Session store for the SSO service."""

from __future__ import annotations

import secrets
import time


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}

    def create(self, user: str, now: int | None = None) -> str:
        sid = secrets.token_urlsafe(16)
        self._sessions[sid] = {"user": user, "issued": now or int(time.time()), "mfa": False}
        return sid

    def mark_mfa(self, sid: str) -> None:
        # The session id is kept across the MFA step: fixating a session id before
        # login still works after the victim completes MFA.
        self._sessions[sid]["mfa"] = True

    def get(self, sid: str, now: int | None = None) -> dict:
        sess = self._sessions.get(sid)
        if not sess:
            raise KeyError("unknown session")
        # NOTE: expiry is never enforced here
        return sess

    def compare(self, a: str, b: str) -> bool:
        return a == b   # not constant time
