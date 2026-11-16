"""Offline abuse detector for code/session event sequences.

The detector is side-effect free: it replays an ordered event log and decides
whether each event constitutes a TOTP replay or a session reuse, citing the
exact evidence (counter, first-seen index, issuance time, TTL, ...).

Event schema (each event is a dict with an ``at`` timestamp):

* ``{"type": "totp_verify", "secret": bytes, "code": str, "at": int}``
* ``{"type": "session_create", "sid": str, "user": str, "at": int}``
* ``{"type": "mfa_complete", "sid": str, "at": int}``
* ``{"type": "session_access", "sid": str, "at": int}``

The three rules map 1:1 to the three red security cases:

* ``totp_replay``          -> test_replay_is_rejected
* ``session_fixation``     -> test_session_id_rotates_after_mfa
* ``expired_session_use``  -> test_expired_session_rejected
"""

from __future__ import annotations

from dataclasses import dataclass, field

from auth.session import SessionStore
from auth.totp import totp

TOTP_REPLAY = "totp_replay"
SESSION_FIXATION = "session_fixation"
EXPIRED_SESSION_USE = "expired_session_use"


@dataclass
class Finding:
    rule: str
    index: int
    reason: str
    evidence: dict = field(default_factory=dict)


def _matching_counter(secret: bytes, code: str, at: int, step: int) -> int | None:
    """Return the counter the code is valid for at ``at`` (current/previous)."""
    current = at // step
    for counter in (current - 1, current):
        if totp(secret, at=counter * step, step=step) == code:
            return counter
    return None


def detect(events: list[dict], *, ttl: int = SessionStore.TTL) -> list[Finding]:
    findings: list[Finding] = []

    # TOTP state: consumed counters per secret and where they were first seen.
    used_counters: dict[bytes, set[int]] = {}
    first_seen_index: dict[tuple[bytes, int], int] = {}

    # Session state: issuance time per id, and ids retired by MFA rotation.
    issued_at: dict[str, int] = {}
    retired_at: dict[str, int] = {}

    for index, event in enumerate(events):
        etype = event.get("type")
        at = event["at"]

        if etype == "totp_verify":
            secret = event["secret"]
            code = event["code"]
            step = event.get("step", 30)
            counter = _matching_counter(secret, code, at, step)
            if counter is None:
                continue  # wrong guess: not a replay, and it consumes nothing
            used = used_counters.setdefault(secret, set())
            if counter in used:
                findings.append(Finding(
                    rule=TOTP_REPLAY,
                    index=index,
                    reason=(
                        f"code for counter {counter} was already accepted at "
                        f"event {first_seen_index[(secret, counter)]}; "
                        "a TOTP code is single-use"
                    ),
                    evidence={
                        "code": code,
                        "counter": counter,
                        "step": step,
                        "first_seen_index": first_seen_index[(secret, counter)],
                        "replay_index": index,
                    },
                ))
            else:
                used.add(counter)
                first_seen_index[(secret, counter)] = index

        elif etype == "session_create":
            issued_at[event["sid"]] = at

        elif etype == "mfa_complete":
            sid = event["sid"]
            if sid in retired_at:
                # Completing MFA again through an id that was already rotated
                # is itself reuse of the fixatable pre-MFA id.
                findings.append(Finding(
                    rule=SESSION_FIXATION,
                    index=index,
                    reason=(
                        f"pre-MFA session id {sid!r} was retired at event "
                        f"{retired_at[sid]} and must not be reused"
                    ),
                    evidence={
                        "sid": sid,
                        "retired_index": retired_at[sid],
                        "reuse_index": index,
                    },
                ))
            elif sid in issued_at:
                # Correct behavior: the id is retired here and replaced.
                retired_at[sid] = index

        elif etype == "session_access":
            sid = event["sid"]
            if sid in retired_at:
                findings.append(Finding(
                    rule=SESSION_FIXATION,
                    index=index,
                    reason=(
                        f"access uses pre-MFA id {sid!r}, which was retired at "
                        f"event {retired_at[sid]}; only the rotated post-MFA "
                        "id may be used"
                    ),
                    evidence={
                        "sid": sid,
                        "retired_index": retired_at[sid],
                        "access_index": index,
                    },
                ))
            elif sid in issued_at and at - issued_at[sid] > ttl:
                findings.append(Finding(
                    rule=EXPIRED_SESSION_USE,
                    index=index,
                    reason=(
                        f"session {sid!r} issued at {issued_at[sid]} expired "
                        f"after a {ttl}s TTL; access attempted at {at} "
                        f"(age {at - issued_at[sid]}s)"
                    ),
                    evidence={
                        "sid": sid,
                        "issued_at": issued_at[sid],
                        "access_at": at,
                        "age": at - issued_at[sid],
                        "ttl": ttl,
                    },
                ))

    return findings


def analyze(events: list[dict], *, ttl: int = SessionStore.TTL) -> dict:
    """Convenience wrapper: verdict plus the findings that support it."""
    findings = detect(events, ttl=ttl)
    return {
        "abuse": bool(findings),
        "rules_hit": sorted({f.rule for f in findings}),
        "findings": [
            {"rule": f.rule, "index": f.index, "reason": f.reason,
             "evidence": f.evidence}
            for f in findings
        ],
    }
