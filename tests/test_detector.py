"""Tests for the offline replay/reuse detector.

The three abuse cases mirror the three red security tests in test_auth.py;
the remaining cases prove legitimate flows never trigger a finding.
"""

from auth.detector import (
    EXPIRED_SESSION_USE,
    SESSION_FIXATION,
    TOTP_REPLAY,
    analyze,
)
from auth.totp import totp

SECRET = b"12345678901234567890"


# ---- abuse cases, one per red security test ------------------------------


def test_detects_totp_replay():
    now = 1_700_000_000
    code = totp(SECRET, at=now)
    result = analyze([
        {"type": "totp_verify", "secret": SECRET, "code": code, "at": now},
        {"type": "totp_verify", "secret": SECRET, "code": code, "at": now},
    ])
    assert result["abuse"] is True
    assert result["rules_hit"] == [TOTP_REPLAY]
    finding = result["findings"][0]
    assert finding["index"] == 1
    assert finding["evidence"]["first_seen_index"] == 0
    assert finding["evidence"]["counter"] == now // 30


def test_detects_session_fixation():
    result = analyze([
        {"type": "session_create", "sid": "fixed", "user": "alice", "at": 100},
        {"type": "mfa_complete", "sid": "fixed", "at": 200},
        # Attacker keeps using the id fixated before MFA.
        {"type": "session_access", "sid": "fixed", "at": 300},
    ])
    assert result["abuse"] is True
    assert result["rules_hit"] == [SESSION_FIXATION]
    assert result["findings"][0]["index"] == 2
    assert result["findings"][0]["evidence"]["retired_index"] == 1


def test_detects_expired_session_use():
    result = analyze([
        {"type": "session_create", "sid": "s1", "user": "alice", "at": 1000},
        {"type": "session_access", "sid": "s1", "at": 1000 + 7200},
    ])
    assert result["abuse"] is True
    assert result["rules_hit"] == [EXPIRED_SESSION_USE]
    evidence = result["findings"][0]["evidence"]
    assert evidence["age"] == 7200
    assert evidence["ttl"] == 3600


# ---- legitimate flows: zero false positives ------------------------------


def test_clean_login_flow_has_no_findings():
    now = 1_700_000_000
    result = analyze([
        {"type": "totp_verify", "secret": SECRET,
         "code": totp(SECRET, at=now), "at": now},
        {"type": "session_create", "sid": "pre", "user": "alice", "at": now},
        {"type": "mfa_complete", "sid": "pre", "at": now + 5},
        # Rotated id used well within the TTL.
        {"type": "session_access", "sid": "post", "at": now + 100},
    ])
    # "post" was never created/retired in the log, so nothing to flag;
    # every recorded event is legitimate.
    assert result["abuse"] is False
    assert result["findings"] == []


def test_wrong_code_is_not_replay():
    now = 1_700_000_000
    result = analyze([
        {"type": "totp_verify", "secret": SECRET, "code": "000000", "at": now},
        {"type": "totp_verify", "secret": SECRET, "code": "000000", "at": now},
    ])
    assert result["abuse"] is False


def test_previous_step_code_used_once_is_fine():
    now = 1_700_000_000
    result = analyze([
        {"type": "totp_verify", "secret": SECRET,
         "code": totp(SECRET, at=now - 30), "at": now},
    ])
    assert result["abuse"] is False


def test_access_within_ttl_is_fine():
    result = analyze([
        {"type": "session_create", "sid": "s1", "user": "alice", "at": 1000},
        {"type": "session_access", "sid": "s1", "at": 1000 + 60},
    ])
    assert result["abuse"] is False


def test_failed_attempts_then_success_is_fine():
    now = 1_700_000_000
    result = analyze([
        {"type": "totp_verify", "secret": SECRET, "code": "111111", "at": now},
        {"type": "totp_verify", "secret": SECRET, "code": "222222", "at": now},
        {"type": "totp_verify", "secret": SECRET,
         "code": totp(SECRET, at=now), "at": now},
    ])
    assert result["abuse"] is False
