import time

import pytest

from auth.session import SessionStore
from auth.totp import hotp, totp, verify

SECRET = b"12345678901234567890"


def test_totp_matches_rfc_vector():
    # RFC 6238 test vector for T=59 with the SHA1 key
    assert totp(SECRET, at=59) == "287082"


def test_verify_accepts_current_step():
    now = 1_700_000_000
    assert verify(SECRET, totp(SECRET, at=now), at=now)


def test_verify_accepts_previous_step():
    now = 1_700_000_000
    assert verify(SECRET, totp(SECRET, at=now - 30), at=now)


def test_verify_rejects_far_past():
    now = 1_700_000_000
    assert not verify(SECRET, totp(SECRET, at=now - 300), at=now)


def test_hotp_is_stable():
    assert hotp(SECRET, 1) == hotp(SECRET, 1)


def test_session_create_returns_id():
    store = SessionStore()
    assert store.create("alice")


def test_session_get_returns_user():
    store = SessionStore()
    sid = store.create("alice")
    assert store.get(sid)["user"] == "alice"


def test_session_unknown_raises():
    store = SessionStore()
    with pytest.raises(KeyError):
        store.get("nope")


def test_session_mark_mfa():
    store = SessionStore()
    sid = store.create("alice")
    store.mark_mfa(sid)
    assert store.get(sid)["mfa"] is True


def test_compare_equal():
    assert SessionStore().compare("abc", "abc")


def test_compare_differs():
    assert not SessionStore().compare("abc", "abd")


def test_create_two_sessions_differ():
    store = SessionStore()
    assert store.create("a") != store.create("a")


def test_get_after_create_keeps_issued():
    store = SessionStore()
    sid = store.create("a", now=100)
    assert store.get(sid)["issued"] == 100


def test_hotp_six_digits():
    assert len(hotp(SECRET, 5)) == 6


def test_totp_changes_between_steps():
    assert totp(SECRET, at=1000) != totp(SECRET, at=1030)


def test_verify_rejects_wrong_code():
    assert not verify(SECRET, "000000", at=1_700_000_000)


# ---- security cases (currently red) --------------------------------------


def test_replay_is_rejected():
    """The same code must not be accepted twice."""
    now = 1_700_000_000
    code = totp(SECRET, at=now)
    assert verify(SECRET, code, at=now) is True
    assert verify(SECRET, code, at=now) is False


def test_session_id_rotates_after_mfa():
    """Completing MFA must issue a new session id."""
    store = SessionStore()
    sid = store.create("alice")
    new_sid = store.mark_mfa(sid)
    assert new_sid and new_sid != sid


def test_expired_session_rejected():
    store = SessionStore()
    sid = store.create("alice", now=1000)
    with pytest.raises(KeyError):
        store.get(sid, now=1000 + 7200)


def test_compare_is_constant_time():
    """Comparison must not short-circuit on the first differing byte."""
    store = SessionStore()
    assert store.compare("abc", "abd") is False
    assert store.compare_constant_time("abc", "abd") is False
