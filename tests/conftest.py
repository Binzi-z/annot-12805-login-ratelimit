"""Shared pytest fixtures."""

import pytest

from auth.totp import reset_replay_state


@pytest.fixture(autouse=True)
def _reset_totp_replay_state():
    """The replay registry is process-wide; start every case with a clean one."""
    reset_replay_state()
    yield
    reset_replay_state()
