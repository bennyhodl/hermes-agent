"""Tests for tools.session_env — per-session env var injection for tools."""

from __future__ import annotations

import threading

import pytest

from tools.approval import reset_current_session_key, set_current_session_key
from tools.session_env import (
    _session_env,
    clear_session_env_vars,
    get_current_session_env_vars,
    get_session_env_vars,
    set_session_env_vars,
)


@pytest.fixture(autouse=True)
def _clean_store():
    """Wipe the module-global store between tests."""
    _session_env.clear()
    yield
    _session_env.clear()


def test_set_and_get_roundtrip():
    set_session_env_vars("sess1", {"GH_TOKEN": "abc", "OTHER": "1"})
    assert get_session_env_vars("sess1") == {"GH_TOKEN": "abc", "OTHER": "1"}


def test_get_returns_empty_for_unknown_session():
    assert get_session_env_vars("nope") == {}


def test_get_returns_copy_not_live_view():
    set_session_env_vars("sess1", {"K": "v"})
    snap = get_session_env_vars("sess1")
    snap["K"] = "mutated"
    assert get_session_env_vars("sess1") == {"K": "v"}


def test_set_coerces_values_to_strings():
    set_session_env_vars("s", {"N": 42, "B": True})
    env = get_session_env_vars("s")
    assert env == {"N": "42", "B": "True"}


def test_set_with_empty_key_or_env_is_noop():
    set_session_env_vars("", {"X": "y"})
    set_session_env_vars("s", {})
    assert _session_env == {}


def test_set_overwrites_existing():
    set_session_env_vars("s", {"A": "1"})
    set_session_env_vars("s", {"B": "2"})
    assert get_session_env_vars("s") == {"B": "2"}


def test_clear_removes_entry():
    set_session_env_vars("s", {"A": "1"})
    clear_session_env_vars("s")
    assert get_session_env_vars("s") == {}
    # Idempotent
    clear_session_env_vars("s")
    clear_session_env_vars("")


def test_get_current_without_session_key():
    # No contextvar bound → empty
    assert get_current_session_env_vars() == {}


def test_get_current_resolves_via_approval_contextvar():
    set_session_env_vars("webhook:r1:d1", {"GH_TOKEN": "xyz"})
    token = set_current_session_key("webhook:r1:d1")
    try:
        assert get_current_session_env_vars() == {"GH_TOKEN": "xyz"}
    finally:
        reset_current_session_key(token)


def test_get_current_empty_when_session_unknown():
    token = set_current_session_key("ghost-session")
    try:
        assert get_current_session_env_vars() == {}
    finally:
        reset_current_session_key(token)


def test_multiple_sessions_isolated():
    set_session_env_vars("a", {"T": "1"})
    set_session_env_vars("b", {"T": "2"})
    assert get_session_env_vars("a") == {"T": "1"}
    assert get_session_env_vars("b") == {"T": "2"}
    clear_session_env_vars("a")
    assert get_session_env_vars("b") == {"T": "2"}


def test_threadsafe_set_get():
    def worker(i: int) -> None:
        set_session_env_vars(f"s{i}", {"I": str(i)})

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for i in range(50):
        assert get_session_env_vars(f"s{i}") == {"I": str(i)}
