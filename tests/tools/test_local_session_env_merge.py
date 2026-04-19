"""Tests for session env var merge in tools.environments.local._make_run_env."""

from __future__ import annotations

import pytest

from tools.approval import reset_current_session_key, set_current_session_key
from tools.environments.local import _make_run_env
from tools.session_env import (
    _session_env,
    clear_session_env_vars,
    set_session_env_vars,
)


@pytest.fixture(autouse=True)
def _clean_session_env():
    _session_env.clear()
    yield
    _session_env.clear()


def test_session_env_vars_appear_in_run_env():
    set_session_env_vars("sess-A", {"GH_TOKEN": "sekrit", "CUSTOM": "yes"})
    token = set_current_session_key("sess-A")
    try:
        env = _make_run_env({})
    finally:
        reset_current_session_key(token)
    assert env.get("GH_TOKEN") == "sekrit"
    assert env.get("CUSTOM") == "yes"


def test_session_env_wins_over_caller_env_and_process_env(monkeypatch):
    # Process env and caller env both set GH_TOKEN to stale values.
    monkeypatch.setenv("GH_TOKEN", "stale-process")
    set_session_env_vars("sess-B", {"GH_TOKEN": "fresh-session"})
    token = set_current_session_key("sess-B")
    try:
        env = _make_run_env({"GH_TOKEN": "stale-caller"})
    finally:
        reset_current_session_key(token)
    # Session-scoped value wins.
    assert env["GH_TOKEN"] == "fresh-session"


def test_no_session_key_bound_leaves_env_untouched(monkeypatch):
    monkeypatch.setenv("EXAMPLE_VAR", "from-process")
    set_session_env_vars("other-session", {"EXAMPLE_VAR": "from-other"})
    # Don't bind the contextvar → the helper sees no "current session".
    env = _make_run_env({})
    assert env["EXAMPLE_VAR"] == "from-process"


def test_cleared_session_does_not_leak():
    set_session_env_vars("sess-C", {"TRANSIENT": "1"})
    clear_session_env_vars("sess-C")
    token = set_current_session_key("sess-C")
    try:
        env = _make_run_env({})
    finally:
        reset_current_session_key(token)
    assert "TRANSIENT" not in env
