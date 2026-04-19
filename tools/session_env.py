"""Per-session environment variable injection for tool subprocesses.

Mirrors the ``_session_yolo`` pattern in :mod:`tools.approval`: gateway code
(e.g. the webhook adapter) can stash per-session environment variables that
should be surfaced to any child process spawned by tools running inside that
session, without mutating the process-global ``os.environ``.

Resolution of the "current" session key leans on the same
``_approval_session_key`` contextvar already populated by the gateway dispatch
layer — this way tool calls executing on executor threads see the right
session identity with no extra wiring.

Typical lifecycle from a webhook dispatch::

    set_session_env_vars(session_key, {"GH_TOKEN": tok, "GITHUB_TOKEN": tok})
    try:
        await handle_message(event)
    finally:
        clear_session_env_vars(session_key)
"""

from __future__ import annotations

import threading
from typing import Dict

__all__ = [
    "set_session_env_vars",
    "get_session_env_vars",
    "clear_session_env_vars",
    "get_current_session_env_vars",
]

_session_env: Dict[str, Dict[str, str]] = {}
_lock = threading.Lock()


def set_session_env_vars(session_key: str, env: Dict[str, str]) -> None:
    """Store a dict of env vars for a specific session.

    Overwrites any existing entry for that session. No-op if session_key is
    falsy or env is empty.
    """
    if not session_key or not env:
        return
    with _lock:
        _session_env[session_key] = {str(k): str(v) for k, v in env.items()}


def get_session_env_vars(session_key: str) -> Dict[str, str]:
    """Return a copy of the env vars registered for a session (or empty dict)."""
    if not session_key:
        return {}
    with _lock:
        return dict(_session_env.get(session_key, {}))


def clear_session_env_vars(session_key: str) -> None:
    """Remove all env vars registered for a session."""
    if not session_key:
        return
    with _lock:
        _session_env.pop(session_key, None)


def get_current_session_env_vars() -> Dict[str, str]:
    """Return env vars for the active approval session, or an empty dict.

    Reads the ``_approval_session_key`` contextvar from :mod:`tools.approval`
    — the same source of truth used by the session-scoped YOLO latch.
    """
    try:
        from tools.approval import get_current_session_key
    except Exception:
        return {}
    session_key = get_current_session_key(default="")
    if not session_key:
        return {}
    return get_session_env_vars(session_key)
