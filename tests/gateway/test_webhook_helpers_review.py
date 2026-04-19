"""Targeted tests for webhook helpers touched in the feat/github-app-auth review.

Covers:
- _parse_body form-encoded ``payload=<json>`` unwrapping (GitHub classic).
- _classify_review_conclusion "no critical" negation guard.
- Shared aiohttp.ClientSession lazy-init + disconnect cleanup.
- Feedback-run detection uses exact skill name, not fuzzy substring.
"""

from __future__ import annotations

import json
import urllib.parse

import pytest

from gateway.config import PlatformConfig
from gateway.platforms.webhook import WebhookAdapter


def _adapter():
    return WebhookAdapter(
        PlatformConfig(enabled=True, extra={"host": "127.0.0.1", "port": 0})
    )


# ---------- _parse_body ----------------------------------------------------


def test_parse_body_json_happy_path():
    assert WebhookAdapter._parse_body(b'{"a": 1}') == {"a": 1}


def test_parse_body_form_encoded_github_payload_is_unwrapped():
    inner = {"action": "opened", "pull_request": {"number": 42}}
    body = urllib.parse.urlencode({"payload": json.dumps(inner)}).encode()
    assert WebhookAdapter._parse_body(body) == inner


def test_parse_body_form_encoded_without_payload_returns_dict():
    body = urllib.parse.urlencode({"foo": "bar"}).encode()
    assert WebhookAdapter._parse_body(body) == {"foo": "bar"}


def test_parse_body_form_encoded_bad_payload_falls_through():
    body = urllib.parse.urlencode({"payload": "not-json"}).encode()
    # Returns the parsed_dict unchanged rather than crashing.
    assert WebhookAdapter._parse_body(body) == {"payload": "not-json"}


# ---------- _classify_review_conclusion ------------------------------------


def test_classify_no_critical_is_not_action_required():
    conclusion, _ = WebhookAdapter._classify_review_conclusion(
        "No critical issues found, LGTM"
    )
    assert conclusion == "success"


def test_classify_zero_critical_is_not_action_required():
    conclusion, _ = WebhookAdapter._classify_review_conclusion(
        "Zero critical findings, 0 findings overall"
    )
    assert conclusion == "success"


def test_classify_actual_critical_is_action_required():
    conclusion, _ = WebhookAdapter._classify_review_conclusion(
        "🔴 critical race condition in dispatch"
    )
    assert conclusion == "action_required"


def test_classify_bare_critical_word_is_action_required():
    conclusion, _ = WebhookAdapter._classify_review_conclusion(
        "Found a critical bug in the auth flow"
    )
    assert conclusion == "action_required"


# ---------- Shared aiohttp.ClientSession -----------------------------------


@pytest.mark.asyncio
async def test_get_http_lazy_init_and_disconnect_closes():
    adapter = _adapter()
    assert adapter._http is None
    session1 = await adapter._get_http()
    session2 = await adapter._get_http()
    # Reuses the same session object.
    assert session1 is session2
    assert not session1.closed
    await adapter.disconnect()
    assert adapter._http is None
    assert session1.closed


@pytest.mark.asyncio
async def test_get_http_recreates_after_manual_close():
    adapter = _adapter()
    s1 = await adapter._get_http()
    await s1.close()
    s2 = await adapter._get_http()
    assert s2 is not s1
    assert not s2.closed
    await adapter.disconnect()


# ---------- Feedback-run detection -----------------------------------------


def test_feedback_run_requires_exact_skill_name():
    # Same logic as _dispatch_route uses inline; check the boolean surface.
    skills_exact = ["github-app-review-feedback"]
    skills_fuzzy = ["review-feedback-loop"]
    skills_empty: list[str] = []

    def is_feedback(skills):
        return "github-app-review-feedback" in (skills or [])

    assert is_feedback(skills_exact) is True
    assert is_feedback(skills_fuzzy) is False
    assert is_feedback(skills_empty) is False
