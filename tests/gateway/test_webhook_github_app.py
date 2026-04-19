"""Integration tests for the /webhooks/app/{app_name} multi-match fan-out
and route-level github_app env injection."""

from __future__ import annotations

import asyncio
import json
import os
from unittest.mock import AsyncMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import gateway.github_app_auth as gha
from gateway.config import PlatformConfig
from gateway.platforms.webhook import WebhookAdapter, _INSECURE_NO_AUTH


@pytest.fixture(autouse=True)
def clean_registry():
    gha.clear_registry()
    yield
    gha.clear_registry()


def _adapter_with_routes(routes):
    config = PlatformConfig(
        enabled=True,
        extra={"host": "0.0.0.0", "port": 0, "routes": routes, "rate_limit": 100},
    )
    return WebhookAdapter(config)


def _app(adapter):
    a = web.Application()
    a.router.add_post("/webhooks/app/{app_name}", adapter._handle_app_webhook)
    a.router.add_post("/webhooks/{route_name}", adapter._handle_webhook)
    return a


def _register_fake_app(name="gpodawund", secret=None, token="ghs_fake_token_abc"):
    """Register a GitHubAppAuth stub whose token minting is mocked."""
    auth = gha.GitHubAppAuth(name, 1, "/nonexistent/pem-not-loaded")
    auth.webhook_secret = secret

    async def _get_installation_token(_iid):
        return token, None

    auth.get_installation_token = _get_installation_token  # type: ignore[assignment]
    gha.register_app(auth)
    return auth


@pytest.mark.asyncio
async def test_fanout_runs_every_matching_route():
    _register_fake_app("gpodawund", secret=None)
    routes = {
        "r1": {
            "secret": _INSECURE_NO_AUTH,
            "github_app": "gpodawund",
            "prompt": "r1: {action}",
        },
        "r2": {
            "secret": _INSECURE_NO_AUTH,
            "github_app": "gpodawund",
            "prompt": "r2: {action}",
        },
        "other": {
            "secret": _INSECURE_NO_AUTH,
            "prompt": "unrelated",
        },
    }
    adapter = _adapter_with_routes(routes)
    adapter.handle_message = AsyncMock()

    async with TestClient(TestServer(_app(adapter))) as cli:
        resp = await cli.post(
            "/webhooks/app/gpodawund",
            json={"action": "opened", "installation": {"id": 125312125}},
            headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "d1"},
        )
        assert resp.status == 202
        data = await resp.json()
        assert data["status"] == "dispatched"
        assert {r["route"] for r in data["routes"]} == {"r1", "r2"}
        for r in data["routes"]:
            assert r["status"] == "accepted"
            assert r["github_app"] == "gpodawund"
    # Let background tasks finish
    await asyncio.gather(*list(adapter._background_tasks), return_exceptions=True)
    assert adapter.handle_message.await_count == 2


@pytest.mark.asyncio
async def test_fanout_filter_short_circuits():
    _register_fake_app("gpodawund")
    routes = {
        "merged_only": {
            "secret": _INSECURE_NO_AUTH,
            "github_app": "gpodawund",
            "filter": {"pull_request.merged": "true"},
            "prompt": "p",
        },
        "any": {
            "secret": _INSECURE_NO_AUTH,
            "github_app": "gpodawund",
            "prompt": "q",
        },
    }
    adapter = _adapter_with_routes(routes)
    adapter.handle_message = AsyncMock()
    async with TestClient(TestServer(_app(adapter))) as cli:
        resp = await cli.post(
            "/webhooks/app/gpodawund",
            json={
                "action": "closed",
                "pull_request": {"merged": False},
                "installation": {"id": 1},
            },
            headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "d2"},
        )
        data = await resp.json()
        by_route = {r["route"]: r for r in data["routes"]}
        assert by_route["merged_only"]["status"] == "filtered"
        assert by_route["any"]["status"] == "accepted"
    await asyncio.gather(*list(adapter._background_tasks), return_exceptions=True)
    # Only "any" should have triggered the agent
    assert adapter.handle_message.await_count == 1


@pytest.mark.asyncio
async def test_fanout_zero_matches():
    _register_fake_app("gpodawund")
    routes = {"unrelated": {"secret": _INSECURE_NO_AUTH, "prompt": "x"}}
    adapter = _adapter_with_routes(routes)
    async with TestClient(TestServer(_app(adapter))) as cli:
        resp = await cli.post(
            "/webhooks/app/gpodawund",
            json={"action": "opened", "installation": {"id": 1}},
            headers={"X-GitHub-Event": "pull_request"},
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "no_matching_routes"


@pytest.mark.asyncio
async def test_fanout_unknown_app_returns_404():
    adapter = _adapter_with_routes({})
    async with TestClient(TestServer(_app(adapter))) as cli:
        resp = await cli.post(
            "/webhooks/app/missing",
            json={"action": "opened"},
        )
        assert resp.status == 404


@pytest.mark.asyncio
async def test_single_match_route_injects_gh_token_env():
    _register_fake_app("gpodawund", token="ghs_env_test_token")
    routes = {
        "r1": {
            "secret": _INSECURE_NO_AUTH,
            "github_app": "gpodawund",
            "prompt": "hi",
        },
    }
    adapter = _adapter_with_routes(routes)
    captured = {}

    from tools.session_env import get_session_env_vars

    async def _fake_handle(event):
        # Token should be stashed under the event's session chat_id, not
        # in the process-global os.environ.
        session_key = event.source.chat_id
        captured["session_key"] = session_key
        captured["session_env"] = get_session_env_vars(session_key)
        captured["os_GH_TOKEN"] = os.environ.get("GH_TOKEN")
        captured["os_GITHUB_TOKEN"] = os.environ.get("GITHUB_TOKEN")

    adapter.handle_message = _fake_handle  # type: ignore[assignment]

    # Guard against test pollution: ensure no stale os.environ GH_TOKEN leaks.
    prior_gh = os.environ.pop("GH_TOKEN", None)
    prior_ghub = os.environ.pop("GITHUB_TOKEN", None)
    try:
        async with TestClient(TestServer(_app(adapter))) as cli:
            resp = await cli.post(
                "/webhooks/r1",
                json={"action": "opened", "installation": {"id": 125312125}},
                headers={"X-GitHub-Event": "pull_request"},
            )
            assert resp.status == 202
        # Drain background tasks so the env-injection has completed
        await asyncio.gather(*list(adapter._background_tasks), return_exceptions=True)

        # New behaviour: token is scoped to the per-delivery session key via
        # tools.session_env, NOT leaked into the process-global os.environ.
        assert captured["session_env"]["GH_TOKEN"] == "ghs_env_test_token"
        assert captured["session_env"]["GITHUB_TOKEN"] == "ghs_env_test_token"
        assert captured["os_GH_TOKEN"] is None
        assert captured["os_GITHUB_TOKEN"] is None
        # After the task's finally block runs, the session env is cleared.
        assert get_session_env_vars(captured["session_key"]) == {}
    finally:
        if prior_gh is not None:
            os.environ["GH_TOKEN"] = prior_gh
        if prior_ghub is not None:
            os.environ["GITHUB_TOKEN"] = prior_ghub


@pytest.mark.asyncio
async def test_fanout_validates_app_webhook_secret():
    import hashlib
    import hmac

    _register_fake_app("gpodawund", secret="sekrit")
    routes = {
        "r1": {
            "secret": "",  # fall back to app's webhook_secret
            "github_app": "gpodawund",
            "prompt": "p",
        },
    }
    adapter = _adapter_with_routes(routes)
    adapter.handle_message = AsyncMock()

    body = json.dumps({"action": "opened", "installation": {"id": 1}}).encode()
    good_sig = "sha256=" + hmac.new(b"sekrit", body, hashlib.sha256).hexdigest()

    async with TestClient(TestServer(_app(adapter))) as cli:
        # Bad signature → 401
        resp = await cli.post(
            "/webhooks/app/gpodawund",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": "sha256=deadbeef",
                "X-GitHub-Event": "pull_request",
            },
        )
        assert resp.status == 401

        # Good signature → 202
        resp = await cli.post(
            "/webhooks/app/gpodawund",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": good_sig,
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "d-sig",
            },
        )
        assert resp.status == 202
    await asyncio.gather(*list(adapter._background_tasks), return_exceptions=True)


# ----------------------------------------------------------------------
# GitHub Check Run integration tests
# ----------------------------------------------------------------------


def _pr_payload(
    *,
    action="opened",
    head_sha="abc123deadbeef",
    repo="owner/repo",
    pr_number=42,
    html_url="https://github.com/owner/repo/pull/42",
    merged=False,
    installation_id=555,
):
    return {
        "action": action,
        "repository": {"full_name": repo},
        "pull_request": {
            "number": pr_number,
            "html_url": html_url,
            "merged": merged,
            "head": {"sha": head_sha},
        },
        "installation": {"id": installation_id},
    }


def _stub_check_lifecycle(adapter, *, create_id=987654, create_should_fail=False):
    state = {"created": [], "completed": []}

    async def _start(**kwargs):
        state["created"].append(kwargs)
        if create_should_fail:
            return None
        return create_id

    async def _complete(**kwargs):
        state["completed"].append(kwargs)
        return True

    adapter._start_github_check = _start  # type: ignore[assignment]
    adapter._complete_github_check = _complete  # type: ignore[assignment]
    return state


def _cleanup_env():
    os.environ.pop("GH_TOKEN", None)
    os.environ.pop("GITHUB_TOKEN", None)


@pytest.mark.asyncio
async def test_check_run_created_for_pr_event_with_github_app():
    _register_fake_app("gpodawund")
    routes = {
        "r1": {
            "secret": _INSECURE_NO_AUTH,
            "github_app": "gpodawund",
            "prompt": "hi",
            "deliver": "log",
        },
    }
    adapter = _adapter_with_routes(routes)
    state = _stub_check_lifecycle(adapter, create_id=111)
    adapter.handle_message = AsyncMock()

    async with TestClient(TestServer(_app(adapter))) as cli:
        resp = await cli.post(
            "/webhooks/r1",
            json=_pr_payload(),
            headers={"X-GitHub-Event": "pull_request"},
        )
        assert resp.status == 202

    assert len(state["created"]) == 1
    call = state["created"][0]
    assert call["name"] == "r1"
    assert call["head_sha"] == "abc123deadbeef"
    assert call["repo_full_name"] == "owner/repo"
    assert call["details_url"] == "https://github.com/owner/repo/pull/42"
    assert call["gh_token"] == "ghs_fake_token_abc"

    key = next(iter(adapter._delivery_info))
    assert adapter._delivery_info[key]["check_run_id"] == 111
    assert adapter._delivery_info[key]["check_run_repo"] == "owner/repo"
    assert adapter._delivery_info[key]["check_run_feedback"] is False

    _cleanup_env()


@pytest.mark.asyncio
async def test_check_run_completion_conclusions():
    _register_fake_app("gpodawund")
    cases = [
        ("Review complete. LGTM — nothing to block on.", "success", "Review: LGTM"),
        ("Verdict: Changes Requested\n🔴 Critical bug.", "action_required", "Review: changes requested"),
        ("A few suggestions, nothing blocking.", "neutral", "Review: suggestions posted"),
        ("Sorry, I encountered an error (RuntimeError). boom", "failure", "Review failed"),
    ]
    for response, expected_conclusion, expected_title in cases:
        routes = {
            "r1": {
                "secret": _INSECURE_NO_AUTH,
                "github_app": "gpodawund",
                "prompt": "hi",
                "deliver": "log",
            },
        }
        adapter = _adapter_with_routes(routes)
        state = _stub_check_lifecycle(adapter, create_id=222)
        adapter.handle_message = AsyncMock()

        async with TestClient(TestServer(_app(adapter))) as cli:
            await cli.post(
                "/webhooks/r1",
                json=_pr_payload(),
                headers={"X-GitHub-Event": "pull_request"},
            )

        chat_id = next(iter(adapter._delivery_info))
        await adapter.send(chat_id, response)

        assert len(state["completed"]) == 1, f"for response={response!r}"
        assert state["completed"][0]["conclusion"] == expected_conclusion
        assert state["completed"][0]["title"] == expected_title
        assert state["completed"][0]["check_run_id"] == 222

    _cleanup_env()


@pytest.mark.asyncio
async def test_no_check_run_for_issues_event():
    _register_fake_app("gpodawund")
    routes = {
        "r1": {
            "secret": _INSECURE_NO_AUTH,
            "github_app": "gpodawund",
            "prompt": "hi",
            "deliver": "log",
        },
    }
    adapter = _adapter_with_routes(routes)
    state = _stub_check_lifecycle(adapter)
    adapter.handle_message = AsyncMock()

    async with TestClient(TestServer(_app(adapter))) as cli:
        await cli.post(
            "/webhooks/r1",
            json={
                "action": "opened",
                "issue": {"number": 9},
                "repository": {"full_name": "owner/repo"},
                "installation": {"id": 1},
            },
            headers={"X-GitHub-Event": "issues"},
        )

    assert state["created"] == []
    _cleanup_env()


@pytest.mark.asyncio
async def test_no_check_run_without_github_app():
    routes = {
        "r1": {
            "secret": _INSECURE_NO_AUTH,
            "prompt": "hi",
            "deliver": "log",
        },
    }
    adapter = _adapter_with_routes(routes)
    state = _stub_check_lifecycle(adapter)
    adapter.handle_message = AsyncMock()

    async with TestClient(TestServer(_app(adapter))) as cli:
        await cli.post(
            "/webhooks/r1",
            json=_pr_payload(),
            headers={"X-GitHub-Event": "pull_request"},
        )

    assert state["created"] == []


@pytest.mark.asyncio
async def test_check_run_create_failure_does_not_block_agent():
    _register_fake_app("gpodawund")
    routes = {
        "r1": {
            "secret": _INSECURE_NO_AUTH,
            "github_app": "gpodawund",
            "prompt": "hi",
            "deliver": "log",
        },
    }
    adapter = _adapter_with_routes(routes)
    state = _stub_check_lifecycle(adapter, create_should_fail=True)
    adapter.handle_message = AsyncMock()

    async with TestClient(TestServer(_app(adapter))) as cli:
        resp = await cli.post(
            "/webhooks/r1",
            json=_pr_payload(),
            headers={"X-GitHub-Event": "pull_request"},
        )
        assert resp.status == 202

    await asyncio.gather(*list(adapter._background_tasks), return_exceptions=True)
    assert adapter.handle_message.await_count == 1
    assert state["completed"] == []
    _cleanup_env()


@pytest.mark.asyncio
async def test_check_run_completes_failure_on_delivery_failure():
    _register_fake_app("gpodawund")
    routes = {
        "r1": {
            "secret": _INSECURE_NO_AUTH,
            "github_app": "gpodawund",
            "prompt": "hi",
            "deliver": "github_comment",
        },
    }
    adapter = _adapter_with_routes(routes)
    state = _stub_check_lifecycle(adapter, create_id=777)
    adapter.handle_message = AsyncMock()

    from gateway.platforms.base import SendResult

    async def _failing_delivery(content, delivery):
        return SendResult(success=False, error="simulated")

    adapter._deliver_github_comment = _failing_delivery  # type: ignore[assignment]

    async with TestClient(TestServer(_app(adapter))) as cli:
        await cli.post(
            "/webhooks/r1",
            json=_pr_payload(),
            headers={"X-GitHub-Event": "pull_request"},
        )

    chat_id = next(iter(adapter._delivery_info))
    await adapter.send(chat_id, "LGTM — looks great")

    assert len(state["completed"]) == 1
    assert state["completed"][0]["conclusion"] == "failure"
    _cleanup_env()


@pytest.mark.asyncio
async def test_feedback_route_uses_suffixed_name_and_neutral():
    _register_fake_app("gpodawund")
    routes = {
        "orange-grove-review": {
            "secret": _INSECURE_NO_AUTH,
            "github_app": "gpodawund",
            "prompt": "hi",
            "deliver": "log",
            "skills": ["github-app-review-feedback"],
        },
    }
    adapter = _adapter_with_routes(routes)
    state = _stub_check_lifecycle(adapter, create_id=888)
    adapter.handle_message = AsyncMock()

    async with TestClient(TestServer(_app(adapter))) as cli:
        await cli.post(
            "/webhooks/orange-grove-review",
            json=_pr_payload(action="closed", merged=True),
            headers={"X-GitHub-Event": "pull_request"},
        )

    assert len(state["created"]) == 1
    assert state["created"][0]["name"] == "orange-grove-review-feedback"

    chat_id = next(iter(adapter._delivery_info))
    await adapter.send(chat_id, "Feedback harvested: 3 reactions collected.")

    assert state["completed"][0]["conclusion"] == "neutral"
    assert state["completed"][0]["title"] == "Feedback harvested"
    _cleanup_env()


def test_classify_review_conclusion_heuristic():
    cls = WebhookAdapter._classify_review_conclusion
    assert cls("")[0] == "failure"
    assert cls(None)[0] == "failure"
    assert cls("Sorry, I encountered an error (X).")[0] == "failure"
    assert cls("Verdict: Changes Requested — see below")[0] == "action_required"
    assert cls("🔴 critical issue")[0] == "action_required"
    assert cls("LGTM 🚀")[0] == "success"
    assert cls("no issues found, ship it")[0] == "success"
    assert cls("0 findings in the diff")[0] == "success"
    assert cls("a few suggestions, nothing blocking")[0] == "neutral"


