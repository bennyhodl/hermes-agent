"""Generic webhook platform adapter.

Runs an aiohttp HTTP server that receives webhook POSTs from external
services (GitHub, GitLab, JIRA, Stripe, etc.), validates HMAC signatures,
transforms payloads into agent prompts, and routes responses back to the
source or to another configured platform.

Configuration lives in config.yaml under platforms.webhook.extra.routes.
Each route defines:
  - events: which event types to accept (header-based filtering)
  - secret: HMAC secret for signature validation (REQUIRED)
  - prompt: template string formatted with the webhook payload
  - skills: optional list of skills to load for the agent
  - deliver: where to send the response (github_comment, telegram, etc.)
  - deliver_extra: additional delivery config (repo, pr_number, chat_id)
  - deliver_only: if true, skip the agent — the rendered prompt IS the
    message that gets delivered.  Use for external push notifications
    (Supabase, monitoring alerts, inter-agent pings) where zero LLM cost
    and sub-second delivery matter more than agent reasoning.

Security:
  - HMAC secret is required per route (validated at startup)
  - Rate limiting per route (fixed-window, configurable)
  - Idempotency cache prevents duplicate agent runs on webhook retries
  - Body size limits checked before reading payload
  - Set secret to "INSECURE_NO_AUTH" to skip validation (testing only)
"""

import asyncio
import datetime as _dt
import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import time
from typing import Any, Dict, List, Optional

try:
    import aiohttp
    from aiohttp import web

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None  # type: ignore[assignment]
    web = None  # type: ignore[assignment]

from gateway.config import Platform, PlatformConfig
from gateway.github_app_auth import (
    GitHubAppAuth,
    get_app as _get_github_app,
    register_apps_from_config as _register_github_apps,
)
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
)
from tools.approval import (
    disable_session_yolo,
    enable_session_yolo,
)
from tools.session_env import (
    clear_session_env_vars,
    set_session_env_vars,
)

logger = logging.getLogger(__name__)

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8644
_INSECURE_NO_AUTH="***"
_DYNAMIC_ROUTES_FILENAME = "webhook_subscriptions.json"
_MISSING = object()  # sentinel for "key absent" in payload filter walking


def check_webhook_requirements() -> bool:
    """Check if webhook adapter dependencies are available."""
    return AIOHTTP_AVAILABLE


class WebhookAdapter(BasePlatformAdapter):
    """Generic webhook receiver that triggers agent runs from HTTP POSTs."""

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.WEBHOOK)
        self._host: str = config.extra.get("host", DEFAULT_HOST)
        self._port: int = int(config.extra.get("port", DEFAULT_PORT))
        self._global_secret: str = config.extra.get("secret", "")
        self._static_routes: Dict[str, dict] = config.extra.get("routes", {})
        self._dynamic_routes: Dict[str, dict] = {}
        self._dynamic_routes_mtime: float = 0.0
        self._routes: Dict[str, dict] = dict(self._static_routes)
        self._runner = None

        # Delivery info keyed by session chat_id.
        #
        # Read by every send() invocation for the chat_id (status messages
        # AND the final response).  Cleaned up via TTL on each POST so the
        # dict stays bounded — see _prune_delivery_info().  Do NOT pop on
        # send(), or interim status messages (e.g. fallback notifications,
        # context-pressure warnings) will consume the entry before the
        # final response arrives, causing the response to silently fall
        # back to the "log" deliver type.
        self._delivery_info: Dict[str, dict] = {}
        self._delivery_info_created: Dict[str, float] = {}

        # Reference to gateway runner for cross-platform delivery (set externally)
        self.gateway_runner = None

        # Idempotency: TTL cache of recently processed delivery IDs.
        # Prevents duplicate agent runs when webhook providers retry.
        self._seen_deliveries: Dict[str, float] = {}
        self._idempotency_ttl: int = 3600  # 1 hour

        # Rate limiting: per-route timestamps in a fixed window.
        self._rate_counts: Dict[str, List[float]] = {}
        self._rate_limit: int = int(config.extra.get("rate_limit", 30))  # per minute

        # Body size limit (auth-before-body pattern)
        self._max_body_bytes: int = int(
            config.extra.get("max_body_bytes", 1_048_576)
        )  # 1MB

        # Lazy-initialised shared aiohttp session for GitHub Check Run calls.
        # Single session lets us reuse the HTTPS connection pool across
        # start/complete pairs instead of paying TLS handshake cost every
        # call. Initialised on first use (from an event-loop context) and
        # closed in disconnect().
        self._http: Optional["aiohttp.ClientSession"] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> bool:
        # Register GitHub Apps from config (safe to call multiple times)
        try:
            n_apps = _register_github_apps(self.config)
            if n_apps:
                logger.info("[webhook] Registered %d GitHub App(s)", n_apps)
        except Exception as e:  # defensive — never block startup
            logger.warning("[webhook] GitHub App registration failed: %s", e)

        # Load agent-created subscriptions before validating
        self._reload_dynamic_routes()

        # Validate routes at startup — secret is required per route
        # (or, for routes bound to a github_app, the app's webhook_secret
        # can supply it — we do the resolution lazily in _resolve_secret()).
        for name, route in self._routes.items():
            if self._resolve_secret(route):
                continue
            raise ValueError(
                f"[webhook] Route '{name}' has no HMAC secret. "
                f"Set 'secret' on the route or globally, or bind it to a "
                f"github_app that has webhook_secret configured. "
                f"For testing without auth, set secret to '{_INSECURE_NO_AUTH}'."
            )

            # deliver_only routes bypass the agent — the POST body becomes a
            # direct push notification via the configured delivery target.
            # Validate up-front so misconfiguration surfaces at startup rather
            # than on the first webhook POST.
            if route.get("deliver_only"):
                deliver = route.get("deliver", "log")
                if not deliver or deliver == "log":
                    raise ValueError(
                        f"[webhook] Route '{name}' has deliver_only=true but "
                        f"deliver is '{deliver}'. Direct delivery requires a "
                        f"real target (telegram, discord, slack, github_comment, etc.)."
                    )

        app = web.Application()
        app.router.add_get("/health", self._handle_health)
        # Multi-match GitHub App fan-out endpoint.  MUST be registered
        # BEFORE the generic single-route handler so aiohttp matches the
        # more specific path first.
        app.router.add_post(
            "/webhooks/app/{app_name}", self._handle_app_webhook
        )
        app.router.add_post("/webhooks/{route_name}", self._handle_webhook)

        # Port conflict detection — fail fast if port is already in use
        import socket as _socket
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as _s:
                _s.settimeout(1)
                _s.connect(('127.0.0.1', self._port))
            logger.error('[webhook] Port %d already in use. Set a different port in config.yaml: platforms.webhook.port', self._port)
            return False
        except (ConnectionRefusedError, OSError):
            pass  # port is free

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._host, self._port)
        await site.start()
        self._mark_connected()

        route_names = ", ".join(self._routes.keys()) or "(none configured)"
        logger.info(
            "[webhook] Listening on %s:%d — routes: %s",
            self._host,
            self._port,
            route_names,
        )
        return True

    async def disconnect(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        if self._http is not None:
            try:
                await self._http.close()
            except Exception as e:  # pragma: no cover - shutdown path
                logger.debug("[webhook] http close error: %s", e)
            self._http = None
        self._mark_disconnected()
        logger.info("[webhook] Disconnected")

    async def _get_http(self) -> "aiohttp.ClientSession":
        """Return the adapter's shared aiohttp session, creating it lazily."""
        if self._http is None or self._http.closed:
            self._http = aiohttp.ClientSession()
        return self._http

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Deliver the agent's response to the configured destination.

        chat_id is ``webhook:{route}:{delivery_id}``.  The delivery info
        stored during webhook receipt is read with ``.get()`` (not popped)
        so that interim status messages emitted before the final response
        — fallback-model notifications, context-pressure warnings, etc. —
        do not consume the entry and silently downgrade the final response
        to the ``log`` deliver type.  TTL cleanup happens on POST.
        """
        delivery = self._delivery_info.get(chat_id, {})
        deliver_type = delivery.get("deliver", "log")

        if deliver_type == "log":
            logger.info("[webhook] Response for %s: %s", chat_id, content[:200])
            await self._finalize_check_from_delivery(delivery, content)
            return SendResult(success=True)

        if deliver_type == "github_comment":
            result = await self._deliver_github_comment(content, delivery)
            if result.success:
                await self._finalize_check_from_delivery(delivery, content)
            else:
                # Delivery failed — still close the check so it doesn't
                # hang at in_progress forever.
                await self._finalize_check_from_delivery(
                    delivery, None  # None → classified as failure
                )
            return result

        # Cross-platform delivery — any platform with a gateway adapter
        if self.gateway_runner and deliver_type in (
            "telegram",
            "discord",
            "slack",
            "signal",
            "sms",
            "whatsapp",
            "matrix",
            "mattermost",
            "homeassistant",
            "email",
            "dingtalk",
            "feishu",
            "wecom",
            "wecom_callback",
            "weixin",
            "bluebubbles",
            "qqbot",
        ):
            result = await self._deliver_cross_platform(
                deliver_type, content, delivery
            )
            if result.success:
                await self._finalize_check_from_delivery(delivery, content)
            return result

        logger.warning("[webhook] Unknown deliver type: %s", deliver_type)
        return SendResult(
            success=False, error=f"Unknown deliver type: {deliver_type}"
        )

    def _prune_delivery_info(self, now: float) -> None:
        """Drop delivery_info entries older than the idempotency TTL.

        Mirrors the cleanup pattern used for ``_seen_deliveries``.  Called
        on each POST so the dict size is bounded by ``rate_limit * TTL``
        even if many webhooks fire and never receive a final response.
        """
        cutoff = now - self._idempotency_ttl
        stale = [
            k
            for k, t in self._delivery_info_created.items()
            if t < cutoff
        ]
        for k in stale:
            self._delivery_info.pop(k, None)
            self._delivery_info_created.pop(k, None)

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {"name": chat_id, "type": "webhook"}

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------

    async def _handle_health(self, request: "web.Request") -> "web.Response":
        """GET /health — simple health check."""
        return web.json_response({"status": "ok", "platform": "webhook"})

    def _reload_dynamic_routes(self) -> None:
        """Reload agent-created subscriptions from disk if the file changed."""
        from hermes_constants import get_hermes_home
        hermes_home = get_hermes_home()
        subs_path = hermes_home / _DYNAMIC_ROUTES_FILENAME
        if not subs_path.exists():
            if self._dynamic_routes:
                self._dynamic_routes = {}
                self._routes = dict(self._static_routes)
                logger.debug("[webhook] Dynamic subscriptions file removed, cleared dynamic routes")
            return
        try:
            mtime = subs_path.stat().st_mtime
            if mtime <= self._dynamic_routes_mtime:
                return  # No change
            data = json.loads(subs_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return
            # Merge: static routes take precedence over dynamic ones
            self._dynamic_routes = {
                k: v for k, v in data.items()
                if k not in self._static_routes
            }
            self._routes = {**self._dynamic_routes, **self._static_routes}
            self._dynamic_routes_mtime = mtime
            logger.info(
                "[webhook] Reloaded %d dynamic route(s): %s",
                len(self._dynamic_routes),
                ", ".join(self._dynamic_routes.keys()) or "(none)",
            )
        except Exception as e:
            logger.error("[webhook] Failed to reload dynamic routes: %s", e)

    async def _handle_webhook(self, request: "web.Request") -> "web.Response":
        """POST /webhooks/{route_name} — receive and process a webhook event."""
        # Hot-reload dynamic subscriptions on each request (mtime-gated, cheap)
        self._reload_dynamic_routes()

        route_name = request.match_info.get("route_name", "")
        route_config = self._routes.get(route_name)

        if not route_config:
            return web.json_response(
                {"error": f"Unknown route: {route_name}"}, status=404
            )

        # ── Auth-before-body ─────────────────────────────────────
        # Check Content-Length before reading the full payload.
        content_length = request.content_length or 0
        if content_length > self._max_body_bytes:
            return web.json_response(
                {"error": "Payload too large"}, status=413
            )

        # Read body (must be done before any validation)
        try:
            raw_body = await request.read()
        except Exception as e:
            logger.error("[webhook] Failed to read body: %s", e)
            return web.json_response({"error": "Bad request"}, status=400)

        # Validate HMAC signature FIRST (skip for INSECURE_NO_AUTH testing mode)
        secret = self._resolve_secret(route_config)
        if secret and secret != _INSECURE_NO_AUTH:
            if not self._validate_signature(request, raw_body, secret):
                logger.warning(
                    "[webhook] Invalid signature for route %s", route_name
                )
                return web.json_response(
                    {"error": "Invalid signature"}, status=401
                )

        # ── Rate limiting (after auth) ───────────────────────────
        now = time.time()
        window = self._rate_counts.setdefault(route_name, [])
        window[:] = [t for t in window if now - t < 60]
        if len(window) >= self._rate_limit:
            return web.json_response(
                {"error": "Rate limit exceeded"}, status=429
            )
        window.append(now)

        # Parse payload
        payload = self._parse_body(raw_body)
        if payload is None:
            return web.json_response(
                {"error": "Cannot parse body"}, status=400
            )

        event_type = self._extract_event_type(request, payload)

        # Dispatch to the single route
        result = await self._dispatch_route(
            route_name=route_name,
            route_config=route_config,
            payload=payload,
            event_type=event_type,
            request=request,
        )
        return web.json_response(result["body"], status=result["status"])

    async def _handle_app_webhook(
        self, request: "web.Request"
    ) -> "web.Response":
        """POST /webhooks/app/{app_name} — multi-match fan-out endpoint.

        One GitHub App webhook URL can target many installations and
        repositories; we iterate every route whose ``github_app``
        matches ``app_name`` and run each matching route in parallel.
        """
        self._reload_dynamic_routes()

        app_name = request.match_info.get("app_name", "")
        app = _get_github_app(app_name)
        if app is None:
            return web.json_response(
                {"error": f"Unknown github_app: {app_name}"}, status=404
            )

        # Body-size pre-check
        content_length = request.content_length or 0
        if content_length > self._max_body_bytes:
            return web.json_response(
                {"error": "Payload too large"}, status=413
            )

        # Rate limit on the app bucket
        now = time.time()
        rl_key = f"__app__:{app_name}"
        window = self._rate_counts.setdefault(rl_key, [])
        window[:] = [t for t in window if now - t < 60]
        if len(window) >= self._rate_limit:
            return web.json_response(
                {"error": "Rate limit exceeded"}, status=429
            )
        window.append(now)

        try:
            raw_body = await request.read()
        except Exception as e:
            logger.error("[webhook] Failed to read body: %s", e)
            return web.json_response({"error": "Bad request"}, status=400)

        # HMAC validation with the app's webhook_secret (shared across
        # all routes bound to this app).  INSECURE_NO_AUTH bypass works
        # when the app has no webhook_secret and is used for local tests.
        secret = app.webhook_secret or ""
        if secret and secret != _INSECURE_NO_AUTH:
            if not self._validate_signature(request, raw_body, secret):
                logger.warning(
                    "[webhook] Invalid signature for app %s", app_name
                )
                return web.json_response(
                    {"error": "Invalid signature"}, status=401
                )

        payload = self._parse_body(raw_body)
        if payload is None:
            return web.json_response(
                {"error": "Cannot parse body"}, status=400
            )

        event_type = self._extract_event_type(request, payload)

        # Gather all routes that belong to this app AND accept this event type.
        # Per-route `events` filter is evaluated here so unrelated event types
        # (push/check_run/etc.) don't spuriously fan out to every route.
        # An empty `events` list on a route means "any event".
        matching = []
        skipped_by_event = []
        for name, cfg in self._routes.items():
            if cfg.get("github_app") != app_name:
                continue
            allowed = cfg.get("events") or []
            if allowed and event_type not in allowed:
                skipped_by_event.append(name)
                continue
            matching.append((name, cfg))

        if not matching:
            if skipped_by_event:
                logger.debug(
                    "[webhook] app=%s event=%s ignored by %d route(s): %s",
                    app_name, event_type, len(skipped_by_event),
                    ", ".join(skipped_by_event),
                )
            return web.json_response(
                {
                    "status": "no_matching_routes",
                    "app": app_name,
                    "event": event_type,
                }
            )

        logger.info(
            "[webhook] app=%s event=%s fan-out to %d route(s): %s",
            app_name,
            event_type,
            len(matching),
            ", ".join(n for n, _ in matching),
        )

        # Dispatch each matching route in parallel.  Each gets its own
        # delivery_id suffix so idempotency is per-(route, delivery).
        tasks = [
            self._dispatch_route(
                route_name=name,
                route_config=cfg,
                payload=payload,
                event_type=event_type,
                request=request,
                delivery_suffix=name,
            )
            for name, cfg in matching
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        summary: List[dict] = []
        for (name, _), res in zip(matching, results):
            if isinstance(res, Exception):
                summary.append({"route": name, "error": str(res)})
            else:
                summary.append({"route": name, **res["body"]})
        return web.json_response(
            {"status": "dispatched", "app": app_name, "routes": summary},
            status=202,
        )

    # ------------------------------------------------------------------
    # Dispatch pipeline (shared by single-match and fan-out handlers)
    # ------------------------------------------------------------------

    def _resolve_secret(self, route_config: dict) -> str:
        """Return the effective HMAC secret for a route.

        Resolution order (first non-empty wins):
          1. ``route.secret``
          2. Bound github_app's ``webhook_secret`` (if any)
          3. The global ``platforms.webhook.secret``
        """
        secret = route_config.get("secret") or ""
        if secret:
            return secret
        app_name = route_config.get("github_app")
        if app_name:
            app = _get_github_app(app_name)
            if app and app.webhook_secret:
                return app.webhook_secret
        return self._global_secret or ""

    @staticmethod
    def _parse_body(raw_body: bytes) -> Optional[dict]:
        try:
            return json.loads(raw_body)
        except json.JSONDecodeError:
            try:
                import urllib.parse

                parsed_dict = dict(
                    urllib.parse.parse_qsl(raw_body.decode("utf-8"))
                )
            except Exception:
                return None
            # GitHub classic webhooks post application/x-www-form-urlencoded
            # with a single ``payload=<json>`` field. Unwrap it so downstream
            # filters see the real payload dict instead of a bare string.
            if "payload" in parsed_dict and isinstance(
                parsed_dict["payload"], str
            ):
                try:
                    unwrapped = json.loads(parsed_dict["payload"])
                    if isinstance(unwrapped, dict):
                        return unwrapped
                except json.JSONDecodeError:
                    pass
            return parsed_dict

    @staticmethod
    def _extract_event_type(request: "web.Request", payload: dict) -> str:
        return (
            request.headers.get("X-GitHub-Event", "")
            or request.headers.get("X-GitLab-Event", "")
            or payload.get("event_type", "")
            or "unknown"
        )

    async def _dispatch_route(
        self,
        *,
        route_name: str,
        route_config: dict,
        payload: dict,
        event_type: str,
        request: "web.Request",
        delivery_suffix: str = "",
    ) -> dict:
        """Evaluate filters, mint tokens, spawn the agent task.

        Returns a dict ``{"status": int, "body": dict}`` suitable for
        the single-match JSON response, or the per-route summary entry
        in the multi-match response.
        """
        # Event filter
        allowed_events = route_config.get("events", [])
        if allowed_events and event_type not in allowed_events:
            logger.debug(
                "[webhook] Ignoring event %s for route %s (allowed: %s)",
                event_type, route_name, allowed_events,
            )
            return {
                "status": 200,
                "body": {"status": "ignored", "event": event_type},
            }

        # Payload filter
        payload_filter = route_config.get("filter", {})
        if payload_filter:
            mismatch = self._filter_mismatch(payload, payload_filter)
            if mismatch is not None:
                key, expected, actual = mismatch
                logger.debug(
                    "[webhook] Filter mismatch for route %s: %s expected=%r actual=%r",
                    route_name, key, expected, actual,
                )
                return {
                    "status": 200,
                    "body": {
                        "status": "filtered",
                        "event": event_type,
                        "mismatch": {
                            "key": key, "expected": expected, "actual": actual,
                        },
                    },
                }

        # GitHub App installation token injection.  We mint BEFORE the
        # agent run so the env is populated when the background task
        # starts; the token is attached to delivery_info and surfaced
        # to tools via a task-scoped environment variable setter
        # (see _inject_github_token_env).
        gh_token: Optional[str] = None
        gh_token_err: Optional[str] = None
        app_name = route_config.get("github_app")
        installation_id = None
        if app_name:
            inst = payload.get("installation") or {}
            installation_id = inst.get("id")
            if installation_id:
                app = _get_github_app(app_name)
                if app is None:
                    gh_token_err = f"github_app '{app_name}' not registered"
                else:
                    gh_token, gh_token_err = await app.get_installation_token(
                        int(installation_id)
                    )
                    if gh_token:
                        logger.info(
                            "[webhook] Minted installation token for "
                            "app=%s installation=%s (prefix=%s…)",
                            app_name, installation_id, gh_token[:6],
                        )
                    else:
                        logger.warning(
                            "[webhook] Could not mint token for app=%s install=%s: %s",
                            app_name, installation_id, gh_token_err,
                        )

        # Prompt rendering
        prompt = self._render_prompt(
            route_config.get("prompt", ""),
            payload, event_type, route_name,
        )

        # Skill injection — stack ALL listed skills, not just the first.
        # Order matters: earlier skills appear first in the prompt. Convention
        # is to list the generic mechanics skill first (e.g. github-app-review),
        # then the repo/context-specific skill (e.g. bitcoin-bay-website-review).
        skills = route_config.get("skills", [])
        if skills:
            try:
                from agent.skill_commands import (
                    build_skill_invocation_message,
                    get_skill_commands,
                )

                skill_cmds = get_skill_commands()
                loaded_parts: list[str] = []
                for skill_name in skills:
                    cmd_key = f"/{skill_name}"
                    if cmd_key not in skill_cmds:
                        logger.warning(
                            "[webhook] Skill '%s' not found", skill_name
                        )
                        continue
                    # Pass user_instruction only to the LAST skill so the
                    # instruction trails the skill stack (standard invocation
                    # shape). Earlier skills get an empty instruction so they
                    # act as pure context prefixes.
                    is_last = skill_name == skills[-1]
                    skill_content = build_skill_invocation_message(
                        cmd_key,
                        user_instruction=prompt if is_last else "",
                    )
                    if skill_content:
                        loaded_parts.append(skill_content)

                if loaded_parts:
                    prompt = "\n\n---\n\n".join(loaded_parts)
            except Exception as e:
                logger.warning("[webhook] Skill loading failed: %s", e)

        # Delivery ID — include route-name suffix for multi-match fanout
        # so each fanned route has a distinct idempotency key.
        base_delivery = request.headers.get(
            "X-GitHub-Delivery",
            request.headers.get(
                "X-Request-ID", str(int(time.time() * 1000))
            ),
        )
        delivery_id = (
            f"{base_delivery}:{delivery_suffix}"
            if delivery_suffix
            else base_delivery
        )

        # Idempotency
        now = time.time()
        self._seen_deliveries = {
            k: v
            for k, v in self._seen_deliveries.items()
            if now - v < self._idempotency_ttl
        }
        if delivery_id in self._seen_deliveries:
            logger.info(
                "[webhook] Skipping duplicate delivery %s", delivery_id
            )
            return {
                "status": 200,
                "body": {"status": "duplicate", "delivery_id": delivery_id},
            }
        self._seen_deliveries[delivery_id] = now

        # ── Direct delivery mode (deliver_only) ─────────────────
        # Skip the agent entirely — the rendered prompt IS the message we
        # deliver.  Use case: external services (Supabase, monitoring,
        # cron jobs, other agents) that need to push a plain notification
        # to a user's chat with zero LLM cost.  Reuses the same HMAC auth,
        # rate limiting, idempotency, and template rendering as agent mode.
        if route_config.get("deliver_only"):
            delivery = {
                "deliver": route_config.get("deliver", "log"),
                "deliver_extra": self._render_delivery_extra(
                    route_config.get("deliver_extra", {}), payload
                ),
                "payload": payload,
            }
            logger.info(
                "[webhook] direct-deliver event=%s route=%s target=%s msg_len=%d delivery=%s",
                event_type,
                route_name,
                delivery["deliver"],
                len(prompt),
                delivery_id,
            )
            try:
                result = await self._direct_deliver(prompt, delivery)
            except Exception:
                logger.exception(
                    "[webhook] direct-deliver failed route=%s delivery=%s",
                    route_name,
                    delivery_id,
                )
                return web.json_response(
                    {"status": "error", "error": "Delivery failed", "delivery_id": delivery_id},
                    status=502,
                )

            if result.success:
                return web.json_response(
                    {
                        "status": "delivered",
                        "route": route_name,
                        "target": delivery["deliver"],
                        "delivery_id": delivery_id,
                    },
                    status=200,
                )
            # Delivery attempted but target rejected it — surface as 502
            # with a generic error (don't leak adapter-level detail).
            logger.warning(
                "[webhook] direct-deliver target rejected route=%s target=%s error=%s",
                route_name,
                delivery["deliver"],
                result.error,
            )
            return web.json_response(
                {"status": "error", "error": "Delivery failed", "delivery_id": delivery_id},
                status=502,
            )

        # Use delivery_id in session key so concurrent webhooks on the
        # same route get independent agent runs (not queued/interrupted).
        session_chat_id = f"webhook:{route_name}:{delivery_id}"

        deliver_config = {
            "deliver": route_config.get("deliver", "log"),
            "deliver_extra": self._render_delivery_extra(
                route_config.get("deliver_extra", {}), payload
            ),
            "payload": payload,
        }
        # Stash token metadata on the delivery record for the agent
        # subprocess / env-injection layer; never logged in full.
        if gh_token:
            deliver_config["gh_token"] = gh_token
            deliver_config["gh_app"] = app_name
            deliver_config["gh_installation_id"] = installation_id

        # ── GitHub Check Run (in-progress) ──────────────────────────────
        # Create a native GitHub check so the PR's "Checks" tab shows a
        # live indicator while the agent runs. Gated on:
        #   - we minted an App token (gh_token present)
        #   - event is a pull_request event
        #   - payload has pull_request.head.sha (targetable ref)
        # Anything else → skip (no error).
        #
        # Feedback routes (merged PR feedback harvest) suffix the check
        # name with "-feedback" so they don't collide with the normal
        # review check, and always complete as ``neutral``.
        pr = payload.get("pull_request") or {}
        head_sha = (pr.get("head") or {}).get("sha") if isinstance(pr, dict) else None
        repo_full_name = (payload.get("repository") or {}).get("full_name", "")
        is_feedback_run = (
            event_type == "pull_request"
            and payload.get("action") == "closed"
            and bool(pr.get("merged"))
            and "github-app-review-feedback" in (route_config.get("skills") or [])
        )
        if (
            gh_token
            and event_type == "pull_request"
            and head_sha
            and repo_full_name
        ):
            check_name = (
                f"{route_name}-feedback" if is_feedback_run else route_name
            )
            if is_feedback_run:
                check_title = "Feedback harvest in progress"
                check_summary = (
                    f"{(app_name or 'Hermes').capitalize()} is harvesting post-merge feedback for this PR."
                )
            else:
                check_title = "Hermes review in progress"
                check_summary = (
                    f"{(app_name or 'Hermes').capitalize()} is reviewing this pull request. See inline "
                    "comments and final summary once complete."
                )
            try:
                check_run_id = await self._start_github_check(
                    gh_token=gh_token,
                    repo_full_name=repo_full_name,
                    head_sha=head_sha,
                    name=check_name,
                    details_url=pr.get("html_url"),
                    title=check_title,
                    summary=check_summary,
                )
                if check_run_id:
                    deliver_config["check_run_id"] = check_run_id
                    deliver_config["check_run_repo"] = repo_full_name
                    deliver_config["check_run_feedback"] = is_feedback_run
            except Exception as e:
                # Defensive: _start_github_check already swallows its
                # own errors, but make doubly sure a check-run hiccup
                # never blocks the agent run.
                logger.warning(
                    "[webhook] _start_github_check raised unexpectedly "
                    "for route %s: %s", route_name, e,
                )
        self._delivery_info[session_chat_id] = deliver_config
        self._delivery_info_created[session_chat_id] = now
        self._prune_delivery_info(now)

        source = self.build_source(
            chat_id=session_chat_id,
            chat_name=f"webhook/{route_name}",
            chat_type="webhook",
            user_id=f"webhook:{route_name}",
            user_name=route_name,
        )
        event = MessageEvent(
            text=prompt,
            message_type=MessageType.TEXT,
            source=source,
            raw_message=payload,
            message_id=delivery_id,
        )

        logger.info(
            "[webhook] %s event=%s route=%s prompt_len=%d delivery=%s gh_token=%s",
            request.method, event_type, route_name, len(prompt),
            delivery_id, "yes" if gh_token else "no",
        )

        async def _run_with_env():
            # Per-session env vars + YOLO latch, both keyed off the unique
            # ``webhook:{route}:{delivery_id}`` session key.  This replaces
            # the old process-global ``os.environ`` mutation, which raced
            # across concurrent installations, and the old
            # ``HERMES_YOLO_MODE`` env latch that leaked across sessions.
            #
            # The approval contextvar (``_approval_session_key``) is set in
            # ``gateway/run.py`` before the agent loop runs, so tool calls
            # executing in executor threads resolve the right session key
            # automatically — see ``tools/session_env.py::get_current_session_env_vars``
            # and ``tools/approval.py::is_current_session_yolo_enabled``.
            auto_approve = bool(route_config.get("auto_approve"))
            if gh_token:
                set_session_env_vars(
                    session_chat_id,
                    {"GH_TOKEN": gh_token, "GITHUB_TOKEN": gh_token},
                )
                logger.info(
                    "[webhook] route=%s GH_TOKEN scoped to session=%s (prefix=%s…)",
                    route_name, session_chat_id, gh_token[:6],
                )
            if auto_approve:
                enable_session_yolo(session_chat_id)
                logger.info(
                    "[webhook] route=%s auto_approve=on (session-scoped YOLO "
                    "enabled for session=%s)",
                    route_name, session_chat_id,
                )
            try:
                await self.handle_message(event)
            finally:
                # Always clean up the session-scoped state. The YOLO latch
                # and env vars only need to live as long as the agent run
                # for this delivery; ``handle_message`` awaits through to
                # completion on the normal path.
                if gh_token:
                    clear_session_env_vars(session_chat_id)
                if auto_approve:
                    disable_session_yolo(session_chat_id)

        task = asyncio.create_task(_run_with_env())
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        body = {
            "status": "accepted",
            "route": route_name,
            "event": event_type,
            "delivery_id": delivery_id,
        }
        if gh_token:
            body["github_app"] = app_name
            body["installation_id"] = installation_id
        elif gh_token_err:
            body["github_app_error"] = gh_token_err
        return {"status": 202, "body": body}

    # ------------------------------------------------------------------
    # Signature validation
    # ------------------------------------------------------------------

    def _validate_signature(
        self, request: "web.Request", body: bytes, secret: str
    ) -> bool:
        """Validate webhook signature (GitHub, GitLab, generic HMAC-SHA256)."""
        # GitHub: X-Hub-Signature-256 = sha256=<hex>
        gh_sig = request.headers.get("X-Hub-Signature-256", "")
        if gh_sig:
            expected = "sha256=" + hmac.new(
                secret.encode(), body, hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(gh_sig, expected)

        # GitLab: X-Gitlab-Token = <plain secret>
        gl_token = request.headers.get("X-Gitlab-Token", "")
        if gl_token:
            return hmac.compare_digest(gl_token, secret)

        # Generic: X-Webhook-Signature = <hex HMAC-SHA256>
        generic_sig = request.headers.get("X-Webhook-Signature", "")
        if generic_sig:
            expected = hmac.new(
                secret.encode(), body, hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(generic_sig, expected)

        # No recognised signature header but secret is configured → reject
        logger.debug(
            "[webhook] Secret configured but no signature header found"
        )
        return False

    # ------------------------------------------------------------------
    # Prompt rendering
    # ------------------------------------------------------------------

    def _render_prompt(
        self,
        template: str,
        payload: dict,
        event_type: str,
        route_name: str,
    ) -> str:
        """Render a prompt template with the webhook payload.

        Supports dot-notation access into nested dicts:
        ``{pull_request.title}`` → ``payload["pull_request"]["title"]``

        Special token ``{__raw__}`` dumps the entire payload as indented
        JSON (truncated to 4000 chars).  Useful for monitoring alerts or
        any webhook where the agent needs to see the full payload.
        """
        if not template:
            truncated = json.dumps(payload, indent=2)[:4000]
            return (
                f"Webhook event '{event_type}' on route "
                f"'{route_name}':\n\n```json\n{truncated}\n```"
            )

        def _resolve(match: re.Match) -> str:
            key = match.group(1)
            # Special token: dump the entire payload as JSON
            if key == "__raw__":
                return json.dumps(payload, indent=2)[:4000]
            value: Any = payload
            for part in key.split("."):
                if isinstance(value, dict):
                    value = value.get(part, f"{{{key}}}")
                else:
                    return f"{{{key}}}"
            if isinstance(value, (dict, list)):
                return json.dumps(value, indent=2)[:2000]
            return str(value)

        return re.sub(r"\{([a-zA-Z0-9_.]+)\}", _resolve, template)

    def _render_delivery_extra(
        self, extra: dict, payload: dict
    ) -> dict:
        """Render delivery_extra template values with payload data."""
        rendered: Dict[str, Any] = {}
        for key, value in extra.items():
            if isinstance(value, str):
                rendered[key] = self._render_prompt(value, payload, "", "")
            else:
                rendered[key] = value
        return rendered

    # ------------------------------------------------------------------
    # Payload filtering
    # ------------------------------------------------------------------

    @staticmethod
    def _get_nested(payload: Any, dotted_key: str) -> Any:
        """Walk a dotted key path through nested dicts. Returns None if
        any segment is missing or a non-dict value is traversed.
        A sentinel tuple is returned for 'missing' so callers can
        distinguish 'key absent' from 'value is literally None'.
        """
        value: Any = payload
        for part in dotted_key.split("."):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return _MISSING
        return value

    @staticmethod
    def _coerce_filter_value(raw: Any) -> Any:
        """Coerce filter values that arrived as strings (from CLI/JSON
        configs) into the JSON scalar they likely represent. Leaves
        non-string values untouched."""
        if not isinstance(raw, str):
            return raw
        lowered = raw.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        if lowered in ("null", "none"):
            return None
        # int / float
        try:
            if lowered.lstrip("-").isdigit():
                return int(raw)
            return float(raw)
        except (ValueError, AttributeError):
            pass
        return raw

    def _filter_mismatch(
        self, payload: dict, filter_dict: dict
    ) -> Optional[tuple]:
        """Return (key, expected, actual) for the first filter entry that
        does not match the payload. Returns None if all entries match.

        Matching semantics:
          - Dot-notation key walks nested dicts (pull_request.base.ref).
          - Expected values from CLI/JSON are coerced: "true"→True,
            "false"→False, "null"→None, numeric strings → int/float.
          - Equality is evaluated on the coerced value first, then falls
            back to stringified comparison so users can write
            ``pull_request.number=42`` against a JSON int without surprise.
        """
        for key, expected_raw in filter_dict.items():
            actual = self._get_nested(payload, key)
            if actual is _MISSING:
                return (key, expected_raw, None)
            expected = self._coerce_filter_value(expected_raw)
            if actual == expected:
                continue
            # Fall back to stringified comparison (handles bool/int edge cases
            # where the config author wrote a string by accident).
            if str(actual).lower() == str(expected_raw).strip().lower():
                continue
            return (key, expected_raw, actual)
        return None

    # ------------------------------------------------------------------
    # Response delivery
    # ------------------------------------------------------------------

    async def _direct_deliver(
        self, content: str, delivery: dict
    ) -> SendResult:
        """Deliver *content* directly without invoking the agent.

        Used by ``deliver_only`` routes: the rendered template becomes the
        literal message body, and we dispatch to the same delivery helpers
        that the agent-mode ``send()`` flow uses.  All target types that
        work in agent mode work here — Telegram, Discord, Slack, GitHub
        PR comments, etc.
        """
        deliver_type = delivery.get("deliver", "log")

        if deliver_type == "log":
            # Shouldn't reach here — startup validation rejects deliver_only
            # with deliver=log — but guard defensively.
            logger.info("[webhook] direct-deliver log-only: %s", content[:200])
            return SendResult(success=True)

        if deliver_type == "github_comment":
            return await self._deliver_github_comment(content, delivery)

        # Fall through to the cross-platform dispatcher, which validates the
        # target name and routes via the gateway runner.
        return await self._deliver_cross_platform(
            deliver_type, content, delivery
        )

    async def _deliver_github_comment(
        self, content: str, delivery: dict
    ) -> SendResult:
        """Post agent response as a GitHub PR/issue comment via ``gh`` CLI.

        repo/pr_number resolution order:
          1. Explicit deliver_extra.repo / pr_number (legacy single-route subs)
          2. Derived from the stashed webhook payload (GitHub App / fan-out mode,
             where repo+PR are dynamic per event). Supports both pull_request
             and issue/issue_comment shapes.
        """
        extra = delivery.get("deliver_extra", {})
        repo = extra.get("repo", "")
        pr_number = extra.get("pr_number", "")

        # Fallback: derive from payload when not explicitly configured.
        # This is the common case for GitHub App mode.
        if not repo or not pr_number:
            payload = delivery.get("payload") or {}
            if not repo:
                repo = (payload.get("repository") or {}).get("full_name", "")
            if not pr_number:
                pr_number = (
                    (payload.get("pull_request") or {}).get("number")
                    or (payload.get("issue") or {}).get("number")
                    or payload.get("number")
                    or ""
                )

        if not repo or not pr_number:
            logger.error(
                "[webhook] github_comment delivery missing repo or pr_number "
                "(no deliver_extra and payload lacks repository.full_name / "
                "pull_request.number / issue.number)"
            )
            return SendResult(
                success=False, error="Missing repo or pr_number"
            )

        # Pull GitHub App installation token off the delivery record
        # (populated by the App-mode fan-out path) and pass it via env so
        # `gh` posts as the App's bot identity instead of whatever local
        # credentials the gateway process happens to have. Without this,
        # `gh` falls back to the gateway user's stored auth and comments
        # land under the WRONG identity.
        gh_token = delivery.get("gh_token")
        gh_env = None
        if gh_token:
            gh_env = {**os.environ, "GH_TOKEN": gh_token, "GITHUB_TOKEN": gh_token}
            # Ensure any pre-existing `gh auth` config isn't preferred over
            # GH_TOKEN. `gh` prioritizes GH_TOKEN over stored auth by design,
            # but being explicit about what identity we expect makes debug
            # logs meaningful.
            logger.debug(
                "[webhook] github_comment using GH_TOKEN (prefix=%s…) "
                "for %s#%s",
                gh_token[:6], repo, pr_number,
            )

        try:
            result = subprocess.run(
                [
                    "gh",
                    "pr",
                    "comment",
                    str(pr_number),
                    "--repo",
                    repo,
                    "--body",
                    content,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                env=gh_env,
            )
            if result.returncode == 0:
                logger.info(
                    "[webhook] Posted comment on %s#%s", repo, pr_number
                )
                return SendResult(success=True)
            else:
                logger.error(
                    "[webhook] gh pr comment failed: %s", result.stderr
                )
                return SendResult(success=False, error=result.stderr)
        except FileNotFoundError:
            logger.error(
                "[webhook] 'gh' CLI not found — install GitHub CLI for "
                "github_comment delivery"
            )
            return SendResult(
                success=False, error="gh CLI not installed"
            )
        except Exception as e:
            logger.error("[webhook] github_comment delivery error: %s", e)
            return SendResult(success=False, error=str(e))

    # ------------------------------------------------------------------
    # GitHub Check Run integration (App-authed PR reviews)
    # ------------------------------------------------------------------

    @staticmethod
    def _iso8601_now() -> str:
        return _dt.datetime.now(tz=_dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    async def _start_github_check(
        self,
        *,
        gh_token: str,
        repo_full_name: str,
        head_sha: str,
        name: str,
        details_url: Optional[str],
        title: str = "Hermes review in progress",
        summary: str = (
            "Hermes is reviewing this pull request. See inline "
            "comments and final summary once complete."
        ),
    ) -> Optional[int]:
        """POST /repos/{owner}/{repo}/check-runs in ``in_progress`` state.

        Returns the Check Run id on success, or None on failure (logged).
        Never raises — a failing check must not block the agent run.
        """
        if not gh_token or not repo_full_name or not head_sha:
            return None
        url = f"https://api.github.com/repos/{repo_full_name}/check-runs"
        body = {
            "name": name,
            "head_sha": head_sha,
            "status": "in_progress",
            "started_at": self._iso8601_now(),
            "output": {"title": title, "summary": summary},
        }
        if details_url:
            body["details_url"] = details_url
        headers = {
            "Authorization": f"Bearer {gh_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hermes-webhook-adapter",
        }
        try:
            session = await self._get_http()
            async with session.post(
                url, json=body, headers=headers, timeout=15
            ) as resp:
                data = await resp.json()
                if resp.status >= 300:
                    logger.warning(
                        "[webhook] Check Run create failed "
                        "(%s): status=%s body=%s",
                        name, resp.status, data,
                    )
                    return None
                check_id = data.get("id")
                logger.info(
                    "[webhook] Created Check Run id=%s name=%s repo=%s",
                    check_id, name, repo_full_name,
                )
                return int(check_id) if check_id else None
        except Exception as e:  # pragma: no cover - network path
            logger.warning(
                "[webhook] Check Run create errored (%s): %s", name, e
            )
            return None

    @staticmethod
    def _classify_review_conclusion(response: Optional[str]) -> tuple:
        """Heuristic mapping of an agent's final-response string to a
        GitHub Check Run ``(conclusion, title)``.

        Simple substring matching. This is intentionally shallow — we can
        replace it with structured output (e.g. a JSON verdict block) once
        the review skill emits one.
        """
        if not response or not response.strip():
            return ("failure", "Review failed")
        text = response
        lowered = text.lower()
        # Gateway base-class error path sends a canned "Sorry, I
        # encountered an error (…)" message when the agent raises.
        # Surface that as a failure conclusion instead of a misleading
        # neutral/suggestions-posted result.
        if "sorry, i encountered an error" in lowered:
            return ("failure", "Review failed")
        # "critical" only counts if it isn't prefixed by a negation like
        # "no critical issues" / "zero critical findings" — otherwise a
        # clean review with that phrase would false-positive action_required.
        has_critical = "critical" in lowered and not any(
            neg in lowered
            for neg in ("no critical", "zero critical", "not critical")
        )
        if (
            "verdict: changes requested" in lowered
            or "🔴" in text
            or has_critical
        ):
            return ("action_required", "Review: changes requested")
        if (
            "lgtm" in lowered
            or "no issues found" in lowered
            or "0 findings" in lowered
        ):
            return ("success", "Review: LGTM")
        return ("neutral", "Review: suggestions posted")

    async def _complete_github_check(
        self,
        *,
        gh_token: str,
        repo_full_name: str,
        check_run_id: int,
        conclusion: str,
        title: str,
        summary: str,
    ) -> bool:
        """PATCH /repos/{owner}/{repo}/check-runs/{id} → completed.

        Returns True on success. Never raises.
        """
        if not gh_token or not repo_full_name or not check_run_id:
            return False
        url = (
            f"https://api.github.com/repos/{repo_full_name}"
            f"/check-runs/{check_run_id}"
        )
        # GitHub caps output.summary at 65535 chars; we stay well under.
        truncated = (summary or "")[:300]
        body = {
            "status": "completed",
            "completed_at": self._iso8601_now(),
            "conclusion": conclusion,
            "output": {"title": title, "summary": truncated or title},
        }
        headers = {
            "Authorization": f"Bearer {gh_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hermes-webhook-adapter",
        }
        try:
            session = await self._get_http()
            async with session.patch(
                url, json=body, headers=headers, timeout=15
            ) as resp:
                if resp.status >= 300:
                    data = await resp.text()
                    logger.warning(
                        "[webhook] Check Run complete failed id=%s "
                        "status=%s body=%s",
                        check_run_id, resp.status, data[:500],
                    )
                    return False
                logger.info(
                    "[webhook] Completed Check Run id=%s "
                    "conclusion=%s",
                    check_run_id, conclusion,
                )
                return True
        except Exception as e:  # pragma: no cover - network path
            logger.warning(
                "[webhook] Check Run complete errored id=%s: %s",
                check_run_id, e,
            )
            return False

    async def _finalize_check_from_delivery(
        self, delivery: dict, response: Optional[str]
    ) -> None:
        """If the delivery has a pending Check Run, complete it based on
        the agent's response. No-op if no check was started.
        """
        check_run_id = delivery.get("check_run_id")
        if not check_run_id:
            return
        gh_token = delivery.get("gh_token")
        repo = delivery.get("check_run_repo")
        if not gh_token or not repo:
            return
        # Feedback-skill routes always report neutral/"Feedback harvested".
        if delivery.get("check_run_feedback"):
            conclusion = "neutral"
            title = "Feedback harvested"
            summary = (response or "Feedback harvested.")[:300]
        else:
            conclusion, title = self._classify_review_conclusion(response)
            summary = (response or "")[:300]
        await self._complete_github_check(
            gh_token=gh_token,
            repo_full_name=repo,
            check_run_id=int(check_run_id),
            conclusion=conclusion,
            title=title,
            summary=summary,
        )
        # Clear so we don't double-complete if send() is called twice
        # (e.g. interim status + final response).
        delivery.pop("check_run_id", None)

    # ------------------------------------------------------------------
    # Cross-platform delivery
    # ------------------------------------------------------------------

    async def _deliver_cross_platform(
        self, platform_name: str, content: str, delivery: dict
    ) -> SendResult:
        """Route response to another platform (telegram, discord, etc.)."""
        if not self.gateway_runner:
            return SendResult(
                success=False,
                error="No gateway runner for cross-platform delivery",
            )

        try:
            target_platform = Platform(platform_name)
        except ValueError:
            return SendResult(
                success=False, error=f"Unknown platform: {platform_name}"
            )

        adapter = self.gateway_runner.adapters.get(target_platform)
        if not adapter:
            return SendResult(
                success=False,
                error=f"Platform {platform_name} not connected",
            )

        # Use home channel if no specific chat_id in deliver_extra
        extra = delivery.get("deliver_extra", {})
        chat_id = extra.get("chat_id", "")
        if not chat_id:
            home = self.gateway_runner.config.get_home_channel(target_platform)
            if home:
                chat_id = home.chat_id
            else:
                return SendResult(
                    success=False,
                    error=f"No chat_id or home channel for {platform_name}",
                )

        # Pass thread_id from deliver_extra so Telegram forum topics work
        metadata = None
        thread_id = extra.get("message_thread_id") or extra.get("thread_id")
        if thread_id:
            metadata = {"thread_id": thread_id}

        return await adapter.send(chat_id, content, metadata=metadata)
