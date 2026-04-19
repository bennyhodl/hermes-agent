"""GitHub App authentication helper.

Mints RS256 JWTs from an App ID + PEM private key, exchanges them for
installation access tokens via the GitHub REST API, and caches the
results in a file-backed TTL cache so the webhook adapter, CLI, and
git credential helpers all share one source of truth.

Design notes
------------
- Cache file: ``~/.hermes/cache/github-app-tokens.json`` (mode 0600).
- Cache key: ``"{app_name}:{installation_id}"``.
- Tokens are refreshed when fewer than 5 minutes remain.
- Concurrent callers are deduped via an asyncio.Lock per-app;
  synchronous callers (CLI) use a threading.Lock fallback.
- All error paths return ``(None, error_message)`` rather than
  raising, so webhook handlers never crash on a bad app config.

PyJWT gotcha
------------
PyJWT silently encodes integer claims as JSON numbers.  GitHub's
``/app/installations/...`` endpoint rejects the JWT with
``"'iss' claim must be a String"`` when ``iss`` is sent as a number,
so we explicitly stringify ``app_id`` before passing it to
``jwt.encode``.  This is surprising enough that multiple public
issues have been filed against PyJWT about it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import jwt  # PyJWT
    _JWT_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only on broken install
    _JWT_AVAILABLE = False
    jwt = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_CACHE_FILENAME = "github-app-tokens.json"
_REFRESH_SKEW_SECS = 5 * 60  # refresh when < 5 min remain
_JWT_LIFETIME_SECS = 9 * 60  # GitHub allows up to 10min; keep slack


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def _cache_dir() -> Path:
    """Return (and create) the hermes cache directory."""
    try:
        from hermes_constants import get_hermes_home

        home = get_hermes_home()
    except Exception:
        home = Path.home() / ".hermes"
    cache_dir = home / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _cache_path() -> Path:
    return _cache_dir() / _CACHE_FILENAME


def _read_cache() -> Dict[str, dict]:
    path = _cache_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.warning("[github-app] Could not read token cache: %s", e)
        return {}


def _write_cache(data: Dict[str, dict]) -> None:
    path = _cache_path()
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(str(tmp), str(path))
    except Exception as e:
        logger.warning("[github-app] Could not write token cache: %s", e)


# ---------------------------------------------------------------------------
# GitHubAppAuth
# ---------------------------------------------------------------------------


@dataclass
class Installation:
    id: int
    account_login: str
    account_type: str
    repositories_count: Optional[int] = None


class GitHubAppAuth:
    """Authenticate as a GitHub App and mint installation tokens.

    Every method that talks to GitHub returns ``(value, error)``
    tuples; uncaught exceptions are converted to error strings before
    propagating so callers can make clean decisions.
    """

    GITHUB_API = "https://api.github.com"

    def __init__(
        self,
        name: str,
        app_id: int,
        private_key_path: str,
        webhook_secret: Optional[str] = None,
    ) -> None:
        self.name = name
        self.app_id = int(app_id)
        self.private_key_path = os.path.expanduser(private_key_path)
        self.webhook_secret = webhook_secret or None
        self._async_lock = asyncio.Lock()
        self._thread_lock = threading.Lock()

    # ---- JWT -----------------------------------------------------------

    def _load_pem(self) -> Tuple[Optional[bytes], Optional[str]]:
        path = self.private_key_path
        if not os.path.exists(path):
            return None, f"Private key not found: {path}"
        try:
            with open(path, "rb") as fp:
                return fp.read(), None
        except PermissionError:
            return None, f"Private key not readable (check permissions): {path}"
        except OSError as e:
            return None, f"Could not read private key {path}: {e}"

    def mint_jwt(self) -> Tuple[Optional[str], Optional[str]]:
        """Mint a short-lived RS256 JWT for the App."""
        if not _JWT_AVAILABLE:
            return None, "PyJWT is not installed (pip install 'PyJWT[crypto]')"

        pem, err = self._load_pem()
        if err:
            return None, err
        assert pem is not None

        now = int(time.time())
        payload = {
            "iat": now - 60,  # account for clock skew
            "exp": now + _JWT_LIFETIME_SECS,
            # PyJWT gotcha: ``iss`` MUST be a string — GitHub rejects
            # JSON numeric ``iss`` values with "'iss' claim must be a String".
            "iss": str(self.app_id),
        }
        try:
            token = jwt.encode(payload, pem, algorithm="RS256")
        except Exception as e:  # cryptography errors, bad key, ...
            return None, f"JWT signing failed: {e}"

        # PyJWT < 2 returned bytes; 2.x returns str.  Normalise.
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return token, None

    # ---- HTTP helpers --------------------------------------------------

    def _http_get(
        self, path: str, bearer: str
    ) -> Tuple[Optional[Any], Optional[str]]:
        return self._http_request("GET", path, bearer)

    def _http_post(
        self, path: str, bearer: str
    ) -> Tuple[Optional[Any], Optional[str]]:
        return self._http_request("POST", path, bearer)

    def _http_request(
        self, method: str, path: str, bearer: str
    ) -> Tuple[Optional[Any], Optional[str]]:
        """Minimal synchronous HTTP call via urllib to avoid
        dragging in aiohttp on the CLI side."""
        import urllib.error
        import urllib.request

        url = f"{self.GITHUB_API}{path}"
        req = urllib.request.Request(url, method=method)
        req.add_header("Authorization", f"Bearer {bearer}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", f"hermes-github-app/{self.name}")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = resp.read().decode("utf-8") or "{}"
                try:
                    return json.loads(body), None
                except json.JSONDecodeError:
                    return body, None
        except urllib.error.HTTPError as e:
            try:
                detail = e.read().decode("utf-8", errors="replace")[:400]
            except Exception:
                detail = ""
            return None, f"GitHub API {e.code} on {method} {path}: {detail}"
        except urllib.error.URLError as e:
            return None, f"Network error on {method} {path}: {e.reason}"
        except Exception as e:  # pragma: no cover - belt & braces
            return None, f"Unexpected error on {method} {path}: {e}"

    # ---- Installation tokens ------------------------------------------

    def _cache_key(self, installation_id: int) -> str:
        return f"{self.name}:{installation_id}"

    def _get_cached_token(
        self, installation_id: int
    ) -> Optional[Tuple[str, float]]:
        cache = _read_cache()
        entry = cache.get(self._cache_key(installation_id))
        if not entry:
            return None
        token = entry.get("token")
        exp = entry.get("expires_at", 0)
        if not token or not exp:
            return None
        if exp - time.time() < _REFRESH_SKEW_SECS:
            return None  # too close to expiry
        return token, float(exp)

    def _store_cached_token(
        self, installation_id: int, token: str, expires_at: float
    ) -> None:
        cache = _read_cache()
        cache[self._cache_key(installation_id)] = {
            "token": token,
            "expires_at": expires_at,
            "app": self.name,
            "installation_id": installation_id,
            "minted_at": time.time(),
        }
        _write_cache(cache)

    def _mint_installation_token_sync(
        self, installation_id: int
    ) -> Tuple[Optional[str], Optional[float], Optional[str]]:
        jwt_token, err = self.mint_jwt()
        if err or not jwt_token:
            return None, None, err

        data, err = self._http_post(
            f"/app/installations/{installation_id}/access_tokens", jwt_token
        )
        if err:
            return None, None, err
        if not isinstance(data, dict):
            return None, None, f"Unexpected response: {data!r}"

        token = data.get("token")
        expires_at_raw = data.get("expires_at")
        if not token or not expires_at_raw:
            return None, None, f"Malformed token response: {data}"

        # "2024-01-01T12:00:00Z" — GitHub returns UTC; use calendar.timegm
        # to convert the naive UTC struct_time to a POSIX timestamp without
        # being influenced by the local timezone.
        try:
            import calendar
            from datetime import datetime

            exp_dt = datetime.strptime(expires_at_raw, "%Y-%m-%dT%H:%M:%SZ")
            expires_at = calendar.timegm(exp_dt.timetuple())
        except Exception as e:
            logger.warning(
                "Failed to parse installation token expires_at=%r: %s; "
                "falling back to +1h",
                expires_at_raw, e,
            )
            expires_at = time.time() + 3600  # default GitHub TTL

        return token, float(expires_at), None

    def get_installation_token_sync(
        self, installation_id: int
    ) -> Tuple[Optional[str], Optional[str]]:
        """Blocking token fetch — CLI / credential-helper entry point."""
        with self._thread_lock:
            cached = self._get_cached_token(installation_id)
            if cached:
                return cached[0], None
            token, exp, err = self._mint_installation_token_sync(
                installation_id
            )
            if err or not token or not exp:
                return None, err or "Unknown error minting token"
            self._store_cached_token(installation_id, token, exp)
            return token, None

    async def get_installation_token(
        self, installation_id: int
    ) -> Tuple[Optional[str], Optional[str]]:
        """Async token fetch — webhook adapter entry point.

        Uses an asyncio.Lock keyed by this app so concurrent webhook
        hits for the same installation don't all race to mint.
        """
        # Fast path: cache hit without lock.
        cached = self._get_cached_token(installation_id)
        if cached:
            return cached[0], None
        async with self._async_lock:
            cached = self._get_cached_token(installation_id)
            if cached:
                return cached[0], None
            loop = asyncio.get_running_loop()
            token, exp, err = await loop.run_in_executor(
                None, self._mint_installation_token_sync, installation_id
            )
            if err or not token or not exp:
                return None, err or "Unknown error minting token"
            self._store_cached_token(installation_id, token, exp)
            return token, None

    # ---- Introspection -------------------------------------------------

    def list_installations(
        self,
    ) -> Tuple[Optional[List[Installation]], Optional[str]]:
        jwt_token, err = self.mint_jwt()
        if err or not jwt_token:
            return None, err
        data, err = self._http_get("/app/installations", jwt_token)
        if err:
            return None, err
        if not isinstance(data, list):
            return None, f"Unexpected installations response: {data!r}"
        out: List[Installation] = []
        for entry in data:
            acct = entry.get("account") or {}
            out.append(
                Installation(
                    id=int(entry.get("id", 0)),
                    account_login=str(acct.get("login", "")),
                    account_type=str(acct.get("type", "")),
                    repositories_count=entry.get("repositories_count"),
                )
            )
        return out, None

    def verify_reachable(self) -> Tuple[bool, Optional[str]]:
        """Mint a JWT and confirm GitHub accepts it (GET /app)."""
        jwt_token, err = self.mint_jwt()
        if err or not jwt_token:
            return False, err
        _, err = self._http_get("/app", jwt_token)
        if err:
            return False, err
        return True, None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


_REGISTRY: Dict[str, GitHubAppAuth] = {}


def register_app(auth: GitHubAppAuth) -> None:
    _REGISTRY[auth.name] = auth


def get_app(name: str) -> Optional[GitHubAppAuth]:
    return _REGISTRY.get(name)


def all_apps() -> Dict[str, GitHubAppAuth]:
    return dict(_REGISTRY)


def clear_registry() -> None:
    """Test helper."""
    _REGISTRY.clear()


def register_apps_from_config(cfg: Any) -> int:
    """Register apps from a webhook platform config (or the raw
    ``github_apps`` dict).

    Accepts any of:
      - a ``PlatformConfig``-like object with ``.extra``
      - a dict with ``extra.github_apps`` or ``github_apps`` keys
      - the ``github_apps`` mapping directly

    Returns the number of apps registered.  Never raises — bad
    entries are logged and skipped.
    """
    apps_dict: Dict[str, Any] = {}

    if hasattr(cfg, "extra") and isinstance(getattr(cfg, "extra"), dict):
        apps_dict = cfg.extra.get("github_apps") or {}
    elif isinstance(cfg, dict):
        if "github_apps" in cfg and isinstance(cfg["github_apps"], dict):
            apps_dict = cfg["github_apps"]
        elif "extra" in cfg and isinstance(cfg.get("extra"), dict):
            apps_dict = cfg["extra"].get("github_apps") or {}

    count = 0
    for name, entry in (apps_dict or {}).items():
        if not isinstance(entry, dict):
            logger.warning(
                "[github-app] Skipping app %r: not a mapping", name
            )
            continue
        try:
            app_id = int(entry.get("app_id") or 0)
        except (TypeError, ValueError):
            logger.warning(
                "[github-app] Skipping app %r: app_id must be int", name
            )
            continue
        pem = entry.get("private_key_path") or ""
        if not app_id or not pem:
            logger.warning(
                "[github-app] Skipping app %r: missing app_id or private_key_path",
                name,
            )
            continue
        auth = GitHubAppAuth(
            name=name,
            app_id=app_id,
            private_key_path=pem,
            webhook_secret=entry.get("webhook_secret"),
        )
        register_app(auth)
        count += 1
        logger.info(
            "[github-app] Registered app %s (app_id=%d, pem=%s)",
            name,
            app_id,
            os.path.expanduser(pem),
        )
    return count
