"""Unit tests for gateway.github_app_auth."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

import gateway.github_app_auth as gha


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    """Redirect the file-backed cache to a temp directory."""
    def _fake_cache_dir():
        return tmp_path

    monkeypatch.setattr(gha, "_cache_dir", _fake_cache_dir)
    yield tmp_path


@pytest.fixture
def rsa_pem(tmp_path):
    """Generate a throwaway RSA keypair and write the private key PEM."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_path = tmp_path / "test.pem"
    pem_path.write_bytes(pem)
    os.chmod(pem_path, 0o600)
    return pem_path


@pytest.fixture(autouse=True)
def clean_registry():
    gha.clear_registry()
    yield
    gha.clear_registry()


# ---------------------------------------------------------------------------
# JWT / basic auth
# ---------------------------------------------------------------------------


class TestMintJWT:
    def test_mint_jwt_has_string_iss(self, rsa_pem):
        """PyJWT gotcha: ``iss`` MUST be a string, not int."""
        import jwt as _jwt

        auth = gha.GitHubAppAuth("x", 3432954, str(rsa_pem))
        token, err = auth.mint_jwt()
        assert err is None
        assert token and isinstance(token, str)

        header_and_payload = _jwt.decode(
            token, options={"verify_signature": False}
        )
        assert header_and_payload["iss"] == "3432954"
        assert isinstance(header_and_payload["iss"], str)
        assert header_and_payload["exp"] > header_and_payload["iat"]

    def test_missing_pem(self, tmp_path):
        auth = gha.GitHubAppAuth("x", 1, str(tmp_path / "nope.pem"))
        token, err = auth.mint_jwt()
        assert token is None
        assert "not found" in err.lower()

    def test_bad_pem_contents(self, tmp_path):
        bad = tmp_path / "bad.pem"
        bad.write_text("definitely not a PEM")
        auth = gha.GitHubAppAuth("x", 1, str(bad))
        token, err = auth.mint_jwt()
        assert token is None
        assert "jwt signing failed" in err.lower()


# ---------------------------------------------------------------------------
# Installation token cache & minting
# ---------------------------------------------------------------------------


class TestInstallationTokens:
    def test_token_cache_roundtrip(self, rsa_pem, tmp_cache):
        auth = gha.GitHubAppAuth("demo", 1, str(rsa_pem))
        future = time.time() + 3600
        auth._store_cached_token(42, "ghs_cached", future)
        # Sanity: cache file exists with 0600
        cache_file = tmp_cache / gha._CACHE_FILENAME
        assert cache_file.exists()
        data = json.loads(cache_file.read_text())
        assert data["demo:42"]["token"] == "ghs_cached"
        # Hit
        cached = auth._get_cached_token(42)
        assert cached and cached[0] == "ghs_cached"

    def test_refresh_skew(self, rsa_pem, tmp_cache):
        auth = gha.GitHubAppAuth("demo", 1, str(rsa_pem))
        # expires in 2 minutes → skew is 5 minutes, considered stale
        auth._store_cached_token(42, "ghs_soon", time.time() + 120)
        assert auth._get_cached_token(42) is None

    def test_mint_sync_success(self, rsa_pem, tmp_cache):
        auth = gha.GitHubAppAuth("demo", 1, str(rsa_pem))

        def fake_post(path, bearer):
            assert path.endswith("/access_tokens")
            return (
                {
                    "token": "ghs_new_token_123",
                    "expires_at": "2099-01-01T00:00:00Z",
                },
                None,
            )

        with patch.object(auth, "_http_post", side_effect=fake_post):
            tok, err = auth.get_installation_token_sync(125312125)
        assert err is None
        assert tok == "ghs_new_token_123"
        # Cached for second call
        with patch.object(auth, "_http_post", side_effect=AssertionError("should not call")):
            tok2, _ = auth.get_installation_token_sync(125312125)
        assert tok2 == "ghs_new_token_123"

    def test_mint_404(self, rsa_pem, tmp_cache):
        auth = gha.GitHubAppAuth("demo", 1, str(rsa_pem))
        with patch.object(
            auth, "_http_post",
            return_value=(None, "GitHub API 404 on POST /app/installations/9/access_tokens: "),
        ):
            tok, err = auth.get_installation_token_sync(9)
        assert tok is None
        assert "404" in err

    @pytest.mark.asyncio
    async def test_concurrent_async_mint_dedup(self, rsa_pem, tmp_cache):
        """Two concurrent async callers must only mint one token."""
        auth = gha.GitHubAppAuth("demo", 1, str(rsa_pem))
        call_count = 0

        def fake_mint(_iid):
            nonlocal call_count
            call_count += 1
            time.sleep(0.05)
            return "ghs_only_once", time.time() + 3600, None

        with patch.object(auth, "_mint_installation_token_sync", side_effect=fake_mint):
            results = await asyncio.gather(
                auth.get_installation_token(42),
                auth.get_installation_token(42),
                auth.get_installation_token(42),
            )
        tokens = {t for t, _ in results}
        assert tokens == {"ghs_only_once"}
        assert call_count == 1


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_register_from_dict_config(self, rsa_pem):
        cfg = {
            "extra": {
                "github_apps": {
                    "gpodawund": {
                        "app_id": 3432954,
                        "private_key_path": str(rsa_pem),
                        "webhook_secret": "abc123",
                    }
                }
            }
        }
        n = gha.register_apps_from_config(cfg)
        assert n == 1
        app = gha.get_app("gpodawund")
        assert app is not None
        assert app.app_id == 3432954
        assert app.webhook_secret == "abc123"

    def test_register_skips_bad_entries(self, rsa_pem, caplog):
        cfg = {
            "extra": {
                "github_apps": {
                    "ok": {"app_id": 1, "private_key_path": str(rsa_pem)},
                    "bad_no_id": {"private_key_path": str(rsa_pem)},
                    "bad_type": "not a dict",
                }
            }
        }
        n = gha.register_apps_from_config(cfg)
        assert n == 1
        assert gha.get_app("ok") is not None
        assert gha.get_app("bad_no_id") is None
