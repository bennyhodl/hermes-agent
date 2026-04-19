"""Tests for the `hermes github-app` CLI subcommand."""

from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout, redirect_stderr
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import gateway.github_app_auth as gha
from hermes_cli import github_app as cli


@pytest.fixture(autouse=True)
def clean_registry(tmp_path, monkeypatch):
    gha.clear_registry()
    # Redirect cache to tmp
    monkeypatch.setattr(gha, "_cache_dir", lambda: tmp_path)
    # Stub config loader so no user config contaminates tests
    monkeypatch.setattr(cli, "_load_webhook_extra", lambda: {})
    yield
    gha.clear_registry()


def _register_stub(name="gpodawund", *, installations=None, token="ghs_fake_xyz", pem_path=None):
    auth = gha.GitHubAppAuth(name, 42, str(pem_path) if pem_path else "/nonexistent.pem")

    def _verify():
        return True, None

    def _list():
        return installations or [
            gha.Installation(id=125312125, account_login="bennyhodl", account_type="User"),
        ], None

    def _get_sync(_iid):
        return token, None

    auth.verify_reachable = _verify  # type: ignore[assignment]
    auth.list_installations = _list  # type: ignore[assignment]
    auth.get_installation_token_sync = _get_sync  # type: ignore[assignment]
    gha.register_app(auth)
    return auth


def _run(fn, args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = fn(args)
    return rc, out.getvalue(), err.getvalue()


class TestListCmd:
    def test_list_empty(self):
        rc, out, _ = _run(cli.cmd_list, SimpleNamespace())
        assert rc == 0
        assert "No GitHub Apps" in out

    def test_list_registered(self, tmp_path):
        pem = tmp_path / "x.pem"
        pem.write_text("dummy")
        _register_stub("gpodawund", pem_path=pem)
        rc, out, _ = _run(cli.cmd_list, SimpleNamespace())
        assert rc == 0
        assert "gpodawund" in out
        assert "app_id:" in out
        assert "jwt_reachable:  y" in out


class TestTokenCmd:
    def test_token_single_installation_prints_only_token(self):
        _register_stub("gpodawund", token="ghs_single_inst_token")
        args = SimpleNamespace(app="gpodawund", installation=None)
        rc, out, _ = _run(cli.cmd_token, args)
        assert rc == 0
        assert out.strip() == "ghs_single_inst_token"

    def test_token_explicit_installation(self):
        _register_stub("gpodawund", token="ghs_explicit")
        args = SimpleNamespace(app="gpodawund", installation=125312125)
        rc, out, _ = _run(cli.cmd_token, args)
        assert rc == 0
        assert out.strip() == "ghs_explicit"

    def test_token_ambiguous_multi_installation(self):
        _register_stub(
            "gpodawund",
            installations=[
                gha.Installation(id=1, account_login="a", account_type="User"),
                gha.Installation(id=2, account_login="b", account_type="User"),
            ],
        )
        args = SimpleNamespace(app="gpodawund", installation=None)
        rc, out, err = _run(cli.cmd_token, args)
        assert rc == 1
        assert "pass --installation" in err

    def test_token_unknown_app_exits_2(self):
        args = SimpleNamespace(app="does-not-exist", installation=None)
        with pytest.raises(SystemExit) as exc:
            _run(cli.cmd_token, args)
        assert exc.value.code == 2


class TestInstallationsCmd:
    def test_installations_lists(self):
        _register_stub("gpodawund")
        args = SimpleNamespace(app="gpodawund")
        rc, out, _ = _run(cli.cmd_installations, args)
        assert rc == 0
        assert "id=125312125" in out
        assert "bennyhodl" in out


class TestSetupGitCmd:
    def test_setup_git_dry_run_prints_command(self, monkeypatch):
        _register_stub("gpodawund")
        # Pretend no existing helper
        def fake_run(cmd, **kw):
            class R:
                stdout = ""
                returncode = 0
                stderr = ""
            return R()
        monkeypatch.setattr(cli.subprocess, "run", fake_run)
        monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/bin/hermes")
        args = SimpleNamespace(app="gpodawund", dry_run=True)
        rc, out, _ = _run(cli.cmd_setup_git, args)
        assert rc == 0
        assert "Would run" in out
        assert "hermes github-app token gpodawund" in out

    def test_setup_git_refuses_to_overwrite_foreign_helper(self, monkeypatch):
        _register_stub("gpodawund")

        def fake_run(cmd, **kw):
            class R:
                # existing foreign helper configured
                stdout = "!some-other-helper\n"
                returncode = 0
                stderr = ""
            return R()

        monkeypatch.setattr(cli.subprocess, "run", fake_run)
        args = SimpleNamespace(app="gpodawund", dry_run=False)
        rc, out, err = _run(cli.cmd_setup_git, args)
        assert rc == 1
        assert "existing git credential.helper" in err
