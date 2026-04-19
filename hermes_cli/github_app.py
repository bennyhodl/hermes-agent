"""`hermes github-app` subcommand.

Provides a thin CLI around :mod:`gateway.github_app_auth`:

    hermes github-app list
    hermes github-app installations <app>
    hermes github-app token <app> [--installation ID]
    hermes github-app setup-git [app]

All commands share the same file-backed token cache as the webhook
adapter so minted tokens are reused everywhere.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

from gateway.github_app_auth import (
    GitHubAppAuth,
    all_apps,
    get_app,
    register_apps_from_config,
)


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _load_webhook_extra() -> dict:
    """Return ``platforms.webhook.extra`` from user config (or {})."""
    try:
        from hermes_cli.config import load_config

        cfg = load_config() or {}
        wh = (cfg.get("platforms") or {}).get("webhook") or {}
        return wh.get("extra") or {}
    except Exception:
        return {}


def _ensure_apps_registered() -> int:
    """Load apps from config; idempotent — safe to call repeatedly."""
    extra = _load_webhook_extra()
    return register_apps_from_config({"extra": extra})


def _get_app_or_die(name: str) -> GitHubAppAuth:
    _ensure_apps_registered()
    app = get_app(name)
    if not app:
        configured = ", ".join(sorted(all_apps().keys())) or "(none)"
        print(
            f"Error: GitHub App '{name}' is not configured. "
            f"Known apps: {configured}",
            file=sys.stderr,
        )
        sys.exit(2)
    return app


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def cmd_list(_args) -> int:
    n = _ensure_apps_registered()
    apps = all_apps()
    if not apps:
        print("No GitHub Apps configured in ~/.hermes/config.yaml.")
        print(
            "Add a block under platforms.webhook.extra.github_apps. "
            "Run 'hermes github-app --help' for details."
        )
        return 0
    print(f"\n  {n} GitHub App(s) configured:\n")
    for name, app in apps.items():
        pem_exists = os.path.exists(app.private_key_path)
        reachable, err = (False, "not checked")
        if pem_exists:
            reachable, err = app.verify_reachable()
        installs_n = "?"
        if reachable:
            installs, lerr = app.list_installations()
            installs_n = str(len(installs)) if installs is not None else f"err: {lerr}"
        print(f"  ◆ {name}")
        print(f"    app_id:         {app.app_id}")
        print(f"    private_key:    {app.private_key_path}  ({'y' if pem_exists else 'n'})")
        print(f"    jwt_reachable:  {'y' if reachable else 'n'}" + ("" if reachable else f"  ({err})"))
        print(f"    installations:  {installs_n}")
        print(f"    webhook_secret: {'set' if app.webhook_secret else 'unset'}")
        print()
    return 0


def cmd_installations(args) -> int:
    app = _get_app_or_die(args.app)
    installs, err = app.list_installations()
    if err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    if not installs:
        print(f"No installations found for {app.name}.")
        return 0
    print(f"\n  {len(installs)} installation(s) for {app.name}:\n")
    for inst in installs:
        print(f"  ◆ id={inst.id}")
        print(f"    account: {inst.account_login} ({inst.account_type})")
        if inst.repositories_count is not None:
            print(f"    repos:   {inst.repositories_count}")
        print()
    return 0


def cmd_token(args) -> int:
    app = _get_app_or_die(args.app)
    installation_id = args.installation
    if installation_id is None:
        installs, err = app.list_installations()
        if err:
            print(f"Error: {err}", file=sys.stderr)
            return 1
        if not installs:
            print(f"Error: no installations for {app.name}", file=sys.stderr)
            return 1
        if len(installs) > 1:
            print(
                f"Error: {app.name} has {len(installs)} installations — "
                f"pass --installation ID to pick one.",
                file=sys.stderr,
            )
            for inst in installs:
                print(
                    f"  id={inst.id}  account={inst.account_login}",
                    file=sys.stderr,
                )
            return 1
        installation_id = installs[0].id
    token, err = app.get_installation_token_sync(int(installation_id))
    if err or not token:
        print(f"Error: {err or 'no token'}", file=sys.stderr)
        return 1
    # Print JUST the token — intended for $(...) and credential helpers.
    print(token)
    return 0


# ---------------------------------------------------------------------------
# Git credential helper
# ---------------------------------------------------------------------------


_HELPER_PREFIX = "!f() { "
_HELPER_MARKER = "# hermes-github-app"


def _build_helper_script(app_name: str) -> str:
    """Return the git credential helper shell snippet for *app_name*.

    Git runs ``<helper> get`` and reads ``username=`` / ``password=``
    from stdout.  We delegate to ``hermes github-app token`` for a
    fresh installation token every time — GitHub requires ``x-access-token``
    as the username when authenticating with installation tokens.
    """
    # Use absolute path to hermes if available, fall back to PATH lookup.
    hermes_bin = shutil.which("hermes") or "hermes"
    script = (
        f"!f() {{ "
        f"test \"$1\" = get || exit 0; "
        f"echo username=x-access-token; "
        f"echo \"password=$({hermes_bin} github-app token {app_name})\"; "
        f"}}; f {_HELPER_MARKER} {app_name}"
    )
    return script


def cmd_setup_git(args) -> int:
    # Require an explicit app name when multiple apps are configured; auto-pick
    # when there's only one.
    app_name = args.app
    if not app_name:
        _ensure_apps_registered()
        configured = sorted(all_apps().keys())
        if len(configured) == 1:
            app_name = configured[0]
        elif not configured:
            print(
                "Error: no GitHub Apps configured. Add one under "
                "platforms.webhook.extra.github_apps in ~/.hermes/config.yaml.",
                file=sys.stderr,
            )
            return 2
        else:
            print(
                "Error: multiple GitHub Apps configured "
                f"({', '.join(configured)}). Pass the app name explicitly: "
                "hermes github-app setup-git <app>",
                file=sys.stderr,
            )
            return 2
    app = _get_app_or_die(app_name)

    # Detect any existing credential helper for github.com
    try:
        existing = subprocess.run(
            ["git", "config", "--global", "--get-all", "credential.https://github.com.helper"],
            capture_output=True, text=True, check=False,
        )
        existing_helpers = [
            line for line in (existing.stdout or "").splitlines() if line.strip()
        ]
    except FileNotFoundError:
        print("Error: git is not installed.", file=sys.stderr)
        return 1

    ours = _build_helper_script(app.name)

    # Idempotent: if our helper is already there unchanged, report and exit.
    if any(_HELPER_MARKER in h and app.name in h for h in existing_helpers):
        print(
            f"Already configured: credential.https://github.com.helper "
            f"→ hermes github-app token {app.name}"
        )
        return 0

    # Refuse to silently overwrite a foreign helper.
    foreign = [h for h in existing_helpers if _HELPER_MARKER not in h]
    if foreign:
        print(
            "Error: existing git credential.helper for github.com detected:",
            file=sys.stderr,
        )
        for h in foreign:
            print(f"  {h}", file=sys.stderr)
        print(
            "\nRefusing to overwrite.  Remove the existing helper first:",
            file=sys.stderr,
        )
        print(
            "  git config --global --unset-all credential.https://github.com.helper",
            file=sys.stderr,
        )
        return 1

    if args.dry_run:
        print("Would run:")
        print(
            "  git config --global --replace-all "
            f"credential.https://github.com.helper '{ours}'"
        )
        return 0

    # Back up current global git config before mutating
    gitconfig = Path.home() / ".gitconfig"
    if gitconfig.exists():
        backup = gitconfig.with_suffix(".gitconfig.hermes-backup")
        if not backup.exists():
            backup.write_bytes(gitconfig.read_bytes())
            print(f"Backed up {gitconfig} → {backup}")

    subprocess.run(
        [
            "git", "config", "--global", "--replace-all",
            "credential.https://github.com.helper", ours,
        ],
        check=True,
    )
    # Optionally also set useHttpPath so the helper is invoked for
    # every github.com URL uniformly (it defaults to false which is
    # fine — scope is the host anyway).
    print(
        f"Configured git credential helper for github.com → "
        f"hermes github-app token {app.name}"
    )
    print("Verify:  git config --global --get-all credential.https://github.com.helper")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def github_app_command(args) -> int:
    action = getattr(args, "github_app_action", None)
    if action == "list":
        return cmd_list(args)
    if action == "installations":
        return cmd_installations(args)
    if action == "token":
        return cmd_token(args)
    if action == "setup-git":
        return cmd_setup_git(args)
    print(
        "Usage: hermes github-app {list|installations|token|setup-git}\n"
        "Run 'hermes github-app --help' for details.",
        file=sys.stderr,
    )
    return 2
