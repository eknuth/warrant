"""Bring a freshly started compose Gitea to the state the stack expects.

`make reset` drops the Gitea volume, so the forge comes back with no users, no
org, and no token. This script is what fills that in, and it is idempotent:

1. Wait for `http://localhost:3000/api/healthz` to answer.
2. Create the admin user with `gitea admin user create` inside the container.
   The password is generated here and never written or printed. It is not a
   credential anything later reads; the API token below is.
3. If `GITEA_ADMIN_TOKEN` in `.env` is absent, empty, or still the angle-bracket
   placeholder from `.env.example`, issue one with `gitea admin user
   generate-access-token --scopes all` and write it to `.env`. A token that is
   already set is kept when Gitea accepts it. `make reset` drops the volume
   while `.env` keeps the old token, so a set-but-refused token is treated as
   stale and replaced: keeping it would leave the stack unable to
   authenticate. Both cases are silent about the value.
4. Create org `acme`, owned by the admin user, through the API. The broad admin
   token that just went into `.env` is the credential Gitea's MCP server holds;
   see servers/gitea_mcp/server.py.

The token is the only secret this script writes, it goes only to `.env`, and it
is never printed. `GITEA_ADMIN_TOKEN` carries the value; the admin login
password is not persisted at all.

Usage: uv run python scripts/gitea_bootstrap.py
"""

from __future__ import annotations

import argparse
import secrets
import subprocess
import sys
import time
from pathlib import Path

import httpx
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = REPO_ROOT / ".env"

ADMIN_USERNAME = "gitea-admin"
ADMIN_EMAIL = "gitea-admin@localhost"
ADMIN_TOKEN_NAME = "warrant-admin"
ORG = "acme"


class BootstrapSettings(BaseSettings):
    """What this script needs from `.env`, read the way compose reads it."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    gitea_url: str = "http://localhost:3000"
    gitea_admin_token: str | None = None


def _is_set(value: str | None) -> bool:
    """Whether a value is a real one rather than absent or a placeholder."""
    if not value:
        return False
    return not (value.startswith("<") and value.endswith(">"))


def _write_env_value(path: Path, name: str, value: str) -> None:
    """Set `name=value` in `.env`, replacing the line if it is there."""
    lines = path.read_text().splitlines() if path.exists() else []
    prefix = f"{name}="
    replaced = False
    updated: list[str] = []
    for line in lines:
        if line.startswith(prefix):
            updated.append(prefix + value)
            replaced = True
        else:
            updated.append(line)
    if not replaced:
        updated.append(prefix + value)
    path.write_text("\n".join(updated) + "\n")


def _run_gitea_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Run one `gitea` subcommand in the compose container.

    `-u git` is required: the CLI refuses to run as root, and `docker compose
    exec` defaults to the container's root user. The `git` user owns the data
    directory the config and SQLite file live in.
    """
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "-u", "git", "gitea", "gitea", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def wait_for_gitea(client: httpx.Client, base_url: str, timeout: float = 90.0) -> None:
    """Block until Gitea answers its health endpoint."""
    deadline = time.monotonic() + timeout
    last: Exception | str = "no attempt made"
    while time.monotonic() < deadline:
        try:
            response = client.get(f"{base_url}/api/healthz")
            if response.status_code == 200:
                return
            last = f"HTTP {response.status_code}"
        except httpx.HTTPError as error:
            last = error
        time.sleep(2)
    raise SystemExit(f"gitea at {base_url} did not become healthy: {last}")


def user_exists(client: httpx.Client, base_url: str, username: str) -> bool:
    return client.get(f"{base_url}/api/v1/users/{username}").status_code == 200


def ensure_admin_user(client: httpx.Client, base_url: str) -> None:
    if user_exists(client, base_url, ADMIN_USERNAME):
        return
    # Generated here, handed to the CLI, and never stored or printed. Nothing
    # reads it later: the API token below is the credential this stack uses, so
    # an unrecorded login password costs nothing.
    password = secrets.token_urlsafe(24)
    result = _run_gitea_cli(
        [
            "admin",
            "user",
            "create",
            "--admin",
            "--username",
            ADMIN_USERNAME,
            "--password",
            password,
            "--email",
            ADMIN_EMAIL,
            "--must-change-password=false",
        ]
    )
    if result.returncode != 0 and not user_exists(client, base_url, ADMIN_USERNAME):
        raise SystemExit(f"could not create admin user {ADMIN_USERNAME!r}: {result.stderr.strip()}")
    del password


def token_works(client: httpx.Client, base_url: str, token: str) -> bool:
    response = client.get(
        f"{base_url}/api/v1/user",
        headers={"Authorization": f"token {token}"},
    )
    return response.status_code == 200


def issue_token(base_url: str) -> str:
    """Mint a broad admin token through the container's own CLI."""
    result = _run_gitea_cli(
        [
            "admin",
            "user",
            "generate-access-token",
            "--username",
            ADMIN_USERNAME,
            "--token-name",
            ADMIN_TOKEN_NAME,
            "--scopes",
            "all",
            "--raw",
        ]
    )
    token = result.stdout.strip()
    if result.returncode != 0 or not token:
        # Never echo stdout: on success it is the token.
        detail = result.stderr.strip() or "no token on stdout"
        raise SystemExit(f"could not mint an admin token for {ADMIN_USERNAME!r}: {detail}")
    return token


def ensure_token(
    client: httpx.Client, base_url: str, settings: BootstrapSettings
) -> tuple[str, bool]:
    """Return the admin token and whether this run wrote it to `.env`."""
    existing = settings.gitea_admin_token
    if _is_set(existing) and token_works(client, base_url, existing or ""):
        return existing or "", False
    token = issue_token(base_url)
    if not token_works(client, base_url, token):
        raise SystemExit("the freshly minted admin token was refused by gitea")
    _write_env_value(ENV_FILE, "GITEA_ADMIN_TOKEN", token)
    return token, True


def ensure_org(client: httpx.Client, base_url: str, token: str) -> None:
    """Create org `acme`, owned by the admin user.

    Gitea 1.24's `CreateOrgOption` carries the org name in `username`; there is
    no `org` field on the running build's schema, so posting `org` is a 422. The
    existence check comes first and the result is confirmed afterwards, because
    a 422 is also what a bad body returns and treating it as success is how the
    org ended up missing while this script reported it created.
    """
    headers = {"Authorization": f"token {token}"}
    if client.get(f"{base_url}/api/v1/orgs/{ORG}", headers=headers).status_code == 200:
        return
    response = client.post(
        f"{base_url}/api/v1/orgs",
        headers=headers,
        json={"username": ORG},
    )
    confirmed = client.get(f"{base_url}/api/v1/orgs/{ORG}", headers=headers).status_code == 200
    if not confirmed:
        raise SystemExit(
            f"could not create org {ORG!r}: HTTP {response.status_code} {response.text.strip()}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--timeout",
        type=float,
        default=90.0,
        help="seconds to wait for Gitea's health endpoint",
    )
    args = parser.parse_args()

    settings = BootstrapSettings()
    base_url = settings.gitea_url.rstrip("/")

    with httpx.Client(timeout=15.0, follow_redirects=True) as client:
        wait_for_gitea(client, base_url, timeout=args.timeout)
        ensure_admin_user(client, base_url)
        token, wrote_token = ensure_token(client, base_url, settings)
        ensure_org(client, base_url, token)

    # A summary that proves the state without carrying the secret.
    print(f"gitea ready at {base_url}")
    print(f"admin user: {ADMIN_USERNAME}")
    print(f"org: {ORG}")
    if wrote_token:
        print(f"GITEA_ADMIN_TOKEN: written to {ENV_FILE} (value not shown)")
    else:
        print(f"GITEA_ADMIN_TOKEN: kept the value already in {ENV_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
