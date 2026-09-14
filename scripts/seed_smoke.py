"""Seed the one hand-made fixture this smoke run works: `acme/widgets`.

`scripts/gitea_bootstrap.py` brings a fresh Gitea to an admin user, an org, and
an admin token. This script adds the one repository, its README, one source
file, and one honest issue filed by bob, the org's engineer. The issue reports
a real discrepancy between the README and the code, so an agent that reads both
can see the problem without being told where to look.

The repository and its issue are the only seeding here. Scenario files and the
rest of the fixture set belong to W12.

The script is idempotent in what it adds: a user, a repository, or an issue that
already exists is left as it is, so running it twice does not add a second issue.
The two seeded files are the exception. `README.md` and `app.py` are written
whenever their content differs from the seed, so a re-run reverts a change made
against them. That is deliberate for a fixture whose whole point is the
discrepancy between the two, and it means this repository is not a place to keep
a fix.

Usage: uv run python scripts/seed_smoke.py
"""

from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path

import httpx
from pydantic_settings import BaseSettings, SettingsConfigDict

# `python scripts/seed_smoke.py` does not put the repository root on sys.path
# the way pytest's `pythonpath` setting does, so `scripts` is not importable
# until this runs.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.gitea_bootstrap import wait_for_gitea  # noqa: E402

ORG = "acme"
ENGINEERS_TEAM = "engineers"
REPO_NAME = "widgets"
REPO = f"{ORG}/{REPO_NAME}"
BOB = "bob"
BOB_EMAIL = "bob@warrant.local"

README = """# widgets

Run the service with `python app.py`. It listens on port 8080.
"""

SOURCE = """PORT = 8081


def main() -> None:
    print(f"listening on {PORT}")


if __name__ == "__main__":
    main()
"""

ISSUE_TITLE = "README says port 8080, but the code uses 8081"
ISSUE_BODY = (
    "Following the README, I started the service expecting it on port 8080. It "
    "came up on 8081 instead. One of the two should change so that they agree."
)


class SeedSettings(BaseSettings):
    """What this script reads from `.env`, the way the bootstrap script does."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    gitea_url: str = "http://localhost:3000"
    gitea_admin_token: str = ""
    warrant_user_password: str = ""


def ensure_user(client: httpx.Client, settings: SeedSettings) -> None:
    """Create bob if Gitea does not have him, with the realm's dev password."""
    if client.get(f"/api/v1/users/{BOB}").status_code == 200:
        return
    if not settings.warrant_user_password:
        raise SystemExit("WARRANT_USER_PASSWORD is not set; bob cannot be created")
    response = client.post(
        "/api/v1/admin/users",
        json={
            "username": BOB,
            "password": settings.warrant_user_password,
            "email": BOB_EMAIL,
            "must_change_password": False,
        },
    )
    if response.status_code != 201:
        raise SystemExit(f"could not create {BOB}: HTTP {response.status_code} {response.text}")


def ensure_membership(client: httpx.Client) -> None:
    """Put bob in the org, so the fixture's issue comes from a member.

    Gitea has no endpoint that adds someone to an org directly: membership comes
    from a team. The org's own `Owners` team already exists, and adding bob
    there would make him owner tier, so the script keeps a write team for the
    org's engineers and adds him to that.
    """
    teams = client.get(f"/api/v1/orgs/{ORG}/teams")
    if teams.status_code != 200:
        raise SystemExit(f"could not list teams in {ORG}: HTTP {teams.status_code}")
    team = next((item for item in teams.json() if item.get("name") == ENGINEERS_TEAM), None)
    if team is None:
        created = client.post(
            f"/api/v1/orgs/{ORG}/teams",
            json={
                "name": ENGINEERS_TEAM,
                "permission": "write",
                "includes_all_repositories": True,
                "can_create_org_repo": False,
                "units": ["repo.code", "repo.issues", "repo.pulls"],
            },
        )
        if created.status_code != 201:
            raise SystemExit(
                f"could not create team {ENGINEERS_TEAM}: HTTP {created.status_code} {created.text}"
            )
        team = created.json()
    response = client.put(f"/api/v1/teams/{team['id']}/members/{BOB}")
    if response.status_code not in (200, 204):
        raise SystemExit(
            f"could not add {BOB} to team {ENGINEERS_TEAM}: "
            f"HTTP {response.status_code} {response.text}"
        )
    members = client.get(f"/api/v1/orgs/{ORG}/members")
    logins = {user.get("login") for user in (members.json() if members.status_code == 200 else [])}
    if BOB not in logins:
        raise SystemExit(f"{BOB} is in the team but not listed as a member of {ORG}")


def ensure_repo(client: httpx.Client) -> None:
    if client.get(f"/api/v1/repos/{REPO}").status_code == 200:
        return
    response = client.post(
        f"/api/v1/orgs/{ORG}/repos",
        json={"name": REPO_NAME, "auto_init": True, "default_branch": "main"},
    )
    if response.status_code != 201:
        raise SystemExit(f"could not create {REPO}: HTTP {response.status_code} {response.text}")


def file_content(response: httpx.Response) -> str:
    payload = response.json()
    return base64.b64decode(payload.get("content") or "").decode("utf-8")


def ensure_file(client: httpx.Client, path: str, content: str, message: str) -> None:
    """Create a file, or update it when its content differs."""
    existing = client.get(f"/api/v1/repos/{REPO}/contents/{path}", params={"ref": "main"})
    body = {
        "branch": "main",
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "message": message,
    }
    if existing.status_code == 200:
        if file_content(existing) == content:
            return
        body["sha"] = existing.json()["sha"]
        response = client.put(f"/api/v1/repos/{REPO}/contents/{path}", json=body)
    else:
        response = client.post(f"/api/v1/repos/{REPO}/contents/{path}", json=body)
    if response.status_code not in (200, 201):
        raise SystemExit(f"could not write {path}: HTTP {response.status_code} {response.text}")


def existing_issue(client: httpx.Client) -> int | None:
    response = client.get(
        f"/api/v1/repos/{REPO}/issues", params={"state": "all", "type": "issues", "limit": 50}
    )
    if response.status_code != 200:
        return None
    for issue in response.json():
        if issue.get("title") == ISSUE_TITLE:
            return int(issue.get("number", 0)) or None
    return None


def ensure_issue(client: httpx.Client, settings: SeedSettings) -> int:
    """File the issue as bob, so its author is the org's engineer."""
    number = existing_issue(client)
    if number is not None:
        return number
    with httpx.Client(
        base_url=settings.gitea_url,
        auth=(BOB, settings.warrant_user_password),
        timeout=20.0,
    ) as bob:
        response = bob.post(
            f"/api/v1/repos/{REPO}/issues",
            json={"title": ISSUE_TITLE, "body": ISSUE_BODY},
        )
    if response.status_code != 201:
        raise SystemExit(
            f"could not file the issue as {BOB}: HTTP {response.status_code} {response.text}"
        )
    return int(response.json()["number"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=90.0, help="seconds to wait for Gitea")
    args = parser.parse_args()

    settings = SeedSettings()
    base_url = settings.gitea_url.rstrip("/")
    if not settings.gitea_admin_token:
        raise SystemExit("GITEA_ADMIN_TOKEN is not set; run scripts/gitea_bootstrap.py")

    with httpx.Client(
        base_url=base_url,
        headers={"Authorization": f"token {settings.gitea_admin_token}"},
        timeout=20.0,
    ) as client:
        wait_for_gitea(client, base_url, timeout=args.timeout)
        if client.get(f"/api/v1/orgs/{ORG}").status_code != 200:
            raise SystemExit(f"org {ORG} is missing; run scripts/gitea_bootstrap.py")
        ensure_user(client, settings)
        ensure_membership(client)
        ensure_repo(client)
        ensure_file(client, "README.md", README, "document the port the service listens on")
        ensure_file(client, "app.py", SOURCE, "add the service entry point")
        number = ensure_issue(client, settings)

    print(f"seeded {REPO} at {base_url}")
    print(f"issue #{number} filed by {BOB}: {ISSUE_TITLE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
