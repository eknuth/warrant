"""The scenario seeders and verify, against the running compose stack.

Everything here is destructive on purpose: a scenario reset owns every
repository in `acme`, every non-admin Gitea user, the four support tables, and
every Mailpit message. These tests are the only ones in the suite that call that
reset, and they are marked `integration` so they skip when the stack is absent.

They cover the criteria a unit test cannot: the CLI's seed and verify pass for
both fixtures, a second seed prints the same verify bytes, seeding 01 then 08
leaves no trace of 01, and seeding every fixture takes under thirty seconds.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import httpx
import psycopg
import pytest

from gen.schema import load_all, load_scenario
from gen.seed import seed, seed_all
from gen.verify import render, verify
from scripts.seed_smoke import SeedSettings
from servers.gitea_mcp.forge import GiteaForge
from servers.mail_mcp.mail import MailSettings
from tests.fixtures.auth import require_postgres

pytestmark = pytest.mark.integration

FIXTURES = ("01-issue-injection", "08-quiet-control")
QUIET_MAIL_SUBJECT = "Question about my API key"


@pytest.fixture
def stack(gitea: object) -> Iterator[SeedSettings]:
    """Skip unless Gitea, Postgres, and Mailpit are all reachable."""
    settings = SeedSettings()
    require_postgres(settings)
    mail = MailSettings()
    url = f"{mail.mail_url.rstrip('/')}/api/v1/messages"
    try:
        response = httpx.get(url, timeout=5.0)
    except httpx.HTTPError as error:
        pytest.skip(f"no Mailpit at {mail.mail_url}: {error}")
    if response.status_code != 200:
        pytest.skip(f"Mailpit answered HTTP {response.status_code}")
    yield settings


def _repos(settings: SeedSettings) -> list[str]:
    with httpx.Client(
        base_url=settings.gitea_url.rstrip("/"),
        headers={"Authorization": f"token {settings.gitea_admin_token}"},
        timeout=20.0,
    ) as client:
        response = client.get("/api/v1/orgs/acme/repos", params={"limit": 50})
        response.raise_for_status()
        return sorted(repo["full_name"] for repo in response.json())


def _logins(settings: SeedSettings) -> set[str]:
    with httpx.Client(
        base_url=settings.gitea_url.rstrip("/"),
        headers={"Authorization": f"token {settings.gitea_admin_token}"},
        timeout=20.0,
    ) as client:
        response = client.get("/api/v1/admin/users", params={"limit": 50})
        response.raise_for_status()
        return {user["login"] for user in response.json()}


def _tickets(settings: SeedSettings) -> list[tuple[int, str]]:
    with psycopg.connect(settings.dsn()) as conn:
        return [
            (row[0], row[1])
            for row in conn.execute("SELECT id, subject FROM tickets ORDER BY id").fetchall()
        ]


def _mail_subjects() -> list[str]:
    mail = MailSettings()
    response = httpx.get(f"{mail.mail_url.rstrip('/')}/api/v1/messages", timeout=15.0)
    response.raise_for_status()
    return sorted(item["Subject"] for item in response.json().get("messages") or [])


@pytest.mark.parametrize("scenario_id", FIXTURES)
def test_seed_then_verify_passes(stack: SeedSettings, scenario_id: str) -> None:
    report = seed(load_scenario(scenario_id))

    result = verify(load_scenario(scenario_id))

    print(render(result))
    assert result.ok, render(result)
    assert report.elapsed_s >= 0.0


def test_seeding_twice_prints_identical_verify_bytes(stack: SeedSettings) -> None:
    scenario = load_scenario("08-quiet-control")

    seed(scenario)
    first = render(verify(scenario))
    seed(scenario)
    second = render(verify(scenario))

    assert first == second


def test_seeding_01_then_08_leaves_no_trace_of_01(stack: SeedSettings) -> None:
    seed(load_scenario("01-issue-injection"))

    seed(load_scenario("08-quiet-control"))

    assert _repos(stack) == ["acme/widgets"]
    assert "mallory" not in _logins(stack), "01's external user is still in Gitea"
    assert [subject for _id, subject in _tickets(stack)] == [
        "Confirm which API key is on file and whether it is still active"
    ]
    assert _mail_subjects() == [QUIET_MAIL_SUBJECT]


def test_seeding_every_fixture_prints_a_time_under_thirty_seconds(stack: SeedSettings) -> None:
    scenarios = load_all()

    started = time.monotonic()
    reports = seed_all(scenarios)
    total = time.monotonic() - started

    for report in reports:
        print(f"seeded {report.scenario_id} in {report.elapsed_s:.2f}s")
    print(f"seeded {len(reports)} fixtures in {total:.2f}s")

    assert total < 30.0, f"seeding the fixtures took {total:.2f}s"


async def test_the_injected_issue_is_external_through_the_forge(stack: SeedSettings) -> None:
    """The W12 criterion at the forge layer; the MCP layer is in test_gitea_integration."""
    seed(load_scenario("01-issue-injection"))
    forge = GiteaForge(stack.gitea_url, stack.gitea_admin_token)
    try:
        issue = await forge.get_issue("acme/widgets", 1)
    finally:
        await forge.aclose()

    assert issue.author == "mallory"
    assert issue.source.author_tier == "external"
