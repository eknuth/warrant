"""GitHub-backed tests against a real throwaway org.

Every test here is marked `integration` and skips when `GITHUB_ADMIN_TOKEN` is
not set, so `make test` is green on a clean checkout and the suite runs
unchanged the day the org and the tokens land.

Nothing in this file creates a GitHub org or a user: GitHub does that only
through its web UI, and the two throwaway accounts are Ed's. The tests create
repositories, files, issues, and comments inside the org that already exists,
and the reset test deletes them again. The org is throwaway by design.
"""

from __future__ import annotations

import pytest

from evals.state import GitHubAdmin, read_forge_effects
from gen.schema import load_scenario
from gen.seed import github_admin_client, reset_github, seed
from scripts.seed_smoke import SeedSettings
from servers.gitea_mcp.forge_github import GitHubForge

pytestmark = pytest.mark.integration


def github_seed_settings() -> SeedSettings:
    """The seeder's settings, forced onto the GitHub path.

    Missing `GITHUB_ADMIN_TOKEN` skips: the whole file is about the live org,
    and the acceptance criterion says the skip is on that variable. A set token
    whose org or members are missing fails on the request, which is a finding.
    """
    settings = SeedSettings()
    if not settings.github_admin_token:
        pytest.skip("GITHUB_ADMIN_TOKEN is not set; the GitHub path has not been exercised")
    return settings.model_copy(update={"forge": "github"})


@pytest.fixture(scope="module")
def github_settings() -> SeedSettings:
    return github_seed_settings()


@pytest.fixture
async def forge(github_settings: SeedSettings):
    instance = GitHubForge(github_settings.github_org, github_settings.github_admin_token)
    try:
        yield instance
    finally:
        await instance.aclose()


def test_reset_leaves_the_org_with_zero_repos(github_settings: SeedSettings) -> None:
    """The acceptance criterion: after reset, the org lists no repositories."""
    with github_admin_client(github_settings) as client:
        reset_github(client, github_settings.github_org)

    with github_admin_client(github_settings) as client:
        response = client.get(f"/orgs/{github_settings.github_org}/repos", params={"per_page": 100})
        assert response.status_code == 200, response.text
        assert response.json() == []


async def test_scenario_01_tiers_read_back_from_github(
    github_settings: SeedSettings, forge: GitHubForge
) -> None:
    """The injected issue is external and the honest author is this org's owner.

    The scenario's honest role is `bob`, which on GitHub is the account in
    `GITHUB_MEMBER_USER`. On this org that account owns it, so the tier the
    forge resolves is `owner`, not the Gitea fixture's `member`. The external
    account has no org relationship and resolves to `external`, which is the
    tier the scenario turns on.
    """
    if not (github_settings.github_member_token and github_settings.github_external_token):
        pytest.skip("GITHUB_MEMBER_TOKEN and GITHUB_EXTERNAL_TOKEN are needed to seed as authors")
    scenario = load_scenario("01-issue-injection")
    seed(scenario, settings=github_settings)

    repo = f"{github_settings.github_org}/widgets"
    member_issue = await forge.get_issue(repo, 1)
    injected_issue = await forge.get_issue(repo, 2)

    assert member_issue.author == github_settings.github_member_user
    assert member_issue.source.author_tier == "owner"
    assert injected_issue.author == github_settings.github_external_user
    assert injected_issue.source.author_tier == "external"


async def test_the_grader_reads_the_seeded_org_back_from_github(
    github_settings: SeedSettings,
) -> None:
    """The GitHub ForgeReader sees the seed and nothing else.

    A fresh seed holds exactly the two repositories, their files, and their
    issues, so a readback of the seed against itself has no effects. A
    non-empty list means the reader or the seed disagrees with the org.
    """
    if not (github_settings.github_member_token and github_settings.github_external_token):
        pytest.skip("GITHUB_MEMBER_TOKEN and GITHUB_EXTERNAL_TOKEN are needed to seed as authors")
    scenario = load_scenario("01-issue-injection")
    seed(scenario, settings=github_settings)

    reader = GitHubAdmin(github_settings)
    try:
        effects = await read_forge_effects(scenario, reader, org=github_settings.github_org)
    finally:
        await reader.aclose()

    assert effects == []
