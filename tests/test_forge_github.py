"""Unit tests for `GitHubForge` and the GitHub seeder, with no network.

Everything here runs against a faked `httpx` transport or a faked client, so it
needs no org and no token. The live-org tests live in
`tests/test_github_integration.py` and skip without `GITHUB_ADMIN_TOKEN`.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
import pytest

from gen.seed import SeedError, github_call, reset_github
from servers.gitea_mcp.forge_github import (
    ForgeError,
    GitHubForge,
    is_rate_limited,
    rate_limit_delay,
)

FORGE_ARGS = ("warrant-demo-org", "test-token")


def _forge(handler: Any, *, sleep: Any = None, **kwargs: Any) -> GitHubForge:
    """A `GitHubForge` whose client answers `handler` instead of the network."""
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://api.github.com",
    )
    if sleep is not None:
        kwargs["sleep"] = sleep
    return GitHubForge(*FORGE_ARGS, client=client, **kwargs)


def test_a_github_forge_refuses_to_start_without_a_token_or_org() -> None:
    with pytest.raises(ForgeError):
        GitHubForge("warrant-demo-org", "")
    with pytest.raises(ForgeError):
        GitHubForge("", "test-token")


def test_rate_limit_delay_reads_the_reset_header() -> None:
    limited = httpx.Response(403, headers={"X-RateLimit-Reset": "1000"})

    assert rate_limit_delay(limited, now=940.0) == 60.0


def test_rate_limit_delay_falls_back_to_retry_after_then_a_minute() -> None:
    delayed = httpx.Response(429, headers={"Retry-After": "5"})

    assert rate_limit_delay(delayed, now=0.0) == 5.0
    assert rate_limit_delay(httpx.Response(403), now=0.0) == 60.0


def test_is_rate_limited_needs_the_zero_remaining_header() -> None:
    assert is_rate_limited(httpx.Response(403, headers={"X-RateLimit-Remaining": "0"}))
    assert not is_rate_limited(httpx.Response(403, headers={"X-RateLimit-Remaining": "7"}))
    assert not is_rate_limited(httpx.Response(404))


async def test_tier_resolves_a_204_to_member_and_a_404_to_external() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/orgs/warrant-demo-org/members/bob":
            return httpx.Response(204)
        if request.url.path == "/orgs/warrant-demo-org/memberships/bob":
            return httpx.Response(200, json={"role": "member"})
        if request.url.path == "/orgs/warrant-demo-org/members/drifter":
            return httpx.Response(404)
        return httpx.Response(404)

    forge = _forge(handler)

    assert await forge._tier("warrant-demo-org", "bob") == "member"
    assert await forge._tier("warrant-demo-org", "drifter") == "external"
    assert await forge._tier("warrant-demo-org", "") == "unknown"


async def test_tier_promotes_an_org_admin_to_owner() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/members/bob"):
            return httpx.Response(204)
        if request.url.path.endswith("/memberships/bob"):
            return httpx.Response(200, json={"role": "admin"})
        return httpx.Response(404)

    forge = _forge(handler)

    assert await forge._tier("warrant-demo-org", "bob") == "owner"


async def test_last_commit_author_reads_the_login_and_its_tier() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/warrant-demo-org/widgets/commits":
            return httpx.Response(200, json=[{"author": {"login": "bob"}}])
        if path == "/orgs/warrant-demo-org/members/bob":
            return httpx.Response(204)
        if path == "/orgs/warrant-demo-org/memberships/bob":
            return httpx.Response(200, json={"role": "member"})
        return httpx.Response(404)

    forge = _forge(handler)

    author, tier = await forge._last_commit_author(
        "warrant-demo-org/widgets", ".github/copilot-instructions.md", "main"
    )

    assert (author, tier) == ("bob", "member")


async def test_last_commit_author_is_unknown_without_a_github_account() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/commits"):
            return httpx.Response(200, json=[{"author": None, "commit": {"author": {"name": "x"}}}])
        return httpx.Response(404)

    forge = _forge(handler)

    assert await forge._last_commit_author("warrant-demo-org/widgets", "AGENTS.md", "main") == (
        "",
        "unknown",
    )


async def test_a_spent_rate_limit_sleeps_until_reset_and_retries() -> None:
    responses = [
        httpx.Response(
            403,
            headers={
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(time.time()) + 7),
            },
        ),
        httpx.Response(200, json={"login": "warrant-admin"}),
    ]
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    forge = _forge(handler, sleep=fake_sleep)

    response = await forge._send("GET", "/user")

    assert response.status_code == 200
    assert len(sleeps) == 1 and 6.0 <= sleeps[0] <= 8.0


async def test_a_403_that_is_not_the_rate_limit_is_returned() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(403, headers={"X-RateLimit-Remaining": "9"})

    forge = _forge(handler)

    response = await forge._send("GET", "/user")

    assert response.status_code == 403
    assert calls == ["/user"]


async def test_list_issues_filters_out_pull_requests() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/warrant-demo-org/widgets/issues":
            return httpx.Response(
                200,
                json=[
                    {
                        "number": 1,
                        "title": "an issue",
                        "body": "body",
                        "state": "open",
                        "user": {"login": "bob"},
                        "labels": [{"name": "bug"}],
                    },
                    {
                        "number": 2,
                        "title": "a pull request",
                        "state": "open",
                        "user": {"login": "bob"},
                        "pull_request": {"url": "https://api.github.com/pulls/2"},
                    },
                ],
            )
        if path == "/orgs/warrant-demo-org/members/bob":
            return httpx.Response(204)
        if path == "/orgs/warrant-demo-org/memberships/bob":
            return httpx.Response(200, json={"role": "member"})
        return httpx.Response(404)

    forge = _forge(handler)

    issues = await forge.list_issues("warrant-demo-org/widgets")

    assert [issue.number for issue in issues] == [1]
    assert issues[0].labels == ["bug"]
    assert issues[0].author_membership == "member"
    assert issues[0].source.system == "github"


async def test_get_file_reads_content_and_the_commit_author() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/warrant-demo-org/widgets/contents/README.md":
            return httpx.Response(
                200,
                json={
                    "type": "file",
                    "path": "README.md",
                    "sha": "abc",
                    "encoding": "base64",
                    "content": base64.b64encode(b"hello\n").decode(),
                },
            )
        if path == "/repos/warrant-demo-org/widgets/commits":
            return httpx.Response(200, json=[{"author": {"login": "drifter"}}])
        if path == "/orgs/warrant-demo-org/members/drifter":
            return httpx.Response(404)
        return httpx.Response(404)

    forge = _forge(handler)

    file = await forge.get_file("warrant-demo-org/widgets", "README.md")

    assert file.content == "hello\n"
    assert file.source.author == "drifter"
    assert file.source.author_tier == "external"


async def test_set_repo_visibility_maps_onto_the_private_flag() -> None:
    seen: list[Any] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/warrant-demo-org/widgets":
            seen.append(json.loads(request.content))
            return httpx.Response(
                200,
                json={
                    "name": "widgets",
                    "full_name": "warrant-demo-org/widgets",
                    "private": True,
                    "default_branch": "main",
                    "owner": {"login": "warrant-demo-org"},
                },
            )
        if request.url.path == "/orgs/warrant-demo-org/members/warrant-demo-org":
            return httpx.Response(404)
        return httpx.Response(404)

    forge = _forge(handler)

    repo = await forge.set_repo_visibility("warrant-demo-org/widgets", "private")

    assert seen == [{"private": True}]
    assert repo.private is True


# -- the seeder's GitHub pieces --------------------------------------------


class FakeClient:
    """A minimal `httpx.Client` stand-in for the seeder's request helpers."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        self.calls.append((method, path))
        return self._responses.pop(0)


def test_github_call_sleeps_through_a_spent_rate_limit() -> None:
    reset = str(int(time.time()) + 7)
    client = FakeClient(
        [
            httpx.Response(403, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset}),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    slept: list[float] = []

    response = github_call(client, "GET", "/user", sleep=slept.append)

    assert response.status_code == 200
    assert len(slept) == 1 and 6.0 <= slept[0] <= 8.0
    assert client.calls == [("GET", "/user"), ("GET", "/user")]


def test_reset_github_deletes_every_repo_across_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("gen.seed.GITHUB_PER_PAGE", 2)
    pages = {
        1: [
            {"full_name": "warrant-demo-org/one"},
            {"full_name": "warrant-demo-org/two"},
        ],
        2: [{"full_name": "warrant-demo-org/three"}],
    }
    deleted: list[str] = []

    class ResetClient:
        def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
            if method == "GET":
                page = kwargs["params"]["page"]
                return httpx.Response(200, json=pages.get(page, []))
            deleted.append(path)
            return httpx.Response(204)

    reset_github(ResetClient(), "warrant-demo-org")

    assert deleted == [
        "/repos/warrant-demo-org/one",
        "/repos/warrant-demo-org/two",
        "/repos/warrant-demo-org/three",
    ]


def test_reset_github_needs_an_org() -> None:
    with pytest.raises(SeedError, match="GITHUB_ORG"):
        reset_github(FakeClient([]), "")
