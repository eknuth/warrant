"""Gitea-backed tests against the running compose stack.

Every test here is marked `integration` and skips when the stack is absent, so
`make test` is green on a clean checkout. When Gitea, Keycloak, and a
bootstrapped token are up, these exercise the real forge and the real MCP
server end to end.

`scripts/gitea_bootstrap.py` has to have run: the tests use the admin token from
`.env`, the org `acme`, and a push of alice's dev password through Keycloak to
mint an on-behalf-of token. The scratch repo and the outsider user each test
creates are deleted again in the fixture.
"""

from __future__ import annotations

import base64
import json
import secrets
import threading
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
import uvicorn
from jose import jwt
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from gen.schema import load_scenario
from gen.seed import seed as seed_scenario
from servers.gitea_mcp.forge import GiteaForge
from servers.gitea_mcp.server import TOOL_NAMES, ServerSettings, build_app

pytestmark = pytest.mark.integration

INITIALIZE_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "w3-integration-test", "version": "0"},
    },
}
MCP_ACCEPT = {"Accept": "application/json, text/event-stream"}


@dataclass
class Scratch:
    """A throwaway repo in `acme` with an issue filed by a non-member."""

    repo: str
    outsider: str
    issue_number: int


@pytest.fixture
def scratch(gitea: ServerSettings) -> Iterator[Scratch]:
    suffix = uuid.uuid4().hex[:8]
    repo = f"acme/w3-scratch-{suffix}"
    name = repo.split("/", 1)[1]
    outsider = f"w3-outsider-{suffix}"
    password = secrets.token_urlsafe(18)
    admin = httpx.Client(
        base_url=gitea.gitea_url,
        headers={"Authorization": f"token {gitea.gitea_admin_token}"},
        timeout=20.0,
    )
    created_repo = False
    created_user = False
    try:
        response = admin.post(
            "/api/v1/orgs/acme/repos",
            json={"name": name, "auto_init": True, "default_branch": "main"},
        )
        assert response.status_code == 201, response.text
        created_repo = True

        response = admin.post(
            "/api/v1/admin/users",
            json={
                "username": outsider,
                "password": password,
                "email": f"{outsider}@example.com",
                "must_change_password": False,
            },
        )
        assert response.status_code == 201, response.text
        created_user = True

        # A file for get_file and search_code to find. The name is deliberately
        # distinctive so a match cannot come from the auto-init README.
        response = admin.post(
            f"/api/v1/repos/{repo}/contents/app/config.py",
            json={
                "branch": "main",
                "content": base64.b64encode(b'PLANTED_SECRET = "w3-scratch"\n').decode(),
                "message": "seed a file to read and search",
            },
        )
        assert response.status_code == 201, response.text

        with httpx.Client(
            base_url=gitea.gitea_url, auth=(outsider, password), timeout=20.0
        ) as stranger:
            response = stranger.post(
                f"/api/v1/repos/{repo}/issues",
                json={"title": "external report", "body": "filed by a non-member"},
            )
            assert response.status_code == 201, response.text
            number = response.json()["number"]
            response = stranger.post(
                f"/api/v1/repos/{repo}/issues/{number}/comments",
                json={"body": "detail from the reporter"},
            )
            assert response.status_code == 201, response.text

        yield Scratch(repo=repo, outsider=outsider, issue_number=number)
    finally:
        if created_repo:
            admin.delete(f"/api/v1/repos/{repo}")
        if created_user:
            admin.delete(f"/api/v1/admin/users/{outsider}")
        admin.close()


@pytest.fixture
async def forge(gitea: ServerSettings) -> AsyncIterator[GiteaForge]:
    instance = GiteaForge(gitea.gitea_url, gitea.gitea_admin_token)
    try:
        yield instance
    finally:
        await instance.aclose()


@contextmanager
def serve(app: Any) -> Iterator[str]:
    """Run the ASGI app on an ephemeral port in a thread and yield its base URL.

    uvicorn's `capture_signals` is a no-op off the main thread, so this is the
    supported way to run it here. Port 0 avoids colliding with a server someone
    left running on 9101.
    """
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20.0
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("the test MCP server did not start")
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10.0)


@pytest.fixture(scope="session")
def mcp_url(gitea: ServerSettings, settings: ServerSettings) -> Iterator[str]:
    """The server as it runs for real: Keycloak's issuer, the token from `.env`."""
    with serve(build_app(settings=settings)) as url:
        yield f"{url}/mcp"


@pytest.fixture(scope="session")
def testkey_mcp_url(
    gitea: ServerSettings,
    settings: ServerSettings,
    rsa_keypair: tuple[str, str],
    test_issuer: str,
) -> Iterator[str]:
    """The same server, verifying tokens this suite signs itself.

    The forge and the Gitea admin token are real; only the signature is. That
    is what lets a token with a scope Keycloak will not mint be presented to the
    real server.
    """
    app = build_app(settings=settings, issuer=test_issuer, key=rsa_keypair[1])
    with serve(app) as url:
        yield f"{url}/mcp"


@asynccontextmanager
async def mcp_session(url: str, token: str) -> AsyncIterator[ClientSession]:
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"}, timeout=30.0
    ) as client:
        async with streamable_http_client(url, http_client=client) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


def structured(result: Any) -> dict[str, Any]:
    """A tool result's structured payload, whichever shape the SDK used."""
    payload = result.structured_content
    if payload is None:
        return json.loads(result.content[0].text)
    if set(payload) == {"result"} and isinstance(payload["result"], dict):
        return payload["result"]
    return payload


async def raw_call(url: str, token: str | None) -> httpx.Response:
    headers = dict(MCP_ACCEPT)
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(timeout=20.0) as client:
        return await client.post(url, json=INITIALIZE_REQUEST, headers=headers)


# -- the HTTP auth boundary ------------------------------------------------


async def test_a_call_with_no_bearer_gets_401(testkey_mcp_url: str) -> None:
    response = await raw_call(testkey_mcp_url, None)

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_request"


async def test_a_call_with_an_expired_bearer_gets_401(
    testkey_mcp_url: str, sign_token: Any
) -> None:
    response = await raw_call(testkey_mcp_url, sign_token(exp_offset=-30))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


async def test_a_call_with_a_postgres_mcp_audience_gets_401(
    testkey_mcp_url: str, sign_token: Any
) -> None:
    response = await raw_call(testkey_mcp_url, sign_token(audience="postgres-mcp"))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


async def test_a_valid_triage_obo_token_lists_the_tools(mcp_url: str, mint_obo: Any) -> None:
    # The real Keycloak exchange, the real issuer, the real server.
    token = mint_obo(scope="task-id:task-w3-list")

    async with mcp_session(mcp_url, token) as session:
        result = await session.list_tools()

    assert {tool.name for tool in result.tools} == set(TOOL_NAMES)


async def test_a_gitea_read_only_token_can_still_set_repo_visibility(
    testkey_mcp_url: str, sign_token: Any, scratch: Scratch, gitea: ServerSettings
) -> None:
    # Scenario 2. The token's scope is only gitea:read, and the call still goes
    # through because this server enforces no scope and holds an admin token
    # that can do anything. That collapse is the point of the scenario: the
    # server's own credential is not what holds, so Warrant has to be.
    token = sign_token(scope=("gitea:read",), task_id="task-scenario-2")
    claims = jwt.get_unverified_claims(token)
    assert claims["scope"] == "gitea:read"
    assert "gitea:write" not in claims["scope"]

    async with mcp_session(testkey_mcp_url, token) as session:
        result = await session.call_tool(
            "set_repo_visibility", {"repo": scratch.repo, "visibility": "private"}
        )

    assert result.is_error is False
    async with httpx.AsyncClient(
        base_url=gitea.gitea_url,
        headers={"Authorization": f"token {gitea.gitea_admin_token}"},
        timeout=20.0,
    ) as client:
        response = await client.get(f"/api/v1/repos/{scratch.repo}")
    assert response.json()["private"] is True


async def test_get_issue_through_the_server_marks_an_outsider_external(
    mcp_url: str, mint_obo: Any, scratch: Scratch
) -> None:
    token = mint_obo(scope="task-id:task-w3-issue")

    async with mcp_session(mcp_url, token) as session:
        result = await session.call_tool(
            "get_issue", {"repo": scratch.repo, "number": scratch.issue_number}
        )

    assert result.is_error is False
    payload = structured(result)
    assert payload["author"] == scratch.outsider
    assert payload["author_membership"] == "external"
    assert payload["source"]["author_tier"] == "external"


async def test_scenario_01_injected_issue_is_external_through_the_server(
    mcp_url: str, mint_obo: Any
) -> None:
    """The W12 criterion: the seeded issue reads back external through W3.

    The scenario seeder writes the second issue as drifter, who is not an org
    member, and this goes through the running MCP server rather than the forge
    directly.
    """
    seed_scenario(load_scenario("01-issue-injection"))
    token = mint_obo(scope="task-id:task-w12-issue")

    async with mcp_session(mcp_url, token) as session:
        result = await session.call_tool("get_issue", {"repo": "acme/widgets", "number": 2})

    assert result.is_error is False
    payload = structured(result)
    assert payload["author"] == "drifter"
    # The external reporter is a repository collaborator as well, so the issue
    # could be filed; `author_tier` is the field the criterion names and it stays
    # external.
    assert payload["source"]["author_tier"] == "external"


# -- the forge against live Gitea ------------------------------------------


async def test_reads(forge: GiteaForge, scratch: Scratch) -> None:
    repos = await forge.list_repos("acme")
    assert scratch.repo in {repo.full_name for repo in repos}
    listed = next(repo for repo in repos if repo.full_name == scratch.repo)
    assert listed.source.kind == "repo"
    assert listed.source.system == "gitea"

    issues = await forge.list_issues(scratch.repo)
    assert {issue.number for issue in issues} == {scratch.issue_number}

    issue = await forge.get_issue(scratch.repo, scratch.issue_number)
    assert issue.author == scratch.outsider
    assert issue.author_membership == "external"
    assert issue.labels == []
    assert issue.source.id == f"{scratch.repo}#{scratch.issue_number}"
    assert issue.source.author_tier == "external"
    assert issue.comments, "the reporter's comment should be attached"
    assert issue.comments[0].author == scratch.outsider
    assert issue.comments[0].author_membership == "external"
    assert issue.comments[0].source.kind == "comment"
    assert issue.comments[0].source.author_tier == "external"

    file = await forge.get_file(scratch.repo, "app/config.py")
    assert file.content == 'PLANTED_SECRET = "w3-scratch"\n'
    assert file.source.kind == "file"
    assert file.source.id == f"{scratch.repo}:app/config.py@main"

    found = await forge.search_code(scratch.repo, "PLANTED_SECRET")
    assert found.truncated is False
    assert [match.path for match in found.matches] == ["app/config.py"]
    assert found.matches[0].line == 1
    assert found.matches[0].source.kind == "file"


async def test_writes(forge: GiteaForge, scratch: Scratch) -> None:
    comment = await forge.create_issue_comment(scratch.repo, scratch.issue_number, "from the test")
    assert comment.body == "from the test"
    assert comment.source.kind == "comment"

    branch = await forge.create_branch(scratch.repo, "w3-feature", "main")
    assert branch.name == "w3-feature"
    assert branch.sha

    commit = await forge.commit_file(
        scratch.repo, "w3-feature", "notes/w3.txt", "hello from w3\n", "add a note"
    )
    assert commit.path == "notes/w3.txt"
    assert commit.branch == "w3-feature"
    assert commit.sha
    assert commit.source.kind == "file"

    pull = await forge.open_pull_request(
        scratch.repo, "w3-feature", "main", "W3 test PR", "opened by the integration test"
    )
    assert pull.number > 0
    assert pull.head == "w3-feature"
    assert pull.base == "main"
    assert pull.state == "open"

    private = await forge.set_repo_visibility(scratch.repo, "private")
    assert private.private is True
    assert private.source.kind == "repo"
    public = await forge.set_repo_visibility(scratch.repo, "public")
    assert public.private is False
