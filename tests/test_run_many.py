"""Two tasks at once through `run_many`, and the token each call carries.

The loop is real: `agents.run_many.run_concurrent` builds two whole runs, each
one logging in, exchanging, opening a session, and writing its run directory.
Only the two ends that need a stack are replaced. The exchange is a fake that
returns a marker per task, and the streamable-HTTP transport is replaced with
fake streams while the shipped `MCPClient` still builds the httpx client and
writes the call log. The Authorization header is read inside `call_tool`, from
the HTTP client the session uses, so the assertion is over the header the
request carries rather than the endpoint the client was built from.

These are the W10 criteria that two concurrent tasks keep their own `sub` and
that a token obtained for one task is never presented on another's call.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agents import loop as loop_module
from agents import mcp_client as mcp_client_module
from agents import run_many
from agents.mcp_client import MCPClient
from agents.providers.base import ToolSchema, ToolUse, Turn, Usage
from agents.task import Task

TOOL = "db.get_ticket"

# Every call's Authorization header, keyed by the HTTP client the session uses.
# Reading it inside `call_tool` is the point: the value is the header the
# request carries, not the endpoint the client was built from.
CALL_HEADERS: dict[int, list[str | None]] = {}


class FakeStream:
    """One end of the fake stream pair, carrying the HTTP client it came from."""

    def __init__(self, http: Any) -> None:
        self.http = http


class FakeTransport:
    """A stand-in for `streamable_http_client`'s async context manager."""

    def __init__(self, http: Any) -> None:
        self.http = http

    async def __aenter__(self) -> tuple[FakeStream, FakeStream]:
        return FakeStream(self.http), FakeStream(self.http)

    async def __aexit__(self, *exc_info: Any) -> None:
        return None


def fake_transport(url: str, http_client: Any = None) -> FakeTransport:
    """The `streamable_http_client` replacement, given the real HTTP client."""
    return FakeTransport(http_client)


class FakeSession:
    """The `ClientSession` methods the MCP client uses, over fake streams."""

    def __init__(self, read: FakeStream, write: FakeStream) -> None:
        self.http = read.http

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        return None

    async def initialize(self) -> None:
        return None

    async def list_tools(self) -> Any:
        return SimpleNamespace(
            tools=[
                SimpleNamespace(
                    name=TOOL,
                    description="Read a ticket.",
                    input_schema={
                        "type": "object",
                        "properties": {"ticket_id": {"type": "integer"}},
                    },
                ),
                SimpleNamespace(
                    name="gitea.get_issue",
                    description="Read an issue.",
                    input_schema={"type": "object", "properties": {"number": {"type": "integer"}}},
                ),
            ]
        )

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        CALL_HEADERS.setdefault(id(self.http), []).append(self.http.headers.get("authorization"))
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text='{"id": 12}')],
            structured_content={"id": 12},
            is_error=False,
        )


class RecordingMCPClient(MCPClient):
    """The shipped client, with every instance kept for inspection.

    `__aenter__` is the shipped one, so the httpx client it builds carries the
    Authorization header this session will send. `_http` is that client, which
    is what makes the per-task token assertion an assertion about the wire.
    """

    instances: list[RecordingMCPClient] = []

    def __init__(
        self, endpoints: Any, *, chain: Any, runs_dir: Path | None = None, **kw: Any
    ) -> None:
        super().__init__(endpoints, chain=chain, runs_dir=runs_dir, **kw)
        self.task_id = chain.task_id
        RecordingMCPClient.instances.append(self)


class OneToolThenText:
    """A provider that asks for `calls` reads, then answers with text.

    It is stateless between conversations: how many tool results are already in
    the transcript is how a turn knows where it is. A shared counter would be
    wrong here, because two tasks run through the same provider at once.
    """

    name = "scripted"
    model = "scripted"
    effort = "off"

    def __init__(self, calls: int = 1) -> None:
        self.calls = calls
        self.offered: list[list[str]] = []

    async def run(self, messages: list[Turn], tools: list[ToolSchema]) -> Turn:
        self.offered.append([tool.name for tool in tools])
        answered = sum(1 for m in messages if m.role == "user" and m.tool_results)
        if answered < self.calls:
            return Turn(
                role="assistant",
                tool_uses=[ToolUse(id=f"c{answered}", name=TOOL, args={"ticket_id": 12})],
                usage=Usage(input_tokens=10, output_tokens=5),
            )
        return Turn(role="assistant", text="answered")


def support_task(user: str, ticket: int = 12) -> Task:
    return Task(
        kind="support",
        subject=f"ticket #{ticket}",
        user=user,
        params={"ticket": ticket},
    )


def install_fake_stack(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Replace the login, the exchange, the decode, and the transport.

    Returns the list the fake exchange appends to, so a test can assert what the
    exchange was asked for as well as what each call carried.
    """
    RecordingMCPClient.instances = []
    CALL_HEADERS.clear()
    exchanges: list[dict[str, Any]] = []

    def fake_login(settings: Any, client: Any, username: str, password: str) -> str:
        return f"subject-{username}"

    def fake_exchange(
        settings: Any,
        client: Any,
        subject_token: str,
        audience: str,
        task_id: str,
        *,
        client_id: str,
        scopes: tuple[str, ...] = (),
    ) -> str:
        exchanges.append(
            {
                "subject_token": subject_token,
                "audience": audience,
                "task_id": task_id,
                "client_id": client_id,
                "scopes": list(scopes),
            }
        )
        return f"marker-{task_id}"

    def fake_decode(token: str) -> dict[str, Any]:
        task_id = token.removeprefix("marker-")
        now = int(time.time())
        return {
            "header": {"alg": "none", "typ": "JWT"},
            "claims": {
                "aud": ["warrant"],
                "act": {"sub": "support-agent"},
                "sub": "h-someone",
                "task_id": [task_id],
                "iat": now,
                "exp": now + 300,
            },
        }

    monkeypatch.setattr(loop_module, "login_user", fake_login)
    monkeypatch.setattr(loop_module, "exchange_for_obo", fake_exchange)
    monkeypatch.setattr(loop_module, "decode_claims", fake_decode)
    monkeypatch.setattr(loop_module, "MCPClient", RecordingMCPClient)
    monkeypatch.setattr(mcp_client_module, "streamable_http_client", fake_transport)
    monkeypatch.setattr(mcp_client_module, "ClientSession", FakeSession)
    return exchanges


async def test_concurrent_tasks_keep_their_own_sub_in_the_logs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Each task's `calls.jsonl` carries only its own `sub`, `act`, and id."""
    install_fake_stack(monkeypatch)
    tasks = [support_task("alice", 12), support_task("bob", 13)]

    outcomes = await run_many.run_concurrent(
        tasks,
        provider=OneToolThenText(),
        runs_dir=tmp_path,
        settings=SimpleNamespace(warrant_user_password=""),
    )

    assert len(outcomes) == len(tasks)
    subs: dict[str, set[str]] = {}
    for task in tasks:
        log = tmp_path / task.task_id / "calls.jsonl"
        assert log.exists(), f"task {task.task_id} wrote no call log"
        records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        subs[task.task_id] = {record["sub"] for record in records}
        assert {record["task_id"] for record in records} == {task.task_id}
        assert {record["act"] for record in records} == {"support-agent"}

    assert subs[tasks[0].task_id] == {"alice"}
    assert subs[tasks[1].task_id] == {"bob"}
    assert set(subs) == {task.task_id for task in tasks}


async def test_each_call_sends_the_token_its_own_task_obtained(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The Authorization header on each call is its own task's marker.

    The header is read inside `call_tool`, from the HTTP client the session
    uses, so a token cached at construction cannot pass this.
    """
    exchanges = install_fake_stack(monkeypatch)
    tasks = [support_task("alice", 12), support_task("bob", 13)]

    await run_many.run_concurrent(
        tasks,
        provider=OneToolThenText(calls=2),
        runs_dir=tmp_path,
        settings=SimpleNamespace(warrant_user_password=""),
    )

    clients = {client.task_id: client for client in RecordingMCPClient.instances}
    assert set(clients) == {task.task_id for task in tasks}
    assert len({id(client._http["warrant"]) for client in clients.values()}) == len(tasks)
    for task in tasks:
        client = clients[task.task_id]
        headers = CALL_HEADERS[id(client._http["warrant"])]
        assert headers, "the task made no call"
        assert set(headers) == {f"Bearer marker-{task.task_id}"}

    # The exchange ran once per task, each as the support client for the gateway.
    assert {exchange["task_id"] for exchange in exchanges} == {t.task_id for t in tasks}
    assert {exchange["client_id"] for exchange in exchanges} == {"support-agent"}
    assert {exchange["audience"] for exchange in exchanges} == {"warrant"}


async def test_a_support_run_offers_only_the_database_and_mail_tools(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The model is not offered a tool the support role does not hold."""
    install_fake_stack(monkeypatch)
    provider = OneToolThenText(calls=1)
    task = support_task("alice")

    await run_many.run_concurrent(
        [task],
        provider=provider,
        runs_dir=tmp_path,
        settings=SimpleNamespace(warrant_user_password=""),
    )

    assert provider.offered, "the model was never offered a tool surface"
    assert {tuple(names) for names in provider.offered} == {(TOOL,)}


async def test_a_failing_task_cancels_its_siblings(monkeypatch: pytest.MonkeyPatch) -> None:
    """One failure is the group's failure, and the sibling stops working.

    `asyncio.TaskGroup` is what the caller sees: the sibling is cancelled and
    awaited before the group raises an `ExceptionGroup` holding the child error.
    """
    cancelled = asyncio.Event()

    async def fake_run_one(task: Task, **kwargs: Any) -> Any:
        if task.user == "boom":
            # Give the sibling a moment to reach its own await, so the failure
            # arrives while it is running rather than before it starts.
            await asyncio.sleep(0.01)
            raise RuntimeError("boom")
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return None

    monkeypatch.setattr(run_many, "run_one", fake_run_one)

    with pytest.raises(ExceptionGroup) as error:
        await run_many.run_concurrent([support_task("boom"), support_task("slow")])

    assert any(isinstance(child, RuntimeError) for child in error.value.exceptions)
    assert cancelled.is_set(), "the sibling kept running after the failure"


async def test_run_concurrent_of_nothing_returns_nothing() -> None:
    assert await run_many.run_concurrent([]) == []
