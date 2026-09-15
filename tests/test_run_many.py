"""Two tasks at once through `run_many`, and the token each call carries.

The loop is real: `agents.run_many.run_concurrent` builds two whole runs, each
one logging in, exchanging, opening a session, and writing its run directory.
Only the two ends that need a stack are replaced. The exchange is a fake that
returns a marker per task, and the MCP client is one that serves a fake session
instead of opening a streamable-HTTP connection. Everything between them,
including `agents/mcp_client.py`'s call log, is the shipped code.

These are the W10 criteria that two concurrent tasks keep their own `sub` and
that a token obtained for one task is never presented on another's call.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agents import loop as loop_module
from agents import run_many
from agents.mcp_client import MCPClient
from agents.providers.base import ToolSchema, ToolUse, Turn, Usage
from agents.task import Task

TOOL = "db.get_ticket"


class FakeSession:
    """The two `ClientSession` methods the MCP client uses."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

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
        self.calls.append((name, arguments))
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text='{"id": 12}')],
            structured_content={"id": 12},
            is_error=False,
        )


class OfflineMCPClient(MCPClient):
    """A real `MCPClient` that skips the network and serves one fake session.

    Every instance is kept so a test can read the bearer each run presented and
    the calls it made. `call` records the bearer at call time, which is the
    question the criterion asks: not what the session was built with, but what
    each call carried.
    """

    instances: list[OfflineMCPClient] = []

    def __init__(
        self, endpoints: Any, *, chain: Any, runs_dir: Path | None = None, **kw: Any
    ) -> None:
        super().__init__(endpoints, chain=chain, runs_dir=runs_dir, **kw)
        self.bearer = self._endpoints[0].bearer
        self.task_id = chain.task_id
        self.session = FakeSession()
        self.call_bearers: list[str] = []
        OfflineMCPClient.instances.append(self)

    async def __aenter__(self) -> OfflineMCPClient:
        for endpoint in self._endpoints:
            self._sessions[endpoint.name] = self.session
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        return None

    async def call(self, name: str, args: dict[str, Any]) -> Any:
        self.call_bearers.append(self.bearer)
        return await super().call(name, args)


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
    OfflineMCPClient.instances = []
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
    ) -> str:
        exchanges.append(
            {
                "subject_token": subject_token,
                "audience": audience,
                "task_id": task_id,
                "client_id": client_id,
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
    monkeypatch.setattr(loop_module, "MCPClient", OfflineMCPClient)
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


async def test_each_call_carries_the_token_its_own_task_obtained(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A marker per task, and every call presents its own task's marker."""
    exchanges = install_fake_stack(monkeypatch)
    tasks = [support_task("alice", 12), support_task("bob", 13)]

    await run_many.run_concurrent(
        tasks,
        provider=OneToolThenText(calls=2),
        runs_dir=tmp_path,
        settings=SimpleNamespace(warrant_user_password=""),
    )

    clients = {client.task_id: client for client in OfflineMCPClient.instances}
    assert set(clients) == {task.task_id for task in tasks}
    for task in tasks:
        client = clients[task.task_id]
        assert client.bearer == f"marker-{task.task_id}"
        assert client.call_bearers, "the task made no call"
        assert set(client.call_bearers) == {f"marker-{task.task_id}"}

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


async def test_run_concurrent_of_nothing_returns_nothing() -> None:
    assert await run_many.run_concurrent([]) == []
