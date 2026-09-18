"""The MCP client's logging and provenance helpers, and its call routing.

The routing test injects a fake session because opening a real streamable-HTTP
session is what `tests/test_gitea_integration.py` does against the running
stack. What is checked here is that a call is routed to the session that offers
the tool and that the JSONL line carries the chain, without a server.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agents.mcp_client import (
    CallResult,
    Endpoint,
    MCPClient,
    MCPError,
    RefreshingToolSource,
    append_jsonl,
    call_record,
    digest,
    extract_sources,
)
from agents.task import Chain

CHAIN = Chain(sub="alice", act="triage-agent", task_id="task-1", sub_id="subject-uuid")

SOURCE = {
    "system": "gitea",
    "kind": "issue",
    "id": "acme/widgets#1",
    "author": "bob",
    "author_tier": "member",
}


def test_digest_is_stable_across_key_order() -> None:
    assert digest({"b": 2, "a": 1}) == digest({"a": 1, "b": 2})
    assert digest({"a": 1}) != digest({"a": 2})


def test_extract_sources_finds_nested_blocks_and_dedupes() -> None:
    payload = {
        "matches": [
            {"path": "app.py", "source": SOURCE},
            {"path": "app.py", "source": dict(SOURCE)},
        ],
        "other": {"source": {**SOURCE, "id": "acme/widgets#2"}},
    }

    found = extract_sources(payload)

    assert [source["id"] for source in found] == ["acme/widgets#1", "acme/widgets#2"]


def test_call_record_carries_the_chain_and_digests() -> None:
    record = call_record(
        chain=CHAIN,
        tool="get_issue",
        endpoint="gitea-mcp",
        args={"repo": "acme/widgets", "number": 1},
        result_value={"number": 1},
        is_error=False,
        sources=[SOURCE],
    )

    assert record["sub"] == "alice"
    assert record["act"] == "triage-agent"
    assert record["task_id"] == "task-1"
    assert record["sub_id"] == "subject-uuid"
    assert record["args_digest"] == digest({"repo": "acme/widgets", "number": 1})
    assert record["result_digest"] == digest({"number": 1})
    assert record["source"] == SOURCE
    assert "sources" not in record


def test_call_record_lists_several_sources_apart() -> None:
    second = {**SOURCE, "id": "acme/widgets#2"}

    record = call_record(
        chain=CHAIN,
        tool="list_issues",
        endpoint="gitea-mcp",
        args={},
        result_value=[],
        is_error=False,
        sources=[SOURCE, second],
    )

    assert record["sources"] == [SOURCE, second]
    assert "source" not in record


def test_append_jsonl_writes_one_object_per_line(tmp_path: Path) -> None:
    path = tmp_path / "runs" / "task-1" / "calls.jsonl"

    append_jsonl(path, {"tool": "get_issue"})
    append_jsonl(path, {"tool": "get_file"})

    lines = path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["tool"] for line in lines] == ["get_issue", "get_file"]


class FakeSession:
    """The two `ClientSession` methods the client uses."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    async def list_tools(self) -> Any:
        return SimpleNamespace(
            tools=[
                SimpleNamespace(
                    name="get_issue",
                    description="Read an issue.",
                    input_schema={"type": "object", "properties": {"number": {"type": "integer"}}},
                )
            ]
        )

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        self.calls.append((name, arguments))
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text='{"number": 1}')],
            structured_content={"number": 1, "source": SOURCE},
            is_error=False,
        )


async def test_call_routes_to_the_session_and_logs_the_chain(tmp_path: Path) -> None:
    session = FakeSession()
    client = MCPClient(
        Endpoint(url="http://127.0.0.1:9101/mcp", bearer="a-token", name="gitea-mcp"),
        chain=CHAIN,
        runs_dir=tmp_path,
    )
    client._sessions["gitea-mcp"] = session

    tools = await client.list_tools()
    result = await client.call("get_issue", {"repo": "acme/widgets", "number": 1})

    assert [tool.name for tool in tools] == ["get_issue"]
    assert session.calls == [("get_issue", {"repo": "acme/widgets", "number": 1})]
    assert isinstance(result, CallResult)
    assert result.sources == [SOURCE]
    # The text block is what the server wrote for the model, so it wins over the
    # structured payload. The payload is the machine-readable copy and can carry
    # fields the model must not be shown, which is exactly the postgres server's
    # `secrets` list.
    assert result.content == '{"number": 1}'
    assert result.payload == {"number": 1, "source": SOURCE}

    lines = (tmp_path / "task-1" / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    assert record["sub"] == "alice"
    assert record["act"] == "triage-agent"
    assert record["task_id"] == "task-1"
    assert record["tool"] == "get_issue"
    assert record["source"] == SOURCE


class RaisingSession(FakeSession):
    """A session whose transport fails, as a timeout or a dropped connection does."""

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        self.calls.append((name, arguments))
        raise RuntimeError("connection reset")


async def test_a_call_that_raises_still_writes_a_line(tmp_path: Path) -> None:
    """A failed call is what an audit reader most wants to see.

    The line used to be written only after a successful return, so a bad tool
    name or a transport error killed the run and left the run directory with no
    record of the attempt.
    """
    client = MCPClient(
        Endpoint(url="http://127.0.0.1:9101/mcp", bearer="a-token", name="gitea-mcp"),
        chain=CHAIN,
        runs_dir=tmp_path,
    )
    session = RaisingSession()
    client._sessions["gitea-mcp"] = session
    await client.list_tools()

    with pytest.raises(RuntimeError):
        await client.call("get_issue", {"repo": "acme/widgets", "number": 1})

    lines = (tmp_path / "task-1" / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1, "the failed call must be recorded"
    record = json.loads(lines[0])
    assert record["is_error"] is True
    assert record["raised"] is True
    assert record["tool"] == "get_issue"
    assert record["sub"] == "alice"
    assert record["task_id"] == "task-1"


async def test_content_falls_back_to_the_payload_when_there_is_no_text(tmp_path: Path) -> None:
    """A server that returns structured content and no text still reaches the model."""

    class StructuredOnly(FakeSession):
        async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
            return SimpleNamespace(
                content=[],
                structured_content={"number": 1},
                is_error=False,
            )

    client = MCPClient(
        Endpoint(url="http://127.0.0.1:9101/mcp", bearer="a-token", name="gitea-mcp"),
        chain=CHAIN,
        runs_dir=tmp_path,
    )
    client._sessions["gitea-mcp"] = StructuredOnly()
    await client.list_tools()

    result = await client.call("get_issue", {"number": 1})

    assert result.text == ""
    assert result.content == json.dumps({"number": 1}, sort_keys=True, default=str)


async def test_an_unknown_tool_that_raises_still_writes_a_line(tmp_path: Path) -> None:
    """A name the server never offered is the other way a call fails."""
    client = MCPClient(
        Endpoint(url="http://127.0.0.1:9101/mcp", bearer="a-token", name="gitea-mcp"),
        chain=CHAIN,
        runs_dir=tmp_path,
    )
    client._sessions["gitea-mcp"] = FakeSession()
    await client.list_tools()

    with pytest.raises(MCPError):
        await client.call("get_issu", {})

    lines = (tmp_path / "task-1" / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["raised"] is True
    assert record["tool"] == "get_issu"


# -- the bearer refresh ------------------------------------------------------


def test_set_bearer_replaces_the_header_the_session_sends() -> None:
    client = MCPClient(
        Endpoint(url="http://127.0.0.1:9101/mcp", bearer="old", name="gitea-mcp"),
        chain=CHAIN,
    )
    http = SimpleNamespace(headers={"Authorization": "Bearer old"})
    client._http["gitea-mcp"] = http

    client.set_bearer("fresh", name="gitea-mcp")

    assert http.headers["Authorization"] == "Bearer fresh"


class FakeSource:
    """The `ToolSource` half a refresh wraps, with no session behind it."""

    def __init__(self) -> None:
        self.bearers: list[str] = []
        self.calls: list[str] = []

    async def list_tools(self) -> list[Any]:
        return []

    async def call(self, name: str, args: dict[str, Any]) -> Any:
        self.calls.append(name)
        return SimpleNamespace(is_error=False)

    def set_bearer(self, bearer: str, *, name: str | None = None) -> None:
        self.bearers.append(bearer)


async def test_refreshing_source_mints_a_new_bearer_at_the_expiry() -> None:
    """A call after the token's lifetime runs on a fresh token, same task."""
    source = FakeSource()
    now = [900.0]
    refreshed: list[str] = []

    def refresh() -> tuple[str, float]:
        refreshed.append("called")
        return "fresh", 1300.0

    wrapper = RefreshingToolSource(
        source, refresh=refresh, expires_at=1050.0, leeway_s=60.0, clock=lambda: now[0]
    )

    await wrapper.call("gitea.get_issue", {})
    assert refreshed == [], "a token with more than the leeway left is not replaced"
    assert source.bearers == []

    now[0] = 1000.0  # 50 s left, inside the 60 s leeway
    await wrapper.call("gitea.get_issue", {})
    assert refreshed == ["called"]
    assert source.bearers == ["fresh"]
    assert source.calls == ["gitea.get_issue", "gitea.get_issue"]

    # The fresh token's expiry replaced the old one, so the next call reuses it.
    await wrapper.call("gitea.get_issue", {})
    assert refreshed == ["called"]


async def test_refreshing_source_catches_a_token_that_expired_during_a_turn() -> None:
    """The check runs at call time, so a token already gone is replaced too."""
    source = FakeSource()
    wrapper = RefreshingToolSource(
        source,
        refresh=lambda: ("fresh", 2000.0),
        expires_at=1000.0,
        leeway_s=60.0,
        clock=lambda: 1100.0,
    )

    await wrapper.call("gitea.get_issue", {})

    assert source.bearers == ["fresh"]
