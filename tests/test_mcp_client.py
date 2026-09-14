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

from agents.mcp_client import (
    CallResult,
    Endpoint,
    MCPClient,
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
    assert result.content == json.dumps(
        {"number": 1, "source": SOURCE}, sort_keys=True, default=str
    )

    lines = (tmp_path / "task-1" / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    assert record["sub"] == "alice"
    assert record["act"] == "triage-agent"
    assert record["task_id"] == "task-1"
    assert record["tool"] == "get_issue"
    assert record["source"] == SOURCE
