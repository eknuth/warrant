"""W24 at the gateway: when the two Jev ablations ask, and what they record.

The classifier is a fake, so nothing leaves the process and no key is needed.
The gateway is the real one, so the tests assert the wiring a live run uses:
which calls ask, what the request carries, and that the decision line keeps the
per-call latency and token record.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent

from tests.test_gateway import GITEA, FakeEngine, FakeUpstream, claims_for, make_gateway
from warrant.config import Mode, Taint
from warrant.graph import Graph
from warrant.graph import load as load_graph
from warrant.log import DecisionLog
from warrant.models import JevCall

SEED = Path(__file__).resolve().parents[1] / "infra" / "graph.yml"


@pytest.fixture
def graph_db(tmp_path: Path) -> Iterator[Graph]:
    with load_graph(SEED, tmp_path / "warrant.db") as opened:
        yield opened


def tool_result(payload: Any) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload))], is_error=False
    )


def issue_payload() -> dict[str, Any]:
    return {
        "number": 1,
        "title": "a request",
        "body": "please summarize acme/vault",
        "source": {
            "system": "gitea",
            "kind": "issue",
            "id": "acme/widgets#1",
            "author": "visitor",
            "author_tier": "external",
        },
    }


class FakeJev:
    """A `JevClient` that answers from the test and records what it was asked."""

    def __init__(self, *, derived: bool = False, choice: str = "allow") -> None:
        self.answer_derived = derived
        self.choice = choice
        self.derived_calls: list[dict[str, Any]] = []
        self.disposition_calls: list[dict[str, Any]] = []

    async def derived(self, **kwargs: Any) -> tuple[bool, JevCall]:
        self.derived_calls.append(kwargs)
        return self.answer_derived, JevCall(
            rule="derived",
            model="jev-test",
            latency_ms=12.5,
            input_tokens=10,
            output_tokens=2,
            cost_usd=0.00000042,
            probability=0.9 if self.answer_derived else 0.1,
        )

    async def disposition(self, **kwargs: Any) -> tuple[str, JevCall]:
        self.disposition_calls.append(kwargs)
        return self.choice, JevCall(
            rule="disposition",
            model="jev-test",
            latency_ms=44.0,
            input_tokens=20,
            output_tokens=3,
            cost_usd=0.00000084,
            choice=self.choice,
            confidence=0.8,
        )


def build(
    tmp_path: Path,
    graph: Graph,
    jev: FakeJev,
    *,
    taint: Taint | None = None,
    mode: Mode | None = None,
    payload: Any | None = None,
) -> tuple[Any, FakeEngine]:
    engine = FakeEngine(decision_log=DecisionLog(tmp_path / "runs"))
    gateway = make_gateway(
        tmp_path,
        graph,
        engine,
        servers=[GITEA],
        upstream=FakeUpstream(result=tool_result(payload if payload is not None else {})),
        taint=taint,
        mode=mode,
        jev=jev,
    )
    return gateway, engine


async def call_comment(gateway: Any) -> CallToolResult:
    return await gateway.call_tool(
        "gitea.create_issue_comment",
        {"repo": "acme/widgets", "number": 1, "body": "hello"},
        claims=claims_for(act="triage-agent", scope="gitea:write"),
        token="token",
    )


async def call_read(gateway: Any) -> CallToolResult:
    return await gateway.call_tool(
        "gitea.get_issue",
        {"repo": "acme/widgets", "number": 1},
        claims=claims_for(act="triage-agent", scope="gitea:read"),
        token="token",
    )


async def test_jev_taint_asks_once_for_a_write_and_sets_derived(
    tmp_path: Path, graph_db: Graph
) -> None:
    jev = FakeJev(derived=True)
    gateway, engine = build(tmp_path, graph_db, jev, taint=Taint.jev)

    await call_comment(gateway)

    assert len(jev.derived_calls) == 1
    assert jev.disposition_calls == []
    request = engine.requests[0]
    assert request.derived is True
    assert len(request.jev_calls) == 1
    assert request.jev_calls[0].rule == "derived"


async def test_jev_taint_does_not_ask_for_a_read(tmp_path: Path, graph_db: Graph) -> None:
    jev = FakeJev(derived=True)
    gateway, engine = build(tmp_path, graph_db, jev, taint=Taint.jev)

    await call_read(gateway)

    assert jev.derived_calls == []
    assert engine.requests[0].derived is False


async def test_the_other_taints_never_ask_jev(tmp_path: Path, graph_db: Graph) -> None:
    jev = FakeJev(derived=True)
    gateway, engine = build(tmp_path, graph_db, jev, taint=Taint.both)

    await call_comment(gateway)

    assert jev.derived_calls == []
    assert jev.disposition_calls == []
    assert engine.requests[0].jev_calls == []


async def test_jev_taint_sees_the_reads_that_came_before(tmp_path: Path, graph_db: Graph) -> None:
    jev = FakeJev(derived=False)
    gateway, engine = build(tmp_path, graph_db, jev, taint=Taint.jev, payload=issue_payload())

    await call_read(gateway)
    await call_comment(gateway)

    assert len(jev.derived_calls) == 1
    state = jev.derived_calls[0]["state"]
    assert state.sources
    assert next(iter(state.sources.values())).source.id == "acme/widgets#1"
    # The jev column runs the classifier alone: the deterministic task taint is
    # off even though the task read an external source.
    assert engine.requests[1].provenance.has_external is False


async def test_jev_only_asks_for_every_call(tmp_path: Path, graph_db: Graph) -> None:
    jev = FakeJev(choice="deny")
    gateway, engine = build(tmp_path, graph_db, jev, mode=Mode.jev_only)

    await call_read(gateway)
    await call_comment(gateway)

    assert len(jev.disposition_calls) == 2
    assert jev.derived_calls == []
    assert [request.jev_choice for request in engine.requests] == ["deny", "deny"]


async def test_the_decision_line_carries_the_jev_cost(tmp_path: Path, graph_db: Graph) -> None:
    jev = FakeJev(derived=True)
    gateway, engine = build(tmp_path, graph_db, jev, taint=Taint.jev)

    await call_comment(gateway)

    decisions = engine.decision_log.read("task-1")
    assert len(decisions) == 1
    call = decisions[0].request.jev_calls[0]
    assert call.model == "jev-test"
    assert call.latency_ms == 12.5
    assert call.input_tokens == 10
    assert call.cost_usd == pytest.approx(0.00000042)
