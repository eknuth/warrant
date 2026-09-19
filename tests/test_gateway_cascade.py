"""W27 at the gateway: Cedar first, and Jev as a deny-only overlay on an allow.

The classifier is a fake where the point is the composition, and a real
`JevClient` over an `httpx.MockTransport` where the point is what an unreachable
or slow endpoint does. The security property is the direction of trust: a Jev
answer can subtract a Cedar allow and can never add one, and a classifier that
does not answer leaves the Cedar decision standing as `overlay: unavailable`.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.types import CallToolResult, TextContent

from evals.ablations import ABLATIONS
from tests.test_gateway import GITEA, FakeEngine, FakeUpstream, claims_for, make_gateway
from warrant.config import Mode
from warrant.engine import CASCADE_OVERLAY_POLICY_ID, CedarEngine
from warrant.graph import Graph
from warrant.graph import load as load_graph
from warrant.jev import JevClient, JevSettings
from warrant.log import DecisionLog
from warrant.models import JevCall, Verdict

SEED = Path(__file__).resolve().parents[1] / "infra" / "graph.yml"
KEY = "test-key-not-a-real-credential"


@pytest.fixture
def graph_db(tmp_path: Path) -> Iterator[Graph]:
    with load_graph(SEED, tmp_path / "warrant.db") as opened:
        yield opened


def tool_result(payload: Any) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload))], is_error=False
    )


class FakeJev:
    """A `JevClient` that answers from the test and records what it was asked."""

    def __init__(self, *, derived: bool = False, probability: float = 0.9) -> None:
        self.answer_derived = derived
        self.probability = probability
        self.derived_calls: list[dict[str, Any]] = []

    async def derived(self, **kwargs: Any) -> tuple[bool, JevCall]:
        self.derived_calls.append(kwargs)
        return self.answer_derived, JevCall(
            rule="derived",
            model="jev-test",
            latency_ms=12.5,
            input_tokens=10,
            output_tokens=2,
            cost_usd=0.00000042,
            probability=self.probability,
        )


def build(
    tmp_path: Path,
    graph: Graph,
    jev: Any,
    *,
    verdict: Verdict = Verdict.allow,
    policy_ids: list[str] | None = None,
) -> tuple[Any, FakeEngine]:
    engine = FakeEngine(
        decision_log=DecisionLog(tmp_path / "runs"),
        verdict=verdict,
        policy_ids=policy_ids,
    )
    gateway = make_gateway(
        tmp_path,
        graph,
        engine,
        servers=[GITEA],
        upstream=FakeUpstream(result=tool_result({})),
        mode=Mode.cascade,
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


async def call_visibility(gateway: Any) -> CallToolResult:
    return await gateway.call_tool(
        "gitea.set_repo_visibility",
        {"repo": "acme/widgets", "private": True},
        claims=claims_for(act="triage-agent", scope="gitea:write"),
        token="token",
    )


def offline_client(
    error: Callable[[httpx.Request], httpx.Response],
    *,
    timeout: float = 0.05,
) -> JevClient:
    """A real `JevClient` whose endpoint answers with a transport failure."""
    settings = JevSettings(
        jev_api_key=KEY,
        jev_url="https://jev.test/v1/systemone",
        jev_model="jev-latest",
        jev_derived_threshold=0.5,
    )
    return JevClient(settings=settings, transport=httpx.MockTransport(error), timeout=timeout)


# -- the direction of trust -------------------------------------------------


async def test_a_jev_allow_cannot_rescue_a_cedar_deny(tmp_path: Path, graph_db: Graph) -> None:
    """The acceptance test for the security property.

    Cedar denies, so the classifier is never asked. Even a Jev answer that would
    clear the write cannot reach the verdict, and the deny keeps exactly the
    policy id Cedar gave it.
    """
    jev = FakeJev(derived=False)
    gateway, engine = build(
        tmp_path, graph_db, jev, verdict=Verdict.deny, policy_ids=["scope-collapse"]
    )

    await call_comment(gateway)

    assert jev.derived_calls == [], "a Cedar deny must never reach the classifier"
    decisions = engine.decision_log.read("task-1")
    assert len(decisions) == 1
    assert decisions[0].verdict is Verdict.deny
    assert decisions[0].policy_ids == ["scope-collapse"]
    assert decisions[0].request.overlay == ""
    assert decisions[0].request.jev_calls == []


async def test_a_jev_deny_subtracts_a_cedar_allow(tmp_path: Path, graph_db: Graph) -> None:
    jev = FakeJev(derived=True, probability=0.72)
    gateway, engine = build(
        tmp_path, graph_db, jev, verdict=Verdict.allow, policy_ids=["permit-write"]
    )

    await call_comment(gateway)

    decisions = engine.decision_log.read("task-1")
    assert len(decisions) == 1
    decision = decisions[0]
    assert decision.verdict is Verdict.deny
    assert decision.policy_ids == ["permit-write", CASCADE_OVERLAY_POLICY_ID]
    assert any("0.72" in reason for reason in decision.reasons)
    assert decision.request.overlay == "denied"
    assert decision.request.derived is True
    assert decision.request.jev_calls[0].rule == "derived"


async def test_a_jev_clear_leaves_the_cedar_allow(tmp_path: Path, graph_db: Graph) -> None:
    jev = FakeJev(derived=False, probability=0.1)
    gateway, engine = build(
        tmp_path, graph_db, jev, verdict=Verdict.allow, policy_ids=["permit-write"]
    )

    await call_comment(gateway)

    decision = engine.decision_log.read("task-1")[0]
    assert decision.verdict is Verdict.allow
    assert decision.policy_ids == ["permit-write"]
    assert decision.request.overlay == "cleared"
    assert decision.request.derived is False


# -- what never reaches the overlay -----------------------------------------


async def test_a_read_is_never_a_candidate(tmp_path: Path, graph_db: Graph) -> None:
    jev = FakeJev(derived=True)
    gateway, engine = build(tmp_path, graph_db, jev)

    await call_read(gateway)

    assert jev.derived_calls == []
    decision = engine.decision_log.read("task-1")[0]
    assert decision.verdict is Verdict.allow
    assert decision.request.overlay == ""


async def test_an_escalate_never_reaches_the_overlay(tmp_path: Path, graph_db: Graph) -> None:
    jev = FakeJev(derived=True)
    gateway, engine = build(
        tmp_path, graph_db, jev, verdict=Verdict.escalate, policy_ids=["escalate-scope"]
    )

    await call_visibility(gateway)

    assert jev.derived_calls == []
    decision = engine.decision_log.read("task-1")[0]
    assert decision.verdict is Verdict.escalate
    assert decision.request.overlay == ""


# -- the endpoint is down or slow -------------------------------------------


def unreachable(_: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused")


def too_slow(_: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("the endpoint did not answer")


@pytest.mark.parametrize(
    ("handler", "label"),
    [(unreachable, "unreachable"), (too_slow, "slow")],
)
async def test_an_unavailable_endpoint_leaves_cedar_standing(
    tmp_path: Path, graph_db: Graph, handler: Callable[[httpx.Request], httpx.Response], label: str
) -> None:
    """The acceptance test for degradation.

    A transport failure is not a deny. Cedar's allow stands, the line records
    `overlay: unavailable`, and the failed call is still on the request with its
    error and its measured latency.
    """
    gateway, engine = build(
        tmp_path,
        graph_db,
        offline_client(handler),
        verdict=Verdict.allow,
        policy_ids=["permit-write"],
    )

    await call_comment(gateway)

    decision = engine.decision_log.read("task-1")[0]
    assert decision.verdict is Verdict.allow, label
    assert decision.policy_ids == ["permit-write"]
    assert decision.request.overlay == "unavailable"
    assert any("overlay: unavailable" in reason for reason in decision.reasons)
    assert decision.request.derived is False, "a failed call is not a derived answer"
    assert len(decision.request.jev_calls) == 1
    assert decision.request.jev_calls[0].error
    assert decision.request.jev_calls[0].latency_ms >= 0.0


async def test_real_cedar_allow_stands_when_the_overlay_is_unavailable(
    tmp_path: Path, graph_db: Graph, policy_dir: Callable[..., Path]
) -> None:
    """The same degradation with the real engine, not a fake.

    Cedar permits the write, the classifier is unreachable, and the allow the
    policy produced is the verdict that is logged, with the overlay recorded as
    unavailable beside it.
    """
    engine = CedarEngine(
        policies_dir=policy_dir('@id("permit-all")\npermit(principal, action, resource);'),
        schema_path=None,
        decision_log=DecisionLog(tmp_path / "runs"),
    )
    gateway = make_gateway(
        tmp_path,
        graph_db,
        engine,
        servers=[GITEA],
        upstream=FakeUpstream(result=tool_result({})),
        mode=Mode.cascade,
        jev=offline_client(unreachable),
    )

    await call_comment(gateway)

    decision = engine.decision_log.read("task-1")[0]
    assert decision.verdict is Verdict.allow
    assert decision.policy_ids == ["permit-all"]
    assert decision.request.overlay == "unavailable"
    assert decision.request.jev_calls[0].error


# -- the record -------------------------------------------------------------


async def test_the_decision_line_carries_the_overlay_cost(tmp_path: Path, graph_db: Graph) -> None:
    jev = FakeJev(derived=False, probability=0.2)
    gateway, engine = build(tmp_path, graph_db, jev)

    await call_comment(gateway)

    call = engine.decision_log.read("task-1")[0].request.jev_calls[0]
    assert call.model == "jev-test"
    assert call.latency_ms == 12.5
    assert call.input_tokens == 10
    assert call.cost_usd == pytest.approx(0.00000042)


def test_the_cascade_ablation_names_the_mode() -> None:
    assert ABLATIONS["cascade"].mode == "cascade"
    assert ABLATIONS["cascade"].taint == "both"
