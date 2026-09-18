"""The gateway's escalation path: the adjudicator, the grant, and the queue.

The engine is a fake that returns `escalate`, the adjudicator is a fake that
returns a chosen answer, and the subject fetch is a fake, so these tests need no
stack and no model. What they pin is the record: which decision lines are
written, which verdicts reach `adjudications.jsonl`, and which calls reach the
human queue.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from agents.providers import ToolSchema, ToolUse, Turn, Usage
from evals.state import Adjudication as RecordedAdjudication
from tests.test_gateway import FakeEngine, FakeUpstream, claims_for, make_gateway
from warrant.adjudicator import (
    VERDICT_TOOL_NAME,
    Adjudication,
    EscalationAdjudicator,
)
from warrant.gateway import Gateway, UpstreamServer
from warrant.grants import SOURCE_ADJUDICATOR, GrantStore
from warrant.graph import Graph
from warrant.graph import load as load_graph
from warrant.log import DecisionLog
from warrant.models import (
    AdjudicationDecision,
    AdjudicatorVerdict,
    AuthzRequest,
    Provenance,
    Source,
    Tier,
    Verdict,
)
from warrant.queue import Queue
from warrant.subjects import SubjectDoc, SubjectRef

SEED = Path(__file__).resolve().parents[1] / "infra" / "graph.yml"
NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)
POSTGRES = UpstreamServer(
    name="postgres-mcp", prefix="db", url="http://127.0.0.1:1/mcp", audience="postgres-mcp"
)

POSTGRES_ARGS = {"customer_id": 1, "key_id": 1}
ROTATE = "db.rotate_api_key"
_DEFAULT_SUBJECT = object()


@pytest.fixture
def graph_db(tmp_path: Path) -> Iterator[Graph]:
    with load_graph(SEED, tmp_path / "warrant.db") as opened:
        yield opened


def ticket_source() -> Source:
    return Source(
        system="db",
        kind="ticket",
        id="42",
        author="ops@customer.test",
        author_tier=Tier.customer,
        digest="sha256:ticket",
    )


def ticket_subject() -> SubjectDoc:
    return SubjectDoc(
        system="db",
        kind="ticket",
        id="42",
        title="Our API key leaked into a build log",
        body="Please rotate the key.",
        author="ops@customer.test",
        tier=Tier.customer,
        incident_id="INC-42",
    )


def approved() -> AdjudicatorVerdict:
    return AdjudicatorVerdict(
        decision=AdjudicationDecision.approve,
        time_box_minutes=15,
        cited_sources=["42"],
        cited_subject="42",
        rationale="ticket 42 asks for the rotation; INC-42 is the declared incident",
    )


class FakeAdjudicator:
    """An `AdjudicatorClient` that returns one answer and records its calls."""

    def __init__(self, adjudication: Adjudication) -> None:
        self.adjudication = adjudication
        self.calls: list[tuple[AuthzRequest, Provenance, SubjectDoc, Sequence[str]]] = []

    async def review(
        self,
        req: AuthzRequest,
        ledger: Provenance,
        subject: SubjectDoc,
        *,
        reasons: Sequence[str] = (),
    ) -> Adjudication:
        self.calls.append((req, ledger, subject, tuple(reasons)))
        return self.adjudication


class FakeSubjects:
    """A subject fetcher that returns one document and records the refs."""

    def __init__(self, subject: SubjectDoc | None) -> None:
        self.subject = subject
        self.refs: list[SubjectRef] = []

    async def __call__(self, ref: SubjectRef, /) -> SubjectDoc | None:
        self.refs.append(ref)
        return self.subject


class FakeProvider:
    """A provider that returns one canned tool call."""

    name = "fake"
    model = "fake-model"
    effort = "max"

    def __init__(self, args: dict[str, Any] | None) -> None:
        self.args = args

    async def run(self, messages: list[Turn], tools: list[ToolSchema]) -> Turn:
        uses = (
            []
            if self.args is None
            else [ToolUse(id="call-1", name=VERDICT_TOOL_NAME, args=self.args)]
        )
        return Turn(role="assistant", tool_uses=uses, usage=Usage())


def escalating_engine(log: DecisionLog) -> FakeEngine:
    return FakeEngine(
        decision_log=log,
        verdict=Verdict.escalate,
        policy_ids=["scope-collapse", "escalate-incident"],
        reasons=["real action denied: db.rotate_api_key (write)"],
    )


def build(
    tmp_path: Path,
    graph: Graph,
    adjudication: Adjudication,
    *,
    subject: SubjectDoc | None | object = _DEFAULT_SUBJECT,
    source: Source | None = None,
    now: datetime = NOW,
) -> tuple[Gateway, FakeEngine, FakeAdjudicator, FakeSubjects, FakeUpstream]:
    log = DecisionLog(tmp_path / "runs")
    engine = escalating_engine(log)
    adjudicator = FakeAdjudicator(adjudication)
    subjects = FakeSubjects(ticket_subject() if subject is _DEFAULT_SUBJECT else subject)  # type: ignore[arg-type]
    upstream = FakeUpstream()
    gateway = make_gateway(
        tmp_path,
        graph,
        engine,
        servers=[POSTGRES],
        upstream=upstream,
        now=lambda: now,
        adjudicator=adjudicator,
        subject_fetcher=subjects,
    )
    gateway.ledger.record(
        "task-1", "triage-agent", source if source is not None else ticket_source()
    )
    return gateway, engine, adjudicator, subjects, upstream


async def call(gateway: Gateway, tool: str = ROTATE, args: dict[str, Any] | None = None) -> Any:
    return await gateway.call_tool(
        tool,
        args if args is not None else dict(POSTGRES_ARGS),
        claims=claims_for(),
        token="",
    )


# -- approve ----------------------------------------------------------------


async def test_an_approved_escalation_mints_a_grant_and_forwards(
    tmp_path: Path, graph_db: Graph
) -> None:
    gateway, _, adjudicator, subjects, upstream = build(
        tmp_path, graph_db, Adjudication(verdict=approved())
    )

    result = await call(gateway)

    assert result.is_error is False
    assert len(upstream.calls) == 1
    assert subjects.refs[0].id == "42"
    request, ledger, subject, reasons = adjudicator.calls[0]
    assert request.tool == ROTATE
    assert ledger.sources[0].id == "42"
    assert subject.incident_id == "INC-42"
    assert reasons == ("real action denied: db.rotate_api_key (write)",)

    decisions = gateway.decision_log.read("task-1")
    assert [decision.verdict for decision in decisions] == [Verdict.escalate, Verdict.allow]
    assert decisions[0].adjudication is not None
    assert decisions[0].adjudication.decision is AdjudicationDecision.approve
    assert decisions[0].policy_ids == ["scope-collapse", "escalate-incident"]
    grants = GrantStore(gateway.runs_dir).read()
    assert len(grants) == 1
    assert grants[0].source == SOURCE_ADJUDICATOR
    assert grants[0].minutes == 15
    assert grants[0].tool == ROTATE
    assert decisions[1].policy_ids == [f"grant:{grants[0].id}"]


async def test_the_accepted_verdict_is_written_where_the_grader_reads_it(
    tmp_path: Path, graph_db: Graph
) -> None:
    gateway, _, _, _, _ = build(tmp_path, graph_db, Adjudication(verdict=approved()))

    await call(gateway)

    path = gateway.runs_dir / "task-1" / "adjudications.jsonl"
    assert path.exists()
    line = path.read_text(encoding="utf-8").strip()
    record = RecordedAdjudication.model_validate_json(line)
    assert record.decision == "approve"
    assert record.time_box_minutes == 15
    assert record.cited_sources == ["42"]
    assert record.cited_subject == "42"
    assert record.rationale


# -- deny and defer ---------------------------------------------------------


async def test_a_refused_escalation_returns_the_reason_and_does_not_forward(
    tmp_path: Path, graph_db: Graph
) -> None:
    refusal = AdjudicatorVerdict(
        decision=AdjudicationDecision.deny,
        cited_sources=["42"],
        cited_subject="42",
        rationale="the ticket does not ask for this rotation",
    )
    gateway, _, _, _, upstream = build(tmp_path, graph_db, Adjudication(verdict=refusal))

    result = await call(gateway)

    assert result.is_error is True
    assert result.content[0].text == "the ticket does not ask for this rotation"
    assert upstream.calls == []
    decisions = gateway.decision_log.read("task-1")
    assert [decision.verdict for decision in decisions] == [Verdict.escalate, Verdict.deny]
    assert decisions[0].adjudication is not None
    assert decisions[1].policy_ids == []
    assert (gateway.runs_dir / "task-1" / "adjudications.jsonl").exists()
    assert not (gateway.runs_dir / "queue.jsonl").exists()


async def test_a_deferred_escalation_waits_for_a_person(tmp_path: Path, graph_db: Graph) -> None:
    deferral = AdjudicatorVerdict(
        decision=AdjudicationDecision.defer, rationale="not enough evidence"
    )
    gateway, _, _, _, upstream = build(tmp_path, graph_db, Adjudication(verdict=deferral))

    result = await call(gateway)

    assert result.is_error is True
    assert result.content[0].text == "escalated: pending human review"
    assert upstream.calls == []
    decisions = gateway.decision_log.read("task-1")
    assert len(decisions) == 1
    assert decisions[0].verdict is Verdict.escalate
    assert decisions[0].adjudication is not None
    assert decisions[0].adjudication.decision is AdjudicationDecision.defer
    assert not (gateway.runs_dir / "task-1" / "adjudications.jsonl").exists()
    pending = Queue(gateway.runs_dir).pending()
    assert len(pending) == 1
    assert pending[0].request.tool == ROTATE
    assert pending[0].reason == "not enough evidence"


async def test_a_rejected_verdict_lands_in_the_queue_with_its_reason(
    tmp_path: Path, graph_db: Graph
) -> None:
    """The acceptance criterion: a fabricated citation is discarded, not honored."""
    log = DecisionLog(tmp_path / "runs")
    provider = FakeProvider(
        {
            "decision": "approve",
            "time_box_minutes": 15,
            "cited_sources": ["fabricated-source-id"],
            "cited_subject": "42",
            "rationale": "trust me",
        }
    )
    gateway = make_gateway(
        tmp_path,
        graph_db,
        escalating_engine(log),
        servers=[POSTGRES],
        upstream=FakeUpstream(),
        now=lambda: NOW,
        adjudicator=EscalationAdjudicator(provider=provider),
        subject_fetcher=FakeSubjects(ticket_subject()),
    )
    gateway.ledger.record("task-1", "triage-agent", ticket_source())

    result = await call(gateway)

    assert result.content[0].text == "escalated: pending human review"
    decisions = gateway.decision_log.read("task-1")
    assert decisions[0].adjudication is None
    assert not (gateway.runs_dir / "task-1" / "adjudications.jsonl").exists()
    pending = Queue(gateway.runs_dir).pending()
    assert len(pending) == 1
    assert "not in the task's ledger" in pending[0].reason
    assert pending[0].raw is not None
    assert pending[0].raw["cited_sources"] == ["fabricated-source-id"]


async def test_a_failed_subject_fetch_defers_the_call(tmp_path: Path, graph_db: Graph) -> None:
    gateway, _, adjudicator, _, upstream = build(
        tmp_path, graph_db, Adjudication(verdict=approved()), subject=None
    )

    result = await call(gateway)

    assert result.content[0].text == "escalated: pending human review"
    assert adjudicator.calls == []
    assert upstream.calls == []
    assert "could not be fetched" in Queue(gateway.runs_dir).pending()[0].reason


async def test_a_ledger_with_no_subject_defers_the_call(tmp_path: Path, graph_db: Graph) -> None:
    """A read that is not a ticket or issue is context, not a subject."""
    customer = Source(
        system="db",
        kind="customer",
        id="1",
        author="alice",
        author_tier=Tier.member,
        digest="sha256:customer",
    )
    gateway, _, adjudicator, _, _ = build(
        tmp_path, graph_db, Adjudication(verdict=approved()), source=customer
    )

    result = await call(gateway)

    assert result.content[0].text == "escalated: pending human review"
    assert adjudicator.calls == []
    assert "names no ticket or issue" in Queue(gateway.runs_dir).pending()[0].reason


# -- grants before the engine -----------------------------------------------


async def test_a_minted_grant_allows_its_call_without_the_engine(
    tmp_path: Path, graph_db: Graph
) -> None:
    gateway, engine, adjudicator, _, upstream = build(
        tmp_path, graph_db, Adjudication(verdict=approved()), now=NOW + timedelta(minutes=1)
    )
    grant = GrantStore(gateway.runs_dir).mint(
        task_id="task-1", tool=ROTATE, resource="1", minutes=10, now=NOW
    )

    result = await call(gateway)

    assert result.is_error is False
    assert engine.requests == [], "the grant answers before the engine"
    assert adjudicator.calls == [], "and before the adjudicator"
    assert len(upstream.calls) == 1
    decisions = gateway.decision_log.read("task-1")
    assert len(decisions) == 1
    assert decisions[0].verdict is Verdict.allow
    assert decisions[0].policy_ids == [f"grant:{grant.id}"]


async def test_an_expired_grant_does_not_allow_the_call(tmp_path: Path, graph_db: Graph) -> None:
    deferral = Adjudication(verdict=AdjudicatorVerdict(decision=AdjudicationDecision.defer))
    gateway, engine, adjudicator, _, _ = build(
        tmp_path, graph_db, deferral, now=NOW + timedelta(minutes=11)
    )
    GrantStore(gateway.runs_dir).mint(
        task_id="task-1", tool=ROTATE, resource="1", minutes=10, now=NOW
    )

    result = await call(gateway)

    assert result.content[0].text == "escalated: pending human review"
    assert len(engine.requests) == 1, "past its expiry the call is evaluated again"
    assert len(adjudicator.calls) == 1


async def test_a_grant_for_another_tool_does_not_allow_this_one(
    tmp_path: Path, graph_db: Graph
) -> None:
    gateway, engine, _, _, _ = build(tmp_path, graph_db, Adjudication(verdict=approved()))
    GrantStore(gateway.runs_dir).mint(
        task_id="task-1", tool="db.update_ticket", resource="1", minutes=10, now=NOW
    )

    await call(gateway)

    assert len(engine.requests) == 1


async def test_a_grant_for_another_resource_does_not_allow_this_one(
    tmp_path: Path, graph_db: Graph
) -> None:
    gateway, engine, _, _, _ = build(tmp_path, graph_db, Adjudication(verdict=approved()))
    GrantStore(gateway.runs_dir).mint(
        task_id="task-1", tool=ROTATE, resource="2", minutes=10, now=NOW
    )

    await call(gateway)

    assert len(engine.requests) == 1
