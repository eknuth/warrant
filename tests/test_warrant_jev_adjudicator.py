"""W26's Jev adjudicator: typed selections behind the adjudicator interface.

The endpoint is a `MockTransport`, so these tests spend nothing and assert the
exact selections the adjudicator would ask for. The point they pin is that a
citation is a choice from the ledger's own ids and that an answer outside that
set is a deferral, not a citation that later validation has to catch.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from warrant import jev
from warrant.adjudicator import (
    ADJUDICATOR_JEV,
    AdjudicatorSettings,
    EscalationAdjudicator,
    JevAdjudicator,
    assemble_rationale,
    build_adjudicator,
)
from warrant.jev import JevClient, JevSettings
from warrant.models import (
    ActionKind,
    AdjudicationDecision,
    AuthzRequest,
    Chain,
    JevCall,
    Provenance,
    Source,
    Tier,
)
from warrant.subjects import SubjectDoc

KEY = "test-key-not-a-real-credential"


def ticket_source() -> Source:
    return Source(
        system="db",
        kind="ticket",
        id="42",
        author="ops@customer.test",
        author_tier=Tier.customer,
        digest="sha256:ticket",
    )


def customer_source() -> Source:
    return Source(
        system="db",
        kind="customer",
        id="1",
        author="alice",
        author_tier=Tier.member,
        digest="sha256:customer",
    )


def ticket_ledger() -> Provenance:
    return Provenance(task_id="task-1", sources=[ticket_source(), customer_source()])


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


def request_for(*, incident_id: str | None = "INC-42") -> AuthzRequest:
    chain = Chain(
        sub="h-alice",
        act="incident-agent",
        task_id="task-1",
        scopes=["incident_id:INC-42"],
        groups=["owners"],
        token_exp=datetime(2030, 1, 1, tzinfo=UTC),
        incident_id=incident_id,
    )
    return AuthzRequest(
        chain=chain,
        tool="db.rotate_api_key",
        action_kind=ActionKind.write,
        resource="db-customer-1",
        args_digest="sha256:args",
        provenance=ticket_ledger(),
        ts=datetime.now(UTC),
    )


def adjudication_response(
    *,
    decision: str = "approve",
    level: int = 2,
    evidence: str = "42",
    subject: str = "42",
    incident: str = "INC-42",
) -> dict[str, Any]:
    return {
        "model": "jev-1.13.0",
        "answers": {
            jev.ADJUDICATE_QUESTION: {
                "type": "choice",
                "choice": decision,
                "confidence": 0.9,
                "probabilities": {decision: 0.9},
            },
            jev.TIME_BOX_QUESTION: {
                "type": "score",
                "score": float(level),
                "confidence": 0.8,
                "legend": {str(i): text for i, text in enumerate(jev.TIME_BOX_CRITERIA)},
                "probabilities": {
                    str(index): (1.0 if index == level else 0.0)
                    for index in range(len(jev.TIME_BOX_LEVELS))
                },
            },
            jev.EVIDENCE_QUESTION: {
                "type": "choice",
                "choice": evidence,
                "confidence": 0.9,
                "probabilities": {evidence: 0.9},
            },
            jev.SUBJECT_QUESTION: {
                "type": "choice",
                "choice": subject,
                "confidence": 0.9,
                "probabilities": {subject: 0.9},
            },
            jev.INCIDENT_QUESTION: {
                "type": "choice",
                "choice": incident,
                "confidence": 0.9,
                "probabilities": {incident: 0.9},
            },
        },
        "usage": {"input_tokens": 1_000_000, "output_tokens": 5},
    }


def client(responder: Callable[[httpx.Request], httpx.Response]) -> JevClient:
    settings = JevSettings(
        jev_api_key=KEY,
        jev_url="https://jev.test/v1/systemone",
        jev_model="jev-latest",
    )
    return JevClient(settings=settings, transport=httpx.MockTransport(responder))


def adjudicator(responder: Callable[[httpx.Request], httpx.Response]) -> JevAdjudicator:
    settings = AdjudicatorSettings(adjudicator=ADJUDICATOR_JEV)
    return JevAdjudicator(settings=settings, client=client(responder))


def test_both_adjudicators_implement_the_same_review_signature() -> None:
    """The gateway selects one per run, so an identical escalation answers both."""
    deepseek = inspect.signature(EscalationAdjudicator.review)
    jev_adjudicator = inspect.signature(JevAdjudicator.review)

    assert list(deepseek.parameters) == list(jev_adjudicator.parameters)
    assert deepseek.return_annotation == jev_adjudicator.return_annotation


async def test_an_approval_cites_the_ledger_and_records_its_cost() -> None:
    def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=adjudication_response(level=2))

    request = request_for()

    attempt = await adjudicator(respond).review(request, ticket_ledger(), ticket_subject())

    assert attempt.verdict is not None
    assert attempt.verdict.decision is AdjudicationDecision.approve
    assert attempt.verdict.time_box_minutes == 15
    assert attempt.verdict.cited_sources == ["42"]
    assert attempt.verdict.cited_subject == "42"
    assert "incident INC-42" in attempt.verdict.rationale
    assert attempt.latency_ms >= 0.0
    assert attempt.input_tokens == 1_000_000
    assert attempt.cost_usd == pytest.approx(0.042)
    assert len(attempt.jev_calls) == 1
    assert attempt.jev_calls[0].rule == "adjudicate"
    assert attempt.jev_calls[0].score == 2.0
    # The call is on the adjudication, not the shared request, so the grant
    # allow line cannot repeat it.
    assert request.jev_calls == []


async def test_a_citation_by_selection_cannot_name_an_id_outside_the_ledger() -> None:
    """An answer outside the option set is no citation, so validation refuses it."""
    captured: dict[str, Any] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.read()))
        return httpx.Response(
            200,
            json=adjudication_response(evidence="source-that-does-not-exist"),
        )

    attempt = await adjudicator(respond).review(request_for(), ticket_ledger(), ticket_subject())

    assert attempt.verdict is None
    assert "not in the task's ledger" in attempt.reason
    # The invented id is dropped before validation sees it: the verdict carries
    # no citation rather than one naming a source the ledger does not hold.
    assert attempt.raw is not None
    assert attempt.raw["cited_sources"] == []
    # The option set the endpoint saw held only ledger ids, so the answer could
    # not have been the invented id in the first place.
    options = captured["questions"][jev.EVIDENCE_QUESTION]["criteria"]
    assert set(options) == {"42", "1"}
    assert "source-that-does-not-exist" not in options


async def test_a_deny_with_a_ledger_citation_stands() -> None:
    def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=adjudication_response(decision="deny"))

    attempt = await adjudicator(respond).review(request_for(), ticket_ledger(), ticket_subject())

    assert attempt.verdict is not None
    assert attempt.verdict.decision is AdjudicationDecision.deny
    assert attempt.verdict.time_box_minutes is None


async def test_a_defer_is_taken_as_it_is() -> None:
    def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=adjudication_response(decision="defer", level=0))

    request = request_for()
    attempt = await adjudicator(respond).review(request, ticket_ledger(), ticket_subject())

    assert attempt.verdict is not None
    assert attempt.verdict.decision is AdjudicationDecision.defer
    assert attempt.jev_calls[0].choice == "defer"


async def test_a_failed_call_defers_and_records_the_error() -> None:
    def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="upstream is down")

    request = request_for()
    attempt = await adjudicator(respond).review(request, ticket_ledger(), ticket_subject())

    assert attempt.verdict is None
    assert "failed" in attempt.reason
    assert attempt.jev_calls[0].error
    assert attempt.jev_calls[0].cost_usd == 0.0


async def test_an_approval_without_the_incident_defers() -> None:
    def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=adjudication_response(incident=jev.NONE_OPTION))

    attempt = await adjudicator(respond).review(request_for(), ticket_ledger(), ticket_subject())

    assert attempt.verdict is None
    assert "incident" in attempt.reason


def test_the_rationale_is_assembled_from_the_selections() -> None:
    answer = jev.AdjudicationAnswer(
        decision="approve",
        confidence=0.9,
        decision_probabilities={},
        time_box=15,
        score=2.0,
        score_probabilities={},
        evidence="42",
        subject="42",
        incident="INC-42",
        evidence_options=("42", "1"),
        evidence_dropped=0,
        call=JevCall(rule="adjudicate"),
        answers={},
    )

    text = assemble_rationale(request_for(), answer)

    assert text == (
        "approve db.rotate_api_key on db-customer-1; cites 42; subject 42; "
        "incident INC-42; time box 15 minutes"
    )


def test_the_rationale_names_a_bounded_ledger_choice() -> None:
    answer = jev.AdjudicationAnswer(
        decision="approve",
        confidence=0.9,
        decision_probabilities={},
        time_box=15,
        score=2.0,
        score_probabilities={},
        evidence="42",
        subject="42",
        incident="INC-42",
        evidence_options=("42",),
        evidence_dropped=5,
        call=JevCall(rule="adjudicate"),
        answers={},
    )

    text = assemble_rationale(request_for(), answer)

    assert "ledger choice bounded to 1 of 6" in text


def test_build_adjudicator_selects_and_refuses() -> None:
    assert isinstance(
        build_adjudicator(AdjudicatorSettings(adjudicator=ADJUDICATOR_JEV)),
        JevAdjudicator,
    )
    assert isinstance(
        build_adjudicator(AdjudicatorSettings(adjudicator="deepseek")),
        EscalationAdjudicator,
    )
    with pytest.raises(ValueError, match="ADJUDICATOR"):
        build_adjudicator(AdjudicatorSettings(adjudicator="other"))
