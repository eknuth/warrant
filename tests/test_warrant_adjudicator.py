"""The adjudicator: its structured output, its checks, and its prompt.

Every test here runs with a fake provider and no stack. The checks are the
point: a verdict is a claim until `validate` has compared it with the ledger and
the task's subject, and these tests pin what is rejected and why.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from agents.providers import ToolSchema, ToolUse, Turn, Usage
from warrant.adjudicator import (
    PROMPT_PATH,
    VERDICT_TOOL_NAME,
    AdjudicatorSettings,
    EscalationAdjudicator,
    adjudicate,
    render_case,
    validate,
    verdict_args,
    verdict_tool,
)
from warrant.models import (
    ActionKind,
    AdjudicationDecision,
    AdjudicatorVerdict,
    AuthzRequest,
    Provenance,
    Source,
    Tier,
)
from warrant.subjects import SubjectDoc

PROMPT_FORBIDDEN = ("widgets", "vault", "INC-42")


class FakeProvider:
    """A provider that returns one canned turn and records the messages."""

    name = "fake"
    model = "fake-model"
    effort = "max"

    def __init__(self, turn: Turn) -> None:
        self.turn = turn
        self.calls: list[tuple[list[Turn], list[ToolSchema]]] = []

    async def run(self, messages: list[Turn], tools: list[ToolSchema]) -> Turn:
        self.calls.append((messages, tools))
        return self.turn


def verdict_turn(**args: Any) -> Turn:
    return Turn(
        role="assistant",
        tool_uses=[ToolUse(id="call-1", name=VERDICT_TOOL_NAME, args=args)],
        usage=Usage(),
    )


def ticket_provenance() -> Provenance:
    return Provenance(
        task_id="task-1",
        sources=[
            Source(
                system="db",
                kind="ticket",
                id="42",
                author="ops@customer.test",
                author_tier=Tier.customer,
                digest="sha256:ticket",
            ),
            Source(
                system="db",
                kind="customer",
                id="1",
                author="alice",
                author_tier=Tier.member,
                digest="sha256:customer",
            ),
        ],
    )


def ticket_subject(*, incident_id: str | None = "INC-42") -> SubjectDoc:
    return SubjectDoc(
        system="db",
        kind="ticket",
        id="42",
        title="Our API key leaked into a build log",
        body="Please rotate the key.",
        author="ops@customer.test",
        tier=Tier.customer,
        incident_id=incident_id,
    )


def approval(**overrides: Any) -> AdjudicatorVerdict:
    data: dict[str, Any] = {
        "decision": "approve",
        "time_box_minutes": 15,
        "cited_sources": ["42"],
        "cited_subject": "42",
        "rationale": "ticket 42 asks for the rotation",
    }
    data.update(overrides)
    return AdjudicatorVerdict.model_validate(data)


# -- the shape --------------------------------------------------------------


def test_an_approval_needs_a_time_box() -> None:
    with pytest.raises(ValueError, match="time_box_minutes"):
        AdjudicatorVerdict.model_validate(
            {"decision": "approve", "cited_sources": ["42"], "cited_subject": "42"}
        )


@pytest.mark.parametrize("minutes", [0, 61, -5])
def test_a_time_box_outside_the_bounds_is_refused(minutes: int) -> None:
    with pytest.raises(ValueError, match="time_box_minutes"):
        approval(time_box_minutes=minutes)


def test_a_deny_needs_no_time_box() -> None:
    verdict = AdjudicatorVerdict.model_validate(
        {"decision": "deny", "cited_sources": ["42"], "cited_subject": "42"}
    )

    assert verdict.time_box_minutes is None


def test_the_tool_schema_is_the_model() -> None:
    tool = verdict_tool()
    schema = tool.input_schema

    assert tool.name == VERDICT_TOOL_NAME
    assert schema["type"] == "object"
    assert set(schema["properties"]) == {
        "decision",
        "time_box_minutes",
        "cited_sources",
        "cited_subject",
        "rationale",
    }


def test_verdict_args_takes_the_matching_call() -> None:
    turn = verdict_turn(decision="defer", cited_sources=[], cited_subject="42")

    assert verdict_args(turn) == {"decision": "defer", "cited_sources": [], "cited_subject": "42"}


def test_verdict_args_is_none_without_the_call() -> None:
    assert verdict_args(Turn(role="assistant", text="no tool call")) is None


# -- the checks -------------------------------------------------------------


def test_a_cited_approval_stands() -> None:
    accepted, reason = validate(approval(), ticket_provenance(), ticket_subject())

    assert reason == ""
    assert accepted is not None
    assert accepted.decision is AdjudicationDecision.approve


def test_a_fabricated_source_is_refused() -> None:
    accepted, reason = validate(
        approval(cited_sources=["source-that-does-not-exist"]),
        ticket_provenance(),
        ticket_subject(),
    )

    assert accepted is None
    assert "not in the task's ledger" in reason
    assert "source-that-does-not-exist" in reason


@pytest.mark.parametrize("spelling", ["42", "ticket:42", "#42"])
def test_a_cited_subject_can_be_a_ticket_prefix_or_hash(spelling: str) -> None:
    accepted, reason = validate(
        approval(cited_subject=spelling), ticket_provenance(), ticket_subject()
    )

    assert accepted is not None, spelling
    assert reason == ""


def test_a_citation_naming_the_customer_row_is_not_the_subject() -> None:
    accepted, reason = validate(
        approval(cited_sources=["1"], cited_subject="1"), ticket_provenance(), ticket_subject()
    )

    assert accepted is None
    assert "subject" in reason


def test_an_approval_without_the_incident_is_refused() -> None:
    accepted, reason = validate(
        approval(cited_sources=["42"], rationale="ticket 42 asks for the rotation"),
        ticket_provenance(),
        ticket_subject(),
        incident_id="INC-42",
    )

    assert accepted is None
    assert "does not name the task's incident" in reason


def test_an_approval_whose_subject_declares_another_incident_is_refused() -> None:
    accepted, reason = validate(
        approval(cited_sources=["42", "INC-99"], rationale="INC-99"),
        ticket_provenance(),
        ticket_subject(incident_id="INC-99"),
        incident_id="INC-42",
    )

    assert accepted is None
    assert "INC-42" in reason


def test_an_approval_naming_the_incident_in_its_rationale_stands() -> None:
    accepted, _ = validate(
        approval(cited_sources=["42"], rationale="INC-42 is the declared incident"),
        ticket_provenance(),
        ticket_subject(),
        incident_id="INC-42",
    )

    assert accepted is not None


def test_a_deny_with_a_ledger_source_stands() -> None:
    verdict = AdjudicatorVerdict.model_validate(
        {
            "decision": "deny",
            "cited_sources": ["42"],
            "cited_subject": "42",
            "rationale": "the request traces to external content",
        }
    )
    accepted, reason = validate(verdict, ticket_provenance(), ticket_subject())

    assert accepted is not None
    assert reason == ""


def test_a_defer_is_taken_as_it_is() -> None:
    verdict = AdjudicatorVerdict(decision=AdjudicationDecision.defer)
    accepted, reason = validate(verdict, ticket_provenance(), ticket_subject())

    assert accepted is not None
    assert reason == ""


def test_a_deny_citing_nothing_is_refused() -> None:
    verdict = AdjudicatorVerdict(decision=AdjudicationDecision.deny)
    accepted, reason = validate(verdict, ticket_provenance(), ticket_subject())

    assert accepted is None
    assert "not in the task's ledger" in reason


# -- the model call ---------------------------------------------------------


async def test_adjudicate_returns_the_accepted_verdict(
    make_request: Callable[..., AuthzRequest],
) -> None:
    request = make_request()
    provider = FakeProvider(
        verdict_turn(
            decision="approve",
            time_box_minutes=15,
            cited_sources=["42"],
            cited_subject="42",
            rationale="ticket 42 asks for the rotation",
        )
    )

    result = await adjudicate(
        request,
        ticket_provenance(),
        ticket_subject(),
        reasons=["real action denied: db.rotate_api_key (write)"],
        provider=provider,
    )

    assert result is not None
    assert result.decision is AdjudicationDecision.approve
    messages, tools = provider.calls[0]
    assert tools[0].name == VERDICT_TOOL_NAME
    assert "real action denied" in messages[1].text
    assert "42 | db | ticket" in messages[1].text
    assert "Our API key leaked" in messages[1].text


async def test_adjudicate_returns_none_for_a_rejected_verdict(
    make_request: Callable[..., AuthzRequest],
) -> None:
    provider = FakeProvider(
        verdict_turn(
            decision="approve",
            time_box_minutes=15,
            cited_sources=["made-up"],
            cited_subject="42",
            rationale="trust me",
        )
    )

    result = await adjudicate(
        make_request(), ticket_provenance(), ticket_subject(), provider=provider
    )

    assert result is None


async def test_review_keeps_the_raw_arguments_of_a_rejected_verdict(
    make_request: Callable[..., AuthzRequest],
) -> None:
    provider = FakeProvider(
        verdict_turn(decision="approve", time_box_minutes=15, cited_sources=["nope"])
    )
    client = EscalationAdjudicator(provider=provider)

    attempt = await client.review(make_request(), ticket_provenance(), ticket_subject())

    assert attempt.verdict is None
    assert attempt.raw is not None
    assert attempt.raw["cited_sources"] == ["nope"]
    assert "not in the task's ledger" in attempt.reason


async def test_review_reports_a_missing_tool_call(
    make_request: Callable[..., AuthzRequest],
) -> None:
    client = EscalationAdjudicator(provider=FakeProvider(Turn(role="assistant", text="hello")))

    attempt = await client.review(make_request(), ticket_provenance(), ticket_subject())

    assert attempt.verdict is None
    assert attempt.reason == "the adjudicator returned no verdict tool call"
    assert attempt.latency_ms >= 0.0


async def test_a_provider_that_cannot_be_built_is_a_deferral(
    make_request: Callable[..., AuthzRequest],
) -> None:
    client = EscalationAdjudicator()

    def explode() -> None:
        raise ValueError("DEEPSEEK_API_KEY is not set; add it to .env")

    client.provider = explode  # type: ignore[method-assign]

    attempt = await client.review(make_request(), ticket_provenance(), ticket_subject())

    assert attempt.verdict is None
    assert "no adjudicator provider" in attempt.reason


def test_the_default_provider_is_built_with_the_output_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The path the gateway uses, not an injected provider.

    A wrong keyword here fails at the first escalation and the call silently
    defers, which is what this test exists to catch.
    """
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-not-a-secret")

    client = EscalationAdjudicator(
        settings=AdjudicatorSettings(
            adjudicator_model="deepseek:deepseek-flash@max",
            adjudicator_max_tokens=1234,
        )
    )

    assert client.provider()._max_tokens == 1234


# -- the prompt and the rendered case ---------------------------------------


def test_the_prompt_names_the_inputs_and_the_rules() -> None:
    text = PROMPT_PATH.read_text(encoding="utf-8")

    for phrase in (
        "provenance ledger",
        "subject",
        "record_verdict",
        "external",
        "time_box_minutes",
        "cited_sources",
        "cited_subject",
    ):
        assert phrase in text, phrase


def test_the_prompt_carries_no_scenario_text() -> None:
    text = PROMPT_PATH.read_text(encoding="utf-8").casefold()

    for word in PROMPT_FORBIDDEN:
        assert word.casefold() not in text, word


def test_the_prompt_uses_the_ledger_tiers() -> None:
    """The deny rule names the two tiers Warrant treats as unverified.

    "Outside the org" was the first wording, and a model read a customer in a
    support ticket as an outsider and refused a call the truth expects to reach
    a person. The rule names the tiers instead, and `customer` is stated as a
    known correspondent.
    """
    text = PROMPT_PATH.read_text(encoding="utf-8")
    folded = text.casefold()

    for tier in ("owner", "member", "customer", "external", "unknown"):
        assert f"`{tier}`" in text, tier
    assert "outside the org" not in folded


def test_render_case_labels_every_input(make_request: Callable[..., AuthzRequest]) -> None:
    request = make_request(
        tool="db.rotate_api_key",
        action_kind=ActionKind.write,
        resource="db-customer-1",
        provenance=ticket_provenance(),
    )

    rendered = render_case(request, ticket_provenance(), ticket_subject(), ["scope-collapse"])

    assert "- tool: db.rotate_api_key" in rendered
    assert "- scope-collapse" in rendered
    assert "- 42 | db | ticket | ops@customer.test | customer" in rendered
    assert "## The subject (id 42)" in rendered
    assert "incident: INC-42" in rendered
