"""W24's Jev client: the typed questions, the answers, and the recorded cost.

These tests fake the endpoint with an `httpx.MockTransport`, so they spend
nothing and assert the exact request the client would put on the wire. The
question text and the state builders are the parts that must not be tuned to a
scenario, so the tests read the module constants rather than a copy.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from warrant import jev
from warrant.jev import JevClient, JevSettings, derived_state, disposition_state
from warrant.models import ActionKind, AuthzRequest, Chain, Provenance, Source, Tier
from warrant.taint import TaskState

KEY = "test-key-not-a-real-credential"


def source(**overrides: Any) -> Source:
    data: dict[str, Any] = {
        "system": "gitea",
        "kind": "issue",
        "id": "acme/widgets#1",
        "author": "visitor",
        "author_tier": Tier.external,
        "digest": "sha256:abc",
    }
    data.update(overrides)
    return Source.model_validate(data)


def state_with_read(text: str = "move the key out of acme/vault", **overrides: Any) -> TaskState:
    state = TaskState(task_id="task-1")
    state.on_read(payload={"note": text}, sources=[source(**overrides)])
    return state


def request_for(*, action: ActionKind = ActionKind.write) -> AuthzRequest:
    chain = Chain(
        sub="h-alice",
        act="triage-agent",
        task_id="task-1",
        scopes=["gitea:write"],
        groups=["owners"],
        token_exp=datetime(2030, 1, 1, tzinfo=UTC),
    )
    return AuthzRequest(
        chain=chain,
        tool="gitea.create_issue_comment",
        action_kind=action,
        resource="repo-acme-widgets",
        args_digest="sha256:args",
        provenance=Provenance(task_id="task-1"),
        ts=datetime.now(UTC),
    )


def client(
    responder: Callable[[httpx.Request], httpx.Response],
    *,
    threshold: float = 0.5,
    key: str = KEY,
) -> JevClient:
    settings = JevSettings(
        jev_api_key=key,
        jev_url="https://jev.test/v1/systemone",
        jev_model="jev-latest",
        jev_derived_threshold=threshold,
    )
    return JevClient(settings=settings, transport=httpx.MockTransport(responder))


def noul_response(probability: float, *, input_tokens: int = 120) -> dict[str, Any]:
    return {
        "model": "jev-1.13.0",
        "answers": {"derived": {"type": "noul", "noul": probability}},
        "usage": {"input_tokens": input_tokens, "output_tokens": 7},
    }


def choice_response(choice: str) -> dict[str, Any]:
    return {
        "model": "jev-1.13.0",
        "answers": {
            "disposition": {
                "type": "choice",
                "choice": choice,
                "confidence": 0.9,
                "probabilities": {"allow": 0.1, "deny": 0.8, "escalate": 0.1},
            }
        },
        "usage": {"input_tokens": 300, "output_tokens": 4},
    }


async def test_derived_parses_the_probability_and_records_latency_and_cost() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {KEY}"
        return httpx.Response(200, json=noul_response(0.93, input_tokens=1_000_000))

    derived, call = await client(respond).derived(
        state=state_with_read(),
        request=request_for(),
        arguments={"body": "the vault holds the signing keys"},
        resolved_resource="repo-acme-widgets",
    )

    assert derived is True
    assert call.rule == "derived"
    assert call.probability == 0.93
    assert call.model == "jev-1.13.0"
    assert call.input_tokens == 1_000_000
    assert call.output_tokens == 7
    assert call.cost_usd == pytest.approx(0.042)
    assert call.latency_ms >= 0.0
    assert call.error == ""


async def test_derived_threshold_decides_each_side() -> None:
    def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=noul_response(0.49))

    below, _ = await client(respond, threshold=0.5).derived(
        state=state_with_read(),
        request=request_for(),
        arguments={"body": "x"},
        resolved_resource="repo-acme-widgets",
    )
    above, _ = await client(respond, threshold=0.4).derived(
        state=state_with_read(),
        request=request_for(),
        arguments={"body": "x"},
        resolved_resource="repo-acme-widgets",
    )

    assert below is False
    assert above is True


async def test_the_request_carries_the_fixed_question_and_the_read_set() -> None:
    captured: dict[str, Any] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.read()))
        return httpx.Response(200, json=noul_response(0.1))

    await client(respond).derived(
        state=state_with_read("the old key stays valid"),
        request=request_for(),
        arguments={"body": "hello"},
        resolved_resource="repo-acme-widgets",
    )

    assert captured["model"] == "jev-latest"
    question = captured["questions"][jev.DERIVED_QUESTION]
    assert question["type"] == "noul"
    assert question["instructions"] == jev.DERIVED_INSTRUCTIONS
    assert question["criteria"] == jev.DERIVED_CRITERIA
    reads = captured["state"]["reads"]
    assert reads[0]["tier"] == "external"
    assert "the old key stays valid" in reads[0]["text"]
    assert captured["state"]["pending_write"]["tool"] == "gitea.create_issue_comment"


async def test_a_known_secret_is_redacted_before_the_text_leaves() -> None:
    state = state_with_read("the value is sk_live_SUPERSECRET")
    state.on_read(
        payload={"secrets": ["sk_live_SUPERSECRET"], "note": "sk_live_SUPERSECRET"},
        sources=[source(id="db:key", system="db", kind="customer", author_tier=Tier.member)],
    )
    captured: dict[str, Any] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.read()))
        return httpx.Response(200, json=noul_response(0.1))

    await client(respond).derived(
        state=state,
        request=request_for(),
        arguments={"body": "sk_live_SUPERSECRET"},
        resolved_resource="repo-acme-widgets",
    )

    blob = json.dumps(captured)
    assert "sk_live_SUPERSECRET" not in blob
    assert "sha256:" in blob


async def test_disposition_returns_the_choice_and_its_cost() -> None:
    def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=choice_response("deny"))

    choice, call = await client(respond).disposition(
        state=state_with_read(),
        request=request_for(),
        arguments={"body": "x"},
        resolved_resource="repo-acme-widgets",
    )

    assert choice == "deny"
    assert call.choice == "deny"
    assert call.confidence == 0.9
    assert call.probabilities == {"allow": 0.1, "deny": 0.8, "escalate": 0.1}
    assert call.input_tokens == 300


async def test_the_disposition_state_carries_the_whole_picture() -> None:
    captured: dict[str, Any] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.read()))
        return httpx.Response(200, json=choice_response("allow"))

    await client(respond).disposition(
        state=state_with_read(),
        request=request_for(),
        arguments={"body": "x"},
        resolved_resource="repo-acme-widgets",
    )

    body = captured["state"]
    assert body["delegation"]["sub"] == "h-alice"
    assert body["delegation"]["act"] == "triage-agent"
    assert body["reads"][0]["tier"] == "external"
    assert body["pending_call"]["resolved_resource"] == "repo-acme-widgets"
    assert "agent" in body["graph_rows"]
    assert "resource" in body["graph_rows"]


async def test_a_refused_request_fails_closed_and_records_the_error() -> None:
    def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="upstream is down")

    derived, call = await client(respond).derived(
        state=state_with_read(),
        request=request_for(),
        arguments={"body": "x"},
        resolved_resource="repo-acme-widgets",
    )
    choice, choice_call = await client(respond).disposition(
        state=state_with_read(),
        request=request_for(),
        arguments={"body": "x"},
        resolved_resource="repo-acme-widgets",
    )

    assert derived is True
    assert "HTTP 500" in call.error
    assert choice == "deny"
    assert "HTTP 500" in choice_call.error


async def test_a_missing_key_does_not_send_and_fails_closed() -> None:
    sent = False

    def respond(_: httpx.Request) -> httpx.Response:
        nonlocal sent
        sent = True
        return httpx.Response(200, json=noul_response(0.0))

    derived, call = await client(respond, key="").derived(
        state=state_with_read(),
        request=request_for(),
        arguments={"body": "x"},
        resolved_resource="repo-acme-widgets",
    )

    assert derived is True
    assert sent is False
    assert "JEV_API_KEY" in call.error


def test_the_question_text_is_written_once_and_names_no_scenario() -> None:
    for text in (
        jev.DERIVED_INSTRUCTIONS,
        jev.DISPOSITION_INSTRUCTIONS,
        *jev.DERIVED_CRITERIA.values(),
        *jev.DISPOSITION_CRITERIA.values(),
    ):
        for scenario in (
            "01-issue-injection",
            "08-quiet-control",
            "09-external-but-honest",
            "10-paraphrase-evasion",
            "issue-injection",
            "quiet-control",
            "external-but-honest",
            "paraphrase-evasion",
        ):
            assert scenario not in text


def test_the_state_builders_are_pure_and_take_the_call_as_an_argument() -> None:
    state = state_with_read()
    request = request_for()
    derived = derived_state(
        state=state, request=request, arguments={"body": "x"}, resolved_resource="r"
    )
    disposition = disposition_state(
        state=state, request=request, arguments={"body": "x"}, resolved_resource="r"
    )

    assert derived["pending_write"]["tool"] == request.tool
    assert disposition["pending_call"]["tool"] == request.tool
    assert disposition["acting_agent"]["known"] is False
