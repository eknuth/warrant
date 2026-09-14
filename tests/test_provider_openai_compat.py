"""The OpenAI-compatible provider, against responses recorded from the endpoint.

Every recording under `tests/data/provider/` is a real chat completion
response recorded from the cloud endpoint, with nothing stripped because a
completion carries no credential. The tests replay them through a mocked
transport, so the adapter's translation and its request body are both checked
without a network and without spending tokens.

The last test in the file is the one the ticket leans on: it captures the body
the provider actually sends at each effort level and asserts the thinking toggle
and the effort field. Reading the code back would prove nothing; this reads the
bytes on the wire.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

import httpx
import pytest

from agents.providers.base import ToolResultBlock, ToolSchema, ToolUse, Turn
from agents.providers.openai_compat import OpenAICompatProvider

FIXTURES = Path(__file__).resolve().parent / "data" / "provider"

TOOLS = [
    ToolSchema(
        name="get_port",
        description="Get the port the app listens on.",
        input_schema={"type": "object", "properties": {}},
    ),
    ToolSchema(
        name="get_host",
        description="Get the hostname the app binds to.",
        input_schema={"type": "object", "properties": {}},
    ),
]


def recorded(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def message_of(body: dict[str, Any]) -> dict[str, Any]:
    return body["choices"][0]["message"]


class Transport:
    """A mocked transport that replays recorded replies and keeps the requests."""

    def __init__(self, bodies: list[dict[str, Any]]) -> None:
        self._bodies = list(bodies)
        self.requests: list[dict[str, Any]] = []
        self.http = httpx.AsyncClient(transport=httpx.MockTransport(self._handle))

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content))
        if not self._bodies:
            raise AssertionError("the provider sent more requests than were recorded")
        return httpx.Response(200, json=self._bodies.pop(0))


def provider_for_test(
    bodies: list[dict[str, Any]], effort: str = "off"
) -> tuple[OpenAICompatProvider, Transport]:
    transport = Transport(bodies)
    provider = OpenAICompatProvider(
        "https://endpoint.test",
        "test-key-not-a-secret",
        "test-model",
        effort,
        http_client=transport.http,
    )
    return provider, transport


class FlakyTransport:
    """Answers the first request with an error, then replays recorded replies."""

    def __init__(self, error: dict[str, Any], bodies: list[dict[str, Any]]) -> None:
        self._error = error
        self._bodies = list(bodies)
        self.requests: list[dict[str, Any]] = []
        self.http = httpx.AsyncClient(transport=httpx.MockTransport(self._handle))

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content))
        if len(self.requests) == 1:
            return httpx.Response(400, json=self._error)
        return httpx.Response(200, json=self._bodies.pop(0))


def flaky_provider_for_test(
    error: dict[str, Any], bodies: list[dict[str, Any]], effort: str = "high"
) -> tuple[OpenAICompatProvider, FlakyTransport]:
    transport = FlakyTransport(error, bodies)
    provider = OpenAICompatProvider(
        "https://endpoint.test",
        "test-key-not-a-secret",
        "test-model",
        effort,
        http_client=transport.http,
    )
    return provider, transport


async def test_one_tool_call_comes_back_as_one_tool_use() -> None:
    body = recorded("one_tool_call")
    provider, _ = provider_for_test([body])

    turn = await provider.run([Turn(role="user", text="Find the port.")], TOOLS)

    expected = message_of(body)["tool_calls"][0]
    assert turn.role == "assistant"
    assert turn.finish_reason == "tool_calls"
    assert [use.name for use in turn.tool_uses] == ["get_port"]
    assert turn.tool_uses[0].id == expected["id"]
    assert turn.tool_uses[0].args == {}
    assert turn.tool_uses[0].malformed is False


async def test_two_parallel_tool_calls_arrive_on_one_turn() -> None:
    body = recorded("parallel_tool_calls")
    provider, _ = provider_for_test([body])

    turn = await provider.run([Turn(role="user", text="Find both.")], TOOLS)

    assert [use.name for use in turn.tool_uses] == ["get_port", "get_host"]
    assert [use.id for use in turn.tool_uses] == [
        call["id"] for call in message_of(body)["tool_calls"]
    ]


async def test_a_text_only_final_turn_has_no_tool_uses() -> None:
    provider, _ = provider_for_test([recorded("text_final")])

    turn = await provider.run([Turn(role="user", text="Say done.")], TOOLS)

    assert turn.tool_uses == []
    assert turn.text == "done"
    assert turn.finish_reason == "stop"


async def test_reasoning_content_is_returned_in_the_turn() -> None:
    body = recorded("reasoning_content")
    expected = message_of(body)["reasoning_content"]
    provider, _ = provider_for_test([body], effort="high")

    turn = await provider.run([Turn(role="user", text="Find the port.")], TOOLS)

    assert expected
    assert turn.reasoning == expected
    assert turn.tool_uses, "the recorded reply also asked for a tool"


async def test_reasoning_content_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    body = recorded("reasoning_content")
    expected = message_of(body)["reasoning_content"]
    provider, _ = provider_for_test([body], effort="high")

    with caplog.at_level(logging.INFO, logger="agents.providers.openai_compat"):
        await provider.run([Turn(role="user", text="Find the port.")], TOOLS)

    assert expected in caplog.text


async def test_reasoning_content_is_never_sent_back() -> None:
    """The follow-up request drops the reasoning the reply carried.

    The vendor's documentation says a request that carries tools must repeat
    `reasoning_content`, and a live probe on 2026-09-13 showed the endpoint
    accepting a follow-up without it, so this provider follows the ticket and
    the observed behavior. If the endpoint ever enforces the documented rule,
    this test is the one that has to change.
    """
    first = recorded("reasoning_content")
    provider, transport = provider_for_test([first, recorded("text_final")], effort="high")

    reply = await provider.run([Turn(role="user", text="Find the port.")], TOOLS)
    assert reply.reasoning

    messages = [
        Turn(role="user", text="Find the port."),
        reply,
        Turn(
            role="user",
            tool_results=[ToolResultBlock(tool_use_id=reply.tool_uses[0].id, content="8081")],
        ),
    ]
    await provider.run(messages, TOOLS)

    follow_up = json.dumps(transport.requests[1])
    assert "reasoning_content" not in follow_up
    for sent in transport.requests[1]["messages"]:
        assert "reasoning_content" not in sent


async def test_finish_reason_length_warns(caplog: pytest.LogCaptureFixture) -> None:
    body = recorded("text_final")
    body["choices"][0]["finish_reason"] = "length"
    provider, _ = provider_for_test([body])

    with caplog.at_level(logging.WARNING, logger="agents.providers.openai_compat"):
        turn = await provider.run([Turn(role="user", text="Say done.")], TOOLS)

    assert turn.finish_reason == "length"
    assert "cut off" in caplog.text


async def test_arguments_that_are_not_json_mark_the_call_malformed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body = recorded("one_tool_call")
    message_of(body)["tool_calls"][0]["function"]["arguments"] = "not json at all"
    provider, _ = provider_for_test([body])

    with caplog.at_level(logging.WARNING, logger="agents.providers.openai_compat"):
        turn = await provider.run([Turn(role="user", text="Find the port.")], TOOLS)

    assert turn.tool_uses[0].malformed is True
    assert turn.tool_uses[0].args == {}
    assert "not a JSON object" in caplog.text


@pytest.mark.parametrize(
    ("effort", "thinking", "reasoning"),
    [
        ("off", {"type": "disabled"}, None),
        ("low", {"type": "enabled"}, "low"),
        ("high", {"type": "enabled"}, "high"),
        ("max", {"type": "enabled"}, "max"),
    ],
)
async def test_effort_on_the_wire(
    effort: str, thinking: dict[str, str], reasoning: str | None
) -> None:
    provider, transport = provider_for_test([recorded("text_final")], effort=effort)

    await provider.run([Turn(role="user", text="Say done.")], TOOLS)

    sent = transport.requests[0]
    assert sent["thinking"] == thinking
    if reasoning is None:
        assert "reasoning_effort" not in sent
    else:
        assert sent["reasoning_effort"] == reasoning


async def test_the_default_effort_sends_thinking_disabled() -> None:
    provider, transport = provider_for_test([recorded("text_final")])

    await provider.run([Turn(role="user", text="Say done.")], TOOLS)

    assert transport.requests[0]["thinking"] == {"type": "disabled"}
    assert "reasoning_effort" not in transport.requests[0]


async def test_the_request_carries_the_tool_schemas() -> None:
    provider, transport = provider_for_test([recorded("text_final")])

    await provider.run([Turn(role="user", text="Say done.")], TOOLS)

    names = [entry["function"]["name"] for entry in transport.requests[0]["tools"]]
    assert names == ["get_port", "get_host"]
    assert transport.requests[0]["tools"][0]["type"] == "function"


def test_an_unknown_effort_is_refused() -> None:
    with pytest.raises(ValueError):
        OpenAICompatProvider(
            "https://endpoint.test", "test-key-not-a-secret", "test-model", "medium"
        )


async def test_a_refused_omission_is_retried_once_with_the_reasoning_echoed() -> None:
    """The vendor's documented requirement, answered instead of failed.

    The endpoint accepts the omission today, and the vendor documents that a
    request carrying tools must repeat `reasoning_content`. Omitting first and
    answering a 400 that names the field keeps both true: the run survives a
    change of mind, and the retry is bounded to one.
    """
    error = {
        "error": {
            "message": (
                "Error code: 400 - The reasoning_content in the thinking mode "
                "must be passed back to the API."
            ),
            "type": "invalid_request_error",
        }
    }
    provider, transport = flaky_provider_for_test(error, [recorded("text_final")], effort="high")

    reply = await provider.run(
        [
            Turn(role="user", text="Find the port."),
            Turn(
                role="assistant",
                text=None,
                reasoning="The README and the code disagree, so read both.",
                tool_uses=[ToolUse(id="call-1", name="get_port", args={}, malformed=False)],
            ),
            Turn(
                role="user",
                tool_results=[ToolResultBlock(tool_use_id="call-1", content="8081")],
            ),
        ],
        TOOLS,
    )

    assert reply.text
    assert len(transport.requests) == 2, "the provider must retry exactly once"
    first, second = transport.requests
    assert not any("reasoning_content" in message for message in first["messages"])
    echoed = [m for m in second["messages"] if m.get("role") == "assistant"]
    assert echoed and echoed[0]["reasoning_content"], "the retry must echo the reasoning"


async def test_an_error_that_does_not_name_the_reasoning_field_is_not_retried() -> None:
    """Only the documented refusal is answered, so a real error still fails."""
    error = {
        "error": {
            "message": "Error code: 400 - bad tool schema",
            "type": "invalid_request_error",
        }
    }
    provider, transport = flaky_provider_for_test(error, [], effort="high")

    with pytest.raises(Exception):
        await provider.run([Turn(role="user", text="Find the port.")], TOOLS)

    assert len(transport.requests) == 1


def test_a_gateway_tool_name_round_trips_through_the_wire_encoding() -> None:
    """The endpoint's grammar has no dot, and the gateway's names do."""
    from agents.providers.openai_compat import decode_tool_name, encode_tool_name

    for name in (
        "gitea.get_issue",
        "gitea.create_issue_comment",
        "db.search_customers",
        "mail.send_reply",
        "a_x2e_b",
        "_leading",
        "trailing_",
    ):
        encoded = encode_tool_name(name)

        assert re.fullmatch(r"[A-Za-z0-9_-]+", encoded), encoded
        assert decode_tool_name(encoded) == name


def test_the_wire_tools_carry_the_encoded_name() -> None:
    from agents.providers.openai_compat import decode_tool_name, wire_tools

    schema = ToolSchema(
        name="gitea.get_issue",
        description="Read one issue.",
        input_schema={"type": "object", "properties": {}},
    )

    entry = wire_tools([schema])[0]["function"]

    assert "." not in entry["name"]
    assert decode_tool_name(entry["name"]) == "gitea.get_issue"
