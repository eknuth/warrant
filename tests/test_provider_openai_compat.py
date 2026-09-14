"""The OpenAI-compatible provider, against responses recorded from the endpoint.

Every fixture under `tests/fixtures/provider/` is a real chat completion
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
from pathlib import Path
from typing import Any

import httpx
import pytest

from agents.providers.base import ToolResultBlock, ToolSchema, Turn
from agents.providers.openai_compat import OpenAICompatProvider

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "provider"

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
