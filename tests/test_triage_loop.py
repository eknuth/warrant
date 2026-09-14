"""The triage loop: the tool call ceiling, the stop on a text turn, and bookkeeping.

No provider and no MCP server are involved. The loop is handed the two
interfaces it uses, so what is under test is the loop's own control flow: how
many calls it makes, when it stops, and what it records.
"""

from __future__ import annotations

from typing import Any

import pytest

from agents.mcp_client import CallResult
from agents.providers.base import ToolSchema, ToolUse, Turn, Usage
from agents.task import Task
from agents.triage import MAX_TOOL_CALLS, Action, TriageError, triage_loop

SOURCE = {
    "system": "gitea",
    "kind": "issue",
    "id": "acme/widgets#1",
    "author": "bob",
    "author_tier": "member",
}

TOOLS = [
    ToolSchema(name="get_issue", description="Read an issue.", input_schema={"type": "object"}),
    ToolSchema(
        name="create_issue_comment",
        description="Comment on an issue.",
        input_schema={"type": "object"},
    ),
]


def a_task() -> Task:
    return Task(
        kind="triage",
        subject="triage",
        user="alice",
        params={"repo": "acme/widgets", "issue": 1},
        task_id="task-loop-test",
    )


class ScriptedProvider:
    """A provider that replays a script, then asks for one more tool call."""

    name = "scripted"
    model = "scripted"
    effort = "off"

    def __init__(self, script: list[Turn] | None = None) -> None:
        self.script = list(script or [])
        self.turns = 0

    async def run(self, messages: list[Turn], tools: list[ToolSchema]) -> Turn:
        self.turns += 1
        if self.script:
            return self.script.pop(0)
        return Turn(
            role="assistant",
            tool_uses=[ToolUse(id=f"call-{self.turns}", name="get_issue", args={"number": 1})],
            usage=Usage(input_tokens=10, output_tokens=5),
        )


class RecordingTools:
    """A tool source that records calls and answers with one provenance block."""

    def __init__(self, result: CallResult | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.result = result or CallResult(
            tool="get_issue",
            endpoint="gitea-mcp",
            payload={"number": 1, "source": SOURCE},
            text='{"number": 1}',
            is_error=False,
            sources=[SOURCE],
        )

    async def list_tools(self) -> list[ToolSchema]:
        return TOOLS

    async def call(self, name: str, args: dict[str, Any]) -> CallResult:
        self.calls.append((name, args))
        return self.result


async def test_the_loop_stops_at_the_tool_call_ceiling() -> None:
    provider = ScriptedProvider()
    tools = RecordingTools()

    outcome, usage = await triage_loop(
        a_task(), provider, tools, system_prompt="system", max_tool_calls=MAX_TOOL_CALLS
    )

    assert len(tools.calls) == MAX_TOOL_CALLS, "the ceiling is a count of tool calls"
    assert provider.turns == MAX_TOOL_CALLS
    assert outcome.turns == MAX_TOOL_CALLS
    assert usage.input_tokens == MAX_TOOL_CALLS * 10
    assert usage.output_tokens == MAX_TOOL_CALLS * 5
    assert "ceiling" in outcome.summary


async def test_the_ceiling_counts_parallel_calls_in_one_turn() -> None:
    """One turn asking for three calls spends three of the twenty."""
    parallel = Turn(
        role="assistant",
        tool_uses=[
            ToolUse(id="a", name="get_issue", args={}),
            ToolUse(id="b", name="get_issue", args={}),
            ToolUse(id="c", name="get_issue", args={}),
        ],
    )
    provider = ScriptedProvider([parallel])
    tools = RecordingTools()

    await triage_loop(a_task(), provider, tools, system_prompt="system", max_tool_calls=3)

    assert len(tools.calls) == 3


async def test_the_loop_stops_on_a_text_turn_and_keeps_its_summary() -> None:
    provider = ScriptedProvider(
        [
            Turn(
                role="assistant",
                tool_uses=[ToolUse(id="c1", name="get_issue", args={"number": 1})],
            ),
            Turn(role="assistant", text="I read the issue and commented on it."),
        ]
    )
    tools = RecordingTools()

    outcome, _ = await triage_loop(a_task(), provider, tools, system_prompt="system")

    assert outcome.summary == "I read the issue and commented on it."
    assert outcome.turns == 2
    assert len(tools.calls) == 1


async def test_write_calls_are_actions_and_results_are_reads() -> None:
    provider = ScriptedProvider(
        [
            Turn(
                role="assistant",
                tool_uses=[
                    ToolUse(id="r1", name="get_issue", args={"number": 1}),
                    ToolUse(
                        id="w1",
                        name="create_issue_comment",
                        args={"number": 1, "body": "fixed"},
                    ),
                ],
            ),
            Turn(role="assistant", text="done"),
        ]
    )
    tools = RecordingTools()

    outcome, _ = await triage_loop(a_task(), provider, tools, system_prompt="system")

    assert outcome.actions == [
        Action(tool="create_issue_comment", args={"number": 1, "body": "fixed"})
    ]
    assert outcome.reads == [SOURCE]
    assert [name for name, _ in tools.calls] == ["get_issue", "create_issue_comment"]


async def test_a_repeated_source_is_recorded_once() -> None:
    provider = ScriptedProvider(
        [
            Turn(
                role="assistant",
                tool_uses=[
                    ToolUse(id="r1", name="get_issue", args={}),
                    ToolUse(id="r2", name="get_issue", args={}),
                ],
            ),
            Turn(role="assistant", text="done"),
        ]
    )
    tools = RecordingTools()

    outcome, _ = await triage_loop(a_task(), provider, tools, system_prompt="system")

    assert outcome.reads == [SOURCE]


async def test_a_task_without_a_repo_is_refused() -> None:
    task = Task(kind="triage", subject="x", user="alice", params={}, task_id="t")

    with pytest.raises(TriageError, match="params"):
        await triage_loop(task, ScriptedProvider(), RecordingTools(), system_prompt="system")
