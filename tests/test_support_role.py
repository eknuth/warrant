"""The support role: its first turn, its tool surface, its writes, and its cap.

The loop itself is covered by W4's tests and by `tests/test_run_many.py`. What
is checked here is what `agents/support.py` supplies to that loop and what the
shared loop does with it: the first message, the database and mail tool slice,
the calls that count as actions, and the twenty-call ceiling.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agents.loop import (
    MAX_TOOL_CALLS,
    AgentError,
    Outcome,
    Role,
    agent_loop,
)
from agents.mcp_client import CallResult
from agents.providers.base import ToolSchema, ToolUse, Turn, Usage
from agents.support import (
    PROMPT_PATH,
    SUPPORT_AGENT,
    SUPPORT_AUDIENCE,
    SUPPORT_ROLE,
    task_message,
)
from agents.task import Task


def a_support_task(ticket: int = 12, user: str = "alice") -> Task:
    return Task(
        kind="support",
        subject=f"ticket #{ticket}",
        user=user,
        params={"ticket": ticket},
        task_id=f"task-support-{ticket}",
    )


def test_the_role_exchanges_as_the_support_client_for_the_gateway() -> None:
    assert SUPPORT_ROLE.name == "support"
    assert SUPPORT_ROLE.agent == SUPPORT_AGENT == "support-agent"
    assert SUPPORT_ROLE.audience == SUPPORT_AUDIENCE == "warrant"


def test_the_first_turn_names_the_ticket_and_the_person() -> None:
    assert task_message(a_support_task(12, "alice")) == "Answer support ticket #12 as alice."


def test_a_support_task_without_a_ticket_is_refused() -> None:
    task = Task(kind="support", subject="ticket", user="alice", params={}, task_id="t")

    with pytest.raises(AgentError, match="params"):
        task_message(task)


def test_the_offered_tools_are_only_the_database_and_mail_servers() -> None:
    """A gitea tool is re-exported by the gateway and is not offered here."""
    from agents.loop import offered_tools

    tools = [
        ToolSchema(name="gitea.get_issue", description="", input_schema={}),
        ToolSchema(name="db.get_ticket", description="", input_schema={}),
        ToolSchema(name="mail.send_reply", description="", input_schema={}),
    ]

    offered = offered_tools(SUPPORT_ROLE, tools)

    assert [tool.name for tool in offered] == ["db.get_ticket", "mail.send_reply"]


def test_the_support_prompt_carries_no_security_language() -> None:
    """The prompt describes the job, not what a ticket might try to say."""
    text = PROMPT_PATH.read_text(encoding="utf-8")

    assert not re.search(r"inject|untrusted|secret", text, re.IGNORECASE)


class ScriptedProvider:
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
            tool_uses=[ToolUse(id=f"c{self.turns}", name="db.get_ticket", args={"ticket_id": 12})],
            usage=Usage(input_tokens=10, output_tokens=5),
        )


class RecordingTools:
    def __init__(self, result: CallResult | None = None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.result = result or CallResult(
            tool="db.get_ticket",
            endpoint="postgres-mcp",
            payload={"id": 12},
            text='{"id": 12}',
            is_error=False,
            sources=[],
        )

    async def list_tools(self) -> list[ToolSchema]:
        return [
            ToolSchema(name="db.get_ticket", description="", input_schema={}),
            ToolSchema(name="db.update_ticket", description="", input_schema={}),
            ToolSchema(name="mail.send_reply", description="", input_schema={}),
        ]

    async def call(self, name: str, args: dict) -> CallResult:
        self.calls.append((name, args))
        return self.result


async def test_a_status_change_is_an_action_and_a_read_is_not() -> None:
    provider = ScriptedProvider(
        [
            Turn(
                role="assistant",
                tool_uses=[
                    ToolUse(id="r1", name="db.get_ticket", args={"ticket_id": 12}),
                    ToolUse(
                        id="w1",
                        name="db.update_ticket",
                        args={"ticket_id": 12, "status": "closed", "note": "answered"},
                    ),
                ],
            ),
            Turn(role="assistant", text="closed it"),
        ]
    )
    tools = RecordingTools()

    outcome, _ = await agent_loop(
        a_support_task(), SUPPORT_ROLE, provider, tools, system_prompt="system"
    )

    assert [action.tool for action in outcome.actions] == ["db.update_ticket"]
    assert [name for name, _ in tools.calls] == ["db.get_ticket", "db.update_ticket"]


async def test_a_reply_to_the_customer_is_an_action() -> None:
    sent = CallResult(
        tool="mail.send_reply",
        endpoint="mail-mcp",
        payload={"message_id": "m1"},
        text='{"message_id": "m1"}',
        is_error=False,
        sources=[],
    )
    provider = ScriptedProvider(
        [
            Turn(
                role="assistant",
                tool_uses=[
                    ToolUse(
                        id="s1",
                        name="mail.send_reply",
                        args={"to": "dana@acme.test", "subject": "re", "body": "hello"},
                    )
                ],
            ),
            Turn(role="assistant", text="sent"),
        ]
    )

    outcome, _ = await agent_loop(
        a_support_task(),
        SUPPORT_ROLE,
        provider,
        RecordingTools(result=sent),
        system_prompt="system",
    )

    assert [action.tool for action in outcome.actions] == ["mail.send_reply"]


async def test_the_support_loop_stops_at_twenty_calls() -> None:
    provider = ScriptedProvider()
    tools = RecordingTools()

    outcome, usage = await agent_loop(
        a_support_task(), SUPPORT_ROLE, provider, tools, system_prompt="system"
    )

    assert len(tools.calls) == MAX_TOOL_CALLS == 20
    assert outcome.turns == MAX_TOOL_CALLS
    assert usage.input_tokens == MAX_TOOL_CALLS * 10
    assert "ceiling" in outcome.summary


async def test_the_summary_names_the_ticket_not_an_issue() -> None:
    outcome, _ = await agent_loop(
        a_support_task(12),
        SUPPORT_ROLE,
        ScriptedProvider(),
        RecordingTools(),
        system_prompt="system",
    )

    assert outcome.summary.startswith("# Support summary for ticket #12")


async def test_a_wrong_role_is_refused_by_the_shared_runner() -> None:
    """The support role runs support tasks; a triage task is not its job."""
    from agents.loop import run_role

    task = Task(kind="triage", subject="issue #1", user="alice", params={"repo": "a/b", "issue": 1})

    with pytest.raises(AgentError, match="triage"):
        await run_role(task, SUPPORT_ROLE)


def test_a_role_is_immutable() -> None:
    """A role is a description, not mutable state shared between runs."""
    role = Role(
        name="support",
        agent="support-agent",
        audience="warrant",
        prompt_path=Path("x.md"),
        first_message=task_message,
        write_tools=frozenset(),
    )

    with pytest.raises(Exception):
        role.name = "other"  # type: ignore[misc]


def test_outcome_is_the_shared_type() -> None:
    from agents import triage

    assert triage.Outcome is Outcome
