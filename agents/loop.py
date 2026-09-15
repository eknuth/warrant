"""The provider and tool loop every agent role shares.

A role supplies four things: the system prompt, the agent client it exchanges
as, the audience its on-behalf-of token is for, and the mapping from a task to
its first user message. It also names the tools whose calls count as actions,
because a read and a write are told apart by the tool's name and only the role
knows which of the tools it holds change anything.

This module supplies the rest of a run. It logs in as the task's human and
exchanges that token for an on-behalf-of token addressed to the gateway, bound
to the task id. It checks the decoded token before the first tool call, opens
one MCP session carrying it, loops the model against the MCP tool surface to a
cap, and writes the run record.

Two roles use it. `agents/triage.py` answers an issue through the Gitea tools
and `agents/support.py` answers a ticket through the database and mail tools.
Each role names its own agent client and prompt, so a scenario proves what the
role does rather than what this loop told it about the task.

There is no token cache anywhere in this module. `run_role` logs in and
exchanges once per call, so two tasks running at the same time hold two tokens
and a token obtained for one task is never presented on another's calls.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, Field

from agents.auth import (
    DevSettings,
    audience_list,
    claim_task_id,
    decode_claims,
    exchange_for_obo,
    lifetime_seconds,
    login_user,
)
from agents.mcp_client import CallResult, MCPClient, warrant_endpoint
from agents.providers import Provider, ToolSchema, Turn, provider_for
from agents.providers.base import ToolResultBlock, Usage
from agents.task import Chain, Task
from warrant.config import RUNS_DIR as DEFAULT_RUNS_DIR
from warrant.config import task_dir, write_run_metadata

logger = logging.getLogger(__name__)

# The loop's ceiling. Twenty calls is enough to read the task's rows, write the
# outcome, and correct one mistake. A run that reaches the cap still returns an
# Outcome and says so.
MAX_TOOL_CALLS = 20

# The token lifetime the realm is configured for. A token longer than this means
# the realm or the exchange changed, and the run should not proceed on it.
MAX_TOKEN_LIFETIME_SECONDS = 300


class AgentError(RuntimeError):
    """The run could not be set up or could not continue."""


class Action(BaseModel):
    """One write tool call, with the arguments it was made with."""

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class Outcome(BaseModel):
    """What one agent run did."""

    summary: str
    actions: list[Action] = Field(default_factory=list)
    reads: list[dict[str, Any]] = Field(default_factory=list)
    turns: int = 0
    # The last turn's finish reason. It is carried because a `length` reply is
    # a truncated answer that reads like a complete one, and a record that says
    # only "the summary was X" cannot tell a reader it was cut off.
    finish_reason: str | None = None


class ToolSource(Protocol):
    """What the loop needs from an MCP client, real or in a test."""

    async def list_tools(self) -> list[ToolSchema]: ...

    async def call(self, name: str, args: dict[str, Any]) -> CallResult: ...


@dataclass(frozen=True)
class Role:
    """What one agent role supplies to the shared loop.

    `name` is the task kind the role runs and the name the run metadata
    records. `agent` is the identity provider client the token is exchanged as,
    which is also the value the policy engine reads as the actor. `audience` is
    the one resource server the token names, which for both roles is the
    gateway. `first_message` turns a task into the first user turn.
    `write_tools` names the calls whose success is an action rather than a read.
    `tool_prefixes` narrows the tool surface the model is offered to the
    servers the role holds; None offers everything the gateway re-exports.
    """

    name: str
    agent: str
    audience: str
    prompt_path: Path
    first_message: Callable[[Task], str]
    write_tools: frozenset[str]
    tool_prefixes: tuple[str, ...] | None = None
    max_tool_calls: int = MAX_TOOL_CALLS


def load_system_prompt(path: Path | None = None) -> str:
    """The role prompt, read from its file so it is reviewable as prose."""
    if path is None:
        raise AgentError("a role needs a prompt path")
    return path.read_text(encoding="utf-8")


def dedupe_sources(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop repeated provenance blocks, keeping the order they arrived in."""
    seen: set[tuple[Any, Any, Any]] = set()
    unique: list[dict[str, Any]] = []
    for source in sources:
        key = (source.get("system"), source.get("kind"), source.get("id"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(source)
    return unique


def check_obo_claims(claims: dict[str, Any], task: Task, audience: str, agent: str) -> None:
    """Refuse a token that is not the one this task asked for.

    The checks are the ones the run record claims: the token names the gateway
    audience and only it, the actor is this role's client, the task id is this
    task's, and the lifetime is the realm's five minutes or less. A token that
    fails any of them stops the run before its first tool call.
    """
    claimed_audience = audience_list(claims)
    if claimed_audience != [audience]:
        raise AgentError(f"OBO token audience is {claimed_audience}, not [{audience!r}]")
    actor = (claims.get("act") or {}).get("sub")
    if actor != agent:
        raise AgentError(f"OBO token actor is {actor!r}, not {agent!r}")
    claimed_task = claim_task_id(claims)
    if claimed_task != task.task_id:
        raise AgentError(f"OBO token task id is {claimed_task!r}, not {task.task_id!r}")
    lifetime = lifetime_seconds(claims)
    if lifetime is None or lifetime > MAX_TOKEN_LIFETIME_SECONDS:
        raise AgentError(
            f"OBO token lifetime is {lifetime}s, above the {MAX_TOKEN_LIFETIME_SECONDS}s ceiling"
        )


def write_token_record(
    runs_dir: Path, task: Task, decoded: dict[str, Any], audience: str, agent: str
) -> Path:
    """Write the decoded token once per task, with the signature stripped."""
    claims = decoded["claims"]
    path = Path(runs_dir) / task.task_id / "token.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "task_id": task.task_id,
        "user": task.user,
        "agent": agent,
        "audience": audience,
        "lifetime_seconds": lifetime_seconds(claims),
        "header": decoded["header"],
        "claims": claims,
        "signature": None,
    }
    path.write_text(json.dumps(record, indent=2, sort_keys=True, default=str) + "\n")
    return path


def synthesize_summary(
    task: Task,
    role: Role,
    actions: list[Action],
    reads: list[dict[str, Any]],
    turns: int,
    capped: bool,
    cap: int = MAX_TOOL_CALLS,
) -> str:
    """A short markdown summary for a run that ended without the model's own."""
    lines = [f"# {role.name.capitalize()} summary for {task.subject}", ""]
    lines.append(f"- Model turns: {turns}")
    if reads:
        lines.append("- Read: " + ", ".join(f"{s.get('kind')} {s.get('id')}" for s in reads))
    if actions:
        lines.append("- Wrote: " + ", ".join(action.tool for action in actions))
    if not actions:
        lines.append("- Wrote: nothing")
    if capped:
        lines.append(f"- Stopped at the {cap} tool call ceiling.")
    return "\n".join(lines)


def offered_tools(role: Role, tools: list[ToolSchema]) -> list[ToolSchema]:
    """The role's slice of the gateway's tool surface.

    A role that names no prefix sees every re-exported tool. A role that names
    prefixes sees only those servers, so the model is not offered a tool the
    role's agent does not hold.
    """
    if role.tool_prefixes is None:
        return tools
    return [tool for tool in tools if tool.name.startswith(role.tool_prefixes)]


async def agent_loop(
    task: Task,
    role: Role,
    provider: Provider,
    tools_source: ToolSource,
    *,
    system_prompt: str,
    max_tool_calls: int | None = None,
) -> tuple[Outcome, Usage]:
    """Run the model and tool loop for one task.

    The cap counts tool calls, not turns, so one turn asking for several calls
    in parallel spends several from the same budget. When the cap is reached
    inside a turn, the calls that fit are made and answered, and the loop stops
    rather than sending the model a transcript with unanswered calls.
    """
    cap = role.max_tool_calls if max_tool_calls is None else max_tool_calls
    tools = offered_tools(role, await tools_source.list_tools())
    messages: list[Turn] = [
        Turn(role="system", text=system_prompt),
        Turn(role="user", text=role.first_message(task)),
    ]
    actions: list[Action] = []
    reads: list[dict[str, Any]] = []
    usage = Usage()
    turns = 0
    tool_calls = 0
    summary = ""
    finish_reason: str | None = None

    while tool_calls < cap:
        turns += 1
        reply = await provider.run(messages, tools)
        messages.append(reply)
        if reply.usage is not None:
            usage = usage + reply.usage
        finish_reason = reply.finish_reason
        if not reply.tool_uses:
            summary = (reply.text or "").strip()
            break

        results: list[ToolResultBlock] = []
        for use in reply.tool_uses:
            if tool_calls >= cap:
                break
            tool_calls += 1
            logger.info(
                "tool call %d: %s task_id=%s sub=%s act=%s",
                tool_calls,
                use.name,
                task.task_id,
                task.user,
                role.agent,
            )
            result = await tools_source.call(use.name, use.args)
            # A write the server refused is not an action the run took. The call
            # record keeps it with `is_error`, and the Outcome must not claim it.
            if use.name in role.write_tools and not result.is_error:
                actions.append(Action(tool=use.name, args=use.args))
            reads.extend(result.sources)
            results.append(
                ToolResultBlock(
                    tool_use_id=use.id, content=result.content, is_error=result.is_error
                )
            )
        messages.append(Turn(role="user", tool_results=results))

    capped = tool_calls >= cap and not summary
    if not summary:
        summary = synthesize_summary(task, role, actions, dedupe_sources(reads), turns, capped, cap)
    return (
        Outcome(
            summary=summary,
            actions=actions,
            reads=dedupe_sources(reads),
            turns=turns,
            finish_reason=finish_reason,
        ),
        usage,
    )


def write_run_record(runs_dir: Path, task: Task, outcome: Outcome, usage: Usage) -> None:
    """Write the outcome and the token usage beside the call log."""
    directory = Path(runs_dir) / task.task_id
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "outcome.json").write_text(
        outcome.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    (directory / "usage.json").write_text(
        json.dumps(
            {
                "task_id": task.task_id,
                "turns": outcome.turns,
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "cache_read_tokens": usage.cache_read_tokens,
                "reasoning_tokens": usage.reasoning_tokens,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


async def run_role(
    task: Task,
    role: Role,
    *,
    provider: Provider | None = None,
    settings: DevSettings | None = None,
    runs_dir: Path | None = None,
    mcp_url: str | None = None,
) -> Outcome:
    """Run one task end to end as `role` and return what it did.

    The login and the exchange happen here, inside the call, so nothing about
    the token outlives the task. The token is a local, there is no cache to
    read it back from, and the MCP session is opened for this task and closed
    at the end of it.
    """
    if task.kind != role.name:
        raise AgentError(f"this role runs a {role.name!r} task, not a {task.kind!r} one")
    settings = settings or DevSettings()
    provider = provider or provider_for()
    runs_dir = Path(runs_dir) if runs_dir is not None else DEFAULT_RUNS_DIR
    system_prompt = load_system_prompt(role.prompt_path)

    with httpx.Client(timeout=30.0) as client:
        subject_token = login_user(settings, client, task.user, settings.warrant_user_password)
        obo_token = exchange_for_obo(
            settings, client, subject_token, role.audience, task.task_id, client_id=role.agent
        )

    decoded = decode_claims(obo_token)
    check_obo_claims(decoded["claims"], task, role.audience, role.agent)
    token_path = write_token_record(runs_dir, task, decoded, role.audience, role.agent)
    # Which commit produced this run, beside the run. A column in the eval table
    # is only worth reading if it says which code it is a column of.
    write_run_metadata(
        task_dir(runs_dir, task.task_id),
        tool=f"agents.{role.name}",
        model=provider.model,
        task_id=task.task_id,
    )
    logger.info(
        "token for task %s: audience=%s lifetime=%ss actor=%s (record: %s)",
        task.task_id,
        audience_list(decoded["claims"]),
        lifetime_seconds(decoded["claims"]),
        (decoded["claims"].get("act") or {}).get("sub"),
        token_path,
    )

    chain = Chain(
        sub=task.user,
        act=role.agent,
        task_id=task.task_id,
        sub_id=str(decoded["claims"].get("sub") or "") or None,
    )
    endpoint = warrant_endpoint(obo_token, url=mcp_url)
    async with MCPClient([endpoint], chain=chain, runs_dir=runs_dir) as mcp:
        outcome, usage = await agent_loop(task, role, provider, mcp, system_prompt=system_prompt)
    write_run_record(runs_dir, task, outcome, usage)
    logger.info(
        "turns=%d writes=%d input_tokens=%d output_tokens=%d",
        outcome.turns,
        len(outcome.actions),
        usage.input_tokens,
        usage.output_tokens,
    )
    return outcome
