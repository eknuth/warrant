"""The triage agent: take one issue, work it, and leave a summary.

The run has four parts.

1. Log in as the task's human and exchange that token for an on-behalf-of token
   addressed to the Gitea MCP server, bound to the task id. The decoded token is
   written once per task to `runs/<task_id>/token.json` with its signature
   stripped, and the audience, the actor, the task id, and the lifetime are
   checked before a single tool call is made.
2. Open one MCP session per endpoint, carrying that token as its bearer.
3. Loop. The model is offered the MCP tools and gets up to `MAX_TOOL_CALLS` tool
   calls. It stops on its own when it answers with text, and it is cut off at
   the cap otherwise. Every call is logged by `agents/mcp_client.py`.
4. Return an `Outcome`: the summary, the write calls, the provenance of what was
   read, and the number of model turns.

The prompt is `agents/prompts/triage.md`. It describes the job and nothing else,
so a scenario proves what the agent does with the issue rather than what the
prompt told it about the issue.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, Field

from agents.auth import (
    TRIAGE_AGENT,
    DevSettings,
    audience_list,
    claim_task_id,
    decode_claims,
    exchange_for_obo,
    lifetime_seconds,
    login_user,
)
from agents.mcp_client import CallResult, Endpoint, MCPClient
from agents.providers import Provider, ToolSchema, Turn, provider_for
from agents.providers.base import ToolResultBlock, Usage
from agents.task import Chain, Task

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS_DIR = REPO_ROOT / "runs"
DEFAULT_MCP_URL = "http://127.0.0.1:9101/mcp"
PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "triage.md"

# The audience the triage exchange asks for, and the realm client that serves
# it. A scenario where the agent is handed a token for another resource server
# is not this role.
TRIAGE_AUDIENCE = "gitea-mcp"

# The loop's ceiling. Twenty calls is enough to read an issue, read a few files,
# search once, and write a comment or a branch and a pull request, with room for
# a correction. A run that reaches the cap still returns an Outcome and says so.
MAX_TOOL_CALLS = 20

# The token lifetime the realm is configured for. A token longer than this means
# the realm or the exchange changed, and the run should not proceed on it.
MAX_TOKEN_LIFETIME_SECONDS = 300

# Tools that change the repository. Everything else is read as provenance. The
# list is explicit rather than derived from a verb, because a misclassified
# write would quietly leave an action out of the Outcome.
WRITE_TOOLS = frozenset(
    {
        "create_issue_comment",
        "create_branch",
        "commit_file",
        "open_pull_request",
        "set_repo_visibility",
    }
)


class TriageError(RuntimeError):
    """The run could not be set up or could not continue."""


class Action(BaseModel):
    """One write tool call, with the arguments it was made with."""

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class Outcome(BaseModel):
    """What one triage run did."""

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


def load_system_prompt(path: Path | None = None) -> str:
    """The role prompt, read from its file so it is reviewable as prose."""
    return (path or PROMPT_PATH).read_text(encoding="utf-8")


def task_message(task: Task) -> str:
    """The first user turn: which issue, in which repository."""
    repo = task.params.get("repo")
    issue = task.params.get("issue")
    if not repo or issue is None:
        raise TriageError("a triage task needs params['repo'] and params['issue']")
    return f"Triage issue #{issue} in {repo}."


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


def check_obo_claims(claims: dict[str, Any], task: Task, audience: str) -> None:
    """Refuse a token that is not the one this task asked for.

    The checks are the ones the run record claims: the token names the Gitea MCP
    audience and only it, the actor is the triage client, the task id is this
    task's, and the lifetime is the realm's five minutes or less. A token that
    fails any of them stops the run before its first tool call.
    """
    claimed_audience = audience_list(claims)
    if claimed_audience != [audience]:
        raise TriageError(f"OBO token audience is {claimed_audience}, not [{audience!r}]")
    actor = (claims.get("act") or {}).get("sub")
    if actor != TRIAGE_AGENT:
        raise TriageError(f"OBO token actor is {actor!r}, not {TRIAGE_AGENT!r}")
    claimed_task = claim_task_id(claims)
    if claimed_task != task.task_id:
        raise TriageError(f"OBO token task id is {claimed_task!r}, not {task.task_id!r}")
    lifetime = lifetime_seconds(claims)
    if lifetime is None or lifetime > MAX_TOKEN_LIFETIME_SECONDS:
        raise TriageError(
            f"OBO token lifetime is {lifetime}s, above the {MAX_TOKEN_LIFETIME_SECONDS}s ceiling"
        )


def write_token_record(runs_dir: Path, task: Task, decoded: dict[str, Any], audience: str) -> Path:
    """Write the decoded token once per task, with the signature stripped."""
    claims = decoded["claims"]
    path = Path(runs_dir) / task.task_id / "token.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "task_id": task.task_id,
        "user": task.user,
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
    actions: list[Action],
    reads: list[dict[str, Any]],
    turns: int,
    capped: bool,
    cap: int = MAX_TOOL_CALLS,
) -> str:
    """A short markdown summary for a run that ended without the model's own."""
    repo = task.params.get("repo")
    issue = task.params.get("issue")
    lines = [f"# Triage summary for issue #{issue} in {repo}", ""]
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


async def triage_loop(
    task: Task,
    provider: Provider,
    tools_source: ToolSource,
    *,
    system_prompt: str,
    max_tool_calls: int = MAX_TOOL_CALLS,
) -> tuple[Outcome, Usage]:
    """Run the model and tool loop for one task.

    The cap counts tool calls, not turns, so one turn asking for several calls
    in parallel spends several from the same budget. When the cap is reached
    inside a turn, the calls that fit are made and answered, and the loop stops
    rather than sending the model a transcript with unanswered calls.
    """
    tools = await tools_source.list_tools()
    messages: list[Turn] = [
        Turn(role="system", text=system_prompt),
        Turn(role="user", text=task_message(task)),
    ]
    actions: list[Action] = []
    reads: list[dict[str, Any]] = []
    usage = Usage()
    turns = 0
    tool_calls = 0
    summary = ""
    finish_reason: str | None = None

    while tool_calls < max_tool_calls:
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
            if tool_calls >= max_tool_calls:
                break
            tool_calls += 1
            logger.info(
                "tool call %d: %s task_id=%s sub=%s act=%s",
                tool_calls,
                use.name,
                task.task_id,
                task.user,
                TRIAGE_AGENT,
            )
            result = await tools_source.call(use.name, use.args)
            # A write the server refused is not an action the run took. The call
            # record keeps it with `is_error`, and the Outcome must not claim it.
            if use.name in WRITE_TOOLS and not result.is_error:
                actions.append(Action(tool=use.name, args=use.args))
            reads.extend(result.sources)
            results.append(
                ToolResultBlock(
                    tool_use_id=use.id, content=result.content, is_error=result.is_error
                )
            )
        messages.append(Turn(role="user", tool_results=results))

    capped = tool_calls >= max_tool_calls and not summary
    if not summary:
        summary = synthesize_summary(
            task, actions, dedupe_sources(reads), turns, capped, max_tool_calls
        )
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


async def run(
    task: Task,
    *,
    provider: Provider | None = None,
    settings: DevSettings | None = None,
    runs_dir: Path | None = None,
    mcp_url: str = DEFAULT_MCP_URL,
) -> Outcome:
    """Triage one task end to end and return what it did."""
    if task.kind != "triage":
        raise TriageError(f"this role triages, it does not run a {task.kind!r} task")
    settings = settings or DevSettings()
    provider = provider or provider_for()
    runs_dir = Path(runs_dir) if runs_dir is not None else DEFAULT_RUNS_DIR
    system_prompt = load_system_prompt()

    with httpx.Client(timeout=30.0) as client:
        subject_token = login_user(settings, client, task.user, settings.warrant_user_password)
        obo_token = exchange_for_obo(settings, client, subject_token, TRIAGE_AUDIENCE, task.task_id)

    decoded = decode_claims(obo_token)
    check_obo_claims(decoded["claims"], task, TRIAGE_AUDIENCE)
    token_path = write_token_record(runs_dir, task, decoded, TRIAGE_AUDIENCE)
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
        act=TRIAGE_AGENT,
        task_id=task.task_id,
        sub_id=str(decoded["claims"].get("sub") or "") or None,
    )
    endpoint = Endpoint(url=mcp_url, bearer=obo_token, name="gitea-mcp")
    async with MCPClient([endpoint], chain=chain, runs_dir=runs_dir) as mcp:
        outcome, usage = await triage_loop(task, provider, mcp, system_prompt=system_prompt)
    write_run_record(runs_dir, task, outcome, usage)
    logger.info(
        "turns=%d writes=%d input_tokens=%d output_tokens=%d",
        outcome.turns,
        len(outcome.actions),
        usage.input_tokens,
        usage.output_tokens,
    )
    return outcome


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agents.triage",
        description="Triage one issue with the Gitea MCP tools and print the outcome.",
    )
    parser.add_argument("--repo", required=True, help="repository as owner/name")
    parser.add_argument("--issue", required=True, type=int, help="issue number")
    parser.add_argument("--user", default="alice", help="the human the token is for")
    parser.add_argument("--mcp-url", default=DEFAULT_MCP_URL, help="Gitea MCP endpoint")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    args = parse_args(argv)
    task = Task(
        kind="triage",
        subject=f"issue #{args.issue} in {args.repo}",
        user=args.user,
        params={"repo": args.repo, "issue": args.issue},
    )
    outcome = asyncio.run(run(task, mcp_url=args.mcp_url))
    print(outcome.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
