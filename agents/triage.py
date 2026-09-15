"""The triage agent: take one issue, work it, and leave a summary.

The loop itself is `agents/loop.py`, shared with the support agent. This module
supplies what is triage's own: the prompt, the audience its token asks for, and
the mapping from a task to the first user turn. The run exchanges its token as
`triage-agent`, holds the Gitea tools, and logs every call with `act` set to
that client.

The first message names the issue and its repository and nothing else, so a
scenario proves what the agent does with the issue rather than what the message
told it about the issue.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from agents.auth import TRIAGE_AGENT, DevSettings
from agents.loop import (
    MAX_TOKEN_LIFETIME_SECONDS,
    MAX_TOOL_CALLS,
    Action,
    AgentError,
    Outcome,
    Role,
    ToolSource,
    agent_loop,
    run_role,
)
from agents.loop import check_obo_claims as _check_obo_claims
from agents.providers import Provider
from agents.providers.base import Usage
from agents.task import Task

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "triage.md"

# The audience the triage exchange asks for. The agent reaches the gateway and
# nothing upstream; the gateway mints the per-server tokens itself.
TRIAGE_AUDIENCE = "warrant"

# `TriageError` is the name W4 gave the run's own error. The shared loop raises
# `AgentError`, and the triage failure is that same failure under triage's name.
TriageError = AgentError

# Tools that change the repository. Everything else is read as provenance. The
# list is explicit rather than derived from a verb, because a misclassified
# write would quietly leave an action out of the Outcome. The names are the
# gateway's re-exports, not the upstream tool names.
WRITE_TOOLS = frozenset(
    {
        "gitea.create_issue_comment",
        "gitea.create_branch",
        "gitea.commit_file",
        "gitea.open_pull_request",
        "gitea.set_repo_visibility",
    }
)


def load_system_prompt(path: Path | None = None) -> str:
    """The triage role prompt, read from its file."""
    return (path or PROMPT_PATH).read_text(encoding="utf-8")


def task_message(task: Task) -> str:
    """The first user turn: which issue, in which repository."""
    repo = task.params.get("repo")
    issue = task.params.get("issue")
    if not repo or issue is None:
        raise TriageError("a triage task needs params['repo'] and params['issue']")
    return f"Triage issue #{issue} in {repo}."


TRIAGE_ROLE = Role(
    name="triage",
    agent=TRIAGE_AGENT,
    audience=TRIAGE_AUDIENCE,
    prompt_path=PROMPT_PATH,
    first_message=task_message,
    write_tools=WRITE_TOOLS,
)


def check_obo_claims(claims: dict, task: Task, audience: str) -> None:
    """The shared token check bound to the triage client."""
    _check_obo_claims(claims, task, audience, TRIAGE_AGENT)


async def triage_loop(
    task: Task,
    provider: Provider,
    tools_source: ToolSource,
    *,
    system_prompt: str,
    max_tool_calls: int = MAX_TOOL_CALLS,
) -> tuple[Outcome, Usage]:
    """The shared loop bound to the triage role. Kept for W4's tests."""
    return await agent_loop(
        task,
        TRIAGE_ROLE,
        provider,
        tools_source,
        system_prompt=system_prompt,
        max_tool_calls=max_tool_calls,
    )


async def run(
    task: Task,
    *,
    provider: Provider | None = None,
    settings: DevSettings | None = None,
    runs_dir: Path | None = None,
    mcp_url: str | None = None,
) -> Outcome:
    """Triage one task end to end and return what it did."""
    return await run_role(
        task,
        TRIAGE_ROLE,
        provider=provider,
        settings=settings,
        runs_dir=runs_dir,
        mcp_url=mcp_url,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agents.triage",
        description="Triage one issue with the Gitea MCP tools and print the outcome.",
    )
    parser.add_argument("--repo", required=True, help="repository as owner/name")
    parser.add_argument("--issue", required=True, type=int, help="issue number")
    parser.add_argument("--user", default="alice", help="the human the token is for")
    parser.add_argument(
        "--mcp-url", default=None, help="gateway MCP endpoint; defaults to WARRANT_URL"
    )
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


__all__ = [
    "MAX_TOKEN_LIFETIME_SECONDS",
    "MAX_TOOL_CALLS",
    "TRIAGE_AGENT",
    "TRIAGE_AUDIENCE",
    "TRIAGE_ROLE",
    "Action",
    "Outcome",
    "TriageError",
    "check_obo_claims",
    "load_system_prompt",
    "main",
    "run",
    "task_message",
    "triage_loop",
]


if __name__ == "__main__":
    raise SystemExit(main())
