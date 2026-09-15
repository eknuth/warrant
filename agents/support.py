"""The support agent: answer one ticket from the database and reply by mail.

The loop itself is `agents/loop.py`, shared with the triage agent. This module
supplies what is support's own: the prompt, the audience its token asks for, and
the mapping from a task to the first user turn. The run exchanges its token as
`support-agent`, holds the database and mail tools through the gateway, and logs
every call with `act` set to that client.

The job is the ticket: read the ticket and its customer, settle the question,
reply to the customer by email, and leave a note and a status that say what the
run did. The prompt says that and nothing about what a ticket body might
contain, so a scenario proves what the agent does with the ticket rather than
what the prompt warned it about.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from agents.auth import SUPPORT_AGENT, DevSettings
from agents.loop import AgentError, Outcome, Role, run_role
from agents.providers import Provider
from agents.task import Task

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "support.md"

# The audience the support exchange asks for. The agent reaches the gateway and
# nothing upstream; the gateway mints the per-server tokens itself.
SUPPORT_AUDIENCE = "warrant"

# The servers whose tools this role holds. The gateway re-exports every server
# it knows; the model is offered only these two.
SUPPORT_TOOL_PREFIXES = ("db.", "mail.")

# Calls that change something. A status or note change and a reply are the
# actions a support run takes; every other call is a read. The names are the
# gateway's re-exports.
WRITE_TOOLS = frozenset({"db.update_ticket", "mail.send_reply"})


def task_message(task: Task) -> str:
    """The first user turn: which ticket, for which person."""
    ticket = task.params.get("ticket")
    if ticket is None:
        raise AgentError("a support task needs params['ticket']")
    return f"Answer support ticket #{ticket} as {task.user}."


SUPPORT_ROLE = Role(
    name="support",
    agent=SUPPORT_AGENT,
    audience=SUPPORT_AUDIENCE,
    prompt_path=PROMPT_PATH,
    first_message=task_message,
    write_tools=WRITE_TOOLS,
    tool_prefixes=SUPPORT_TOOL_PREFIXES,
)


async def run(
    task: Task,
    *,
    provider: Provider | None = None,
    settings: DevSettings | None = None,
    runs_dir: Path | None = None,
    mcp_url: str | None = None,
) -> Outcome:
    """Answer one ticket end to end and return what the run did."""
    return await run_role(
        task,
        SUPPORT_ROLE,
        provider=provider,
        settings=settings,
        runs_dir=runs_dir,
        mcp_url=mcp_url,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agents.support",
        description="Answer one support ticket with the database and mail MCP tools.",
    )
    parser.add_argument("--ticket", required=True, type=int, help="ticket number")
    parser.add_argument("--user", default="alice", help="the human the token is for")
    parser.add_argument(
        "--mcp-url", default=None, help="gateway MCP endpoint; defaults to WARRANT_URL"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    args = parse_args(argv)
    task = Task(
        kind="support",
        subject=f"ticket #{args.ticket}",
        user=args.user,
        params={"ticket": args.ticket},
    )
    outcome = asyncio.run(run(task, mcp_url=args.mcp_url))
    print(outcome.model_dump_json(indent=2))
    return 0


__all__ = [
    "SUPPORT_AGENT",
    "SUPPORT_AUDIENCE",
    "SUPPORT_ROLE",
    "SUPPORT_TOOL_PREFIXES",
    "Outcome",
    "main",
    "parse_args",
    "run",
    "task_message",
]


if __name__ == "__main__":
    raise SystemExit(main())
