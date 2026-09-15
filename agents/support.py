"""The support agent: answer one ticket from the database and reply by mail.

The loop itself is `agents/loop.py`, shared with the triage agent. This module
supplies what is support's own: the prompt, the audience its token asks for, the
mapping from a task to the first user turn, and the write set derived from the
access graph. The run exchanges its token as `support-agent`, holds the database
and mail tools through the gateway, and logs every call with `act` set to that
client.

A support task under the shipped rules runs as a member of `support-leads`,
which is `carol`. The subject rule in `policies/50-ownership.cedar` refuses a
`db.*` or `mail.*` call whose resource the human in `sub` does not own, and a
ticket, a customer, or a recipient the graph has no row for resolves to an
unknown resource. `support-leads` is the rule's exemption, and W12 owns the
ticket and customer resource rows, so a non-lead's honest read is refused until
those rows exist. The CLI defaults to carol for that reason.

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
from agents.loop import AgentError, Outcome, Role, run_role, write_tools_from_graph
from agents.providers import Provider
from agents.task import Task

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "support.md"

# The audience the support exchange asks for. The agent reaches the gateway and
# nothing upstream; the gateway mints the per-server tokens itself.
SUPPORT_AUDIENCE = "warrant"

# The default user. The shipped rules let a support lead answer for a row the
# desk does not own; carol carries the `support-leads` group in the realm and
# owns `support-lead-agent`, which holds the database and mail tools.
SUPPORT_USER = "carol"

# The servers whose tools this role holds. The gateway re-exports every server
# it knows; the model is offered only these two.
SUPPORT_TOOL_PREFIXES = ("db.", "mail.")

# Calls that change something, derived from the access graph's `action_kind`
# for the tools support-agent holds. A hand-kept copy could disagree with the
# graph the gateway decides with.
WRITE_TOOLS = write_tools_from_graph(SUPPORT_AGENT)


def task_message(task: Task) -> str:
    """The first user turn: which ticket, for which person."""
    ticket = task.params.get("ticket")
    if ticket is None:
        raise AgentError("a support task needs params['ticket']")
    return f"Answer support ticket #{ticket} as {task.user}."


def summary_subject(task: Task) -> str:
    """The task's subject in the shape a support summary names it."""
    ticket = task.params.get("ticket")
    if ticket is None:
        raise AgentError("a support task needs params['ticket']")
    return f"ticket #{ticket}"


SUPPORT_ROLE = Role(
    name="support",
    agent=SUPPORT_AGENT,
    audience=SUPPORT_AUDIENCE,
    prompt_path=PROMPT_PATH,
    first_message=task_message,
    summary_subject=summary_subject,
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
    parser.add_argument(
        "--user",
        default=SUPPORT_USER,
        help=(
            "the human the token is for; the shipped rules answer as a support lead, which is carol"
        ),
    )
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
    "SUPPORT_USER",
    "Outcome",
    "main",
    "parse_args",
    "run",
    "summary_subject",
    "task_message",
    "write_tools_from_graph",
]


if __name__ == "__main__":
    raise SystemExit(main())
