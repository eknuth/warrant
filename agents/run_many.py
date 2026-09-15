"""Run several agent tasks at once, one run directory and one token per task.

Scenario 7 needs two support tasks for two different people in flight through
the same process at the same time, and the eval runner has the same shape when
it runs a column of tasks. This module is the one way to do that. It builds the
per-task coroutine in one `asyncio.TaskGroup`, and each coroutine is a whole
run: its own login, its own on-behalf-of exchange keyed to its own task id, its
own run directory, and its own MCP session. A task that fails cancels its
siblings and the group raises the failures together.

Nothing is shared between the coroutines but the process. There is no token
cache and no module-level chain, so the token one task obtained is never
presented on another task's call. The run directories keep them apart on disk:
`runs/<task_id>/calls.jsonl` carries only its own task's `sub`, `act`, and
`task_id`.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from agents import support, triage
from agents.auth import DevSettings
from agents.loop import AgentError, Outcome
from agents.providers import Provider
from agents.task import Task

logger = logging.getLogger(__name__)


async def run_one(
    task: Task,
    *,
    provider: Provider | None = None,
    settings: DevSettings | None = None,
    runs_dir: Path | None = None,
    mcp_url: str | None = None,
) -> Outcome:
    """Run one task with the role its kind names."""
    if task.kind == "triage":
        return await triage.run(
            task, provider=provider, settings=settings, runs_dir=runs_dir, mcp_url=mcp_url
        )
    if task.kind == "support":
        return await support.run(
            task, provider=provider, settings=settings, runs_dir=runs_dir, mcp_url=mcp_url
        )
    raise AgentError(f"no role runs a {task.kind!r} task")


async def run_concurrent(
    tasks: list[Task],
    *,
    provider: Provider | None = None,
    settings: DevSettings | None = None,
    runs_dir: Path | None = None,
    mcp_url: str | None = None,
) -> list[Outcome]:
    """Run every task at the same time and return the outcomes in task order.

    `asyncio.TaskGroup`, so the tasks are one unit: when one fails the group
    cancels its siblings and waits for them to finish before it raises. A
    caller that catches the failure sees an `ExceptionGroup` holding the child
    errors, not a bare `RuntimeError`; a group whose children all raise holds
    all of them. A caller that wants partial outcomes has to catch at its own
    level, and a sibling's in-flight work is already cancelled by then.
    """
    if not tasks:
        return []
    logger.info("running %d tasks at once: %s", len(tasks), [t.task_id for t in tasks])
    async with asyncio.TaskGroup() as group:
        started = [
            group.create_task(
                run_one(
                    task,
                    provider=provider,
                    settings=settings,
                    runs_dir=runs_dir,
                    mcp_url=mcp_url,
                ),
                name=f"agent-task-{task.task_id}",
            )
            for task in tasks
        ]
    return [task.result() for task in started]
