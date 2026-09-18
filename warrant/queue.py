"""The human queue for escalations no verdict could answer.

A call reaches this queue when the adjudicator deferred it, when its verdict did
not validate, or when no adjudicator could be reached at all. Each entry carries
the full `AuthzRequest`, so the person reading it sees the tool, the resource,
the chain, the provenance, and the taint fields without opening another file,
plus the adjudicator's reason for not deciding and the raw tool arguments when
there were any.

The queue is `runs/queue.jsonl`, one JSON object per line. A resolution appends
a new snapshot of the same entry rather than rewriting the file, so the record
of what a person was asked and what they answered is append-only like the rest
of a run. `approve` mints a `Grant` through `warrant.grants`; `deny` records the
refusal. The CLI is the whole interface:

    uv run python -m warrant queue list
    uv run python -m warrant queue approve <id> --minutes 10
    uv run python -m warrant queue deny <id>
"""

from __future__ import annotations

import argparse
import logging
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel

from warrant.config import RUNS_DIR
from warrant.grants import SOURCE_HUMAN, Grant, GrantStore
from warrant.models import AdjudicatorVerdict, AuthzRequest

logger = logging.getLogger(__name__)

QUEUE_NAME = "queue.jsonl"


class QueueItem(BaseModel):
    """One escalation waiting for a person, and the answer when it has one."""

    id: str
    ts: AwareDatetime
    status: Literal["pending", "approved", "denied"] = "pending"
    reason: str = ""
    request: AuthzRequest
    verdict: AdjudicatorVerdict | None = None
    raw: dict[str, Any] | None = None
    minutes: int | None = None
    grant_id: str | None = None
    resolved_at: AwareDatetime | None = None


class Queue:
    """The pending escalations and their resolutions, by task."""

    def __init__(self, root: Path | str = RUNS_DIR) -> None:
        self.root = Path(root)

    @property
    def path(self) -> Path:
        return self.root / QUEUE_NAME

    def add(
        self,
        request: AuthzRequest,
        *,
        reason: str,
        verdict: AdjudicatorVerdict | None = None,
        raw: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> QueueItem:
        """Append one pending escalation and return it."""
        item = QueueItem(
            id=uuid.uuid4().hex[:12],
            ts=now or datetime.now(UTC),
            reason=reason,
            request=request,
            verdict=verdict,
            raw=raw,
        )
        self._append(item)
        return item

    def read(self) -> list[QueueItem]:
        """Every line on disk, oldest first. Unreadable lines are skipped."""
        if not self.path.exists():
            return []
        items: list[QueueItem] = []
        for number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                items.append(QueueItem.model_validate_json(line))
            except ValueError as error:
                logger.warning(
                    "skipping unreadable queue line at %s:%d: %s", self.path, number, error
                )
        return items

    def latest(self) -> list[QueueItem]:
        """The most recent snapshot of each entry, in the order it was queued."""
        by_id: dict[str, QueueItem] = {}
        order: list[str] = []
        for item in self.read():
            if item.id not in by_id:
                order.append(item.id)
            by_id[item.id] = item
        return [by_id[item_id] for item_id in order]

    def pending(self) -> list[QueueItem]:
        """Every entry no person has answered yet."""
        return [item for item in self.latest() if item.status == "pending"]

    def get(self, item_id: str) -> QueueItem | None:
        """The latest snapshot of one entry, or None."""
        for item in self.latest():
            if item.id == item_id:
                return item
        return None

    def approve(
        self,
        item_id: str,
        minutes: int,
        *,
        grants: GrantStore | None = None,
        now: datetime | None = None,
    ) -> tuple[QueueItem, Grant]:
        """Answer one pending entry with a time box and mint its grant.

        The grant is keyed on the task, tool, and resource the entry recorded,
        so the approval answers exactly the call the person read.
        """
        at = now or datetime.now(UTC)
        item = self._pending_or_refuse(item_id)
        store = grants or GrantStore(self.root)
        grant = store.mint(
            task_id=item.request.chain.task_id,
            tool=item.request.tool,
            resource=item.request.resource,
            minutes=minutes,
            source=SOURCE_HUMAN,
            now=at,
        )
        resolved = item.model_copy(
            update={
                "status": "approved",
                "minutes": minutes,
                "grant_id": grant.id,
                "resolved_at": at,
            }
        )
        self._append(resolved)
        return resolved, grant

    def deny(self, item_id: str, *, now: datetime | None = None) -> QueueItem:
        """Answer one pending entry with a refusal."""
        item = self._pending_or_refuse(item_id)
        resolved = item.model_copy(
            update={
                "status": "denied",
                "resolved_at": now or datetime.now(UTC),
            }
        )
        self._append(resolved)
        return resolved

    def _pending_or_refuse(self, item_id: str) -> QueueItem:
        item = self.get(item_id)
        if item is None:
            raise KeyError(f"no queue entry {item_id!r}")
        if item.status != "pending":
            raise ValueError(f"queue entry {item_id!r} is already {item.status}")
        return item

    def _append(self, item: QueueItem) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(item.model_dump_json() + "\n")


def render_pending(item: QueueItem) -> str:
    """One pending entry as one line for the CLI."""
    return (
        f"{item.id}  {item.request.tool} -> {item.request.resource}  "
        f"task={item.request.chain.task_id}  {item.reason}"
    )


def main(argv: Sequence[str] | None = None, *, queue: Queue | None = None) -> int:
    """The `warrant queue` CLI.

    `queue` is an injection point for the tests; the CLI itself reads the runs
    directory the process is configured with.
    """
    parser = argparse.ArgumentParser(
        prog="warrant queue", description="The human queue for escalated calls."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="show the escalations waiting for a person")
    approve = sub.add_parser("approve", help="approve one escalation with a time box")
    approve.add_argument("id", help="the queue entry id")
    approve.add_argument("--minutes", type=int, required=True, help="how long the grant lasts")
    deny = sub.add_parser("deny", help="refuse one escalation")
    deny.add_argument("id", help="the queue entry id")
    args = parser.parse_args(argv)

    queue = queue or Queue()
    if args.command == "list":
        pending = queue.pending()
        if not pending:
            print("no pending escalations")
            return 0
        for item in pending:
            print(render_pending(item))
        return 0
    try:
        if args.command == "approve":
            item, grant = queue.approve(args.id, args.minutes)
            print(
                f"approved {item.id}: grant {grant.id} for {grant.tool} on {grant.resource}, "
                f"expires {grant.expires_at.isoformat()}"
            )
            return 0
        item = queue.deny(args.id)
        print(f"denied {item.id}: {item.request.tool} -> {item.request.resource}")
        return 0
    except (KeyError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
