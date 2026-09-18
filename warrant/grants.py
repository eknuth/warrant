"""Time-boxed grants: the narrow allowance an approval mints.

An escalation is answered either by the adjudicator or by a person reading the
queue. Either answer that approves mints one `Grant`: a tool, a resource, a task
id, and an expiry. The gateway checks the grant before the engine, and a
matching unexpired grant turns the call into an allow with
`policy_ids: ["grant:<id>"]`, which is the line that says a person's answer let
this call through rather than a policy.

The grant is narrow on purpose. The tool and the resolved resource have to match
exactly, and the task id has to be the one the approval was for, so an approval
for a key rotation does not authorize another tool, another customer, or another
task. The expiry is what makes the approval time-boxed: after it passes the same
call escalates again.

The store is append-only JSONL under the runs directory. A file rather than a
process memory is what lets the queue CLI, which is a separate process, mint the
grant a running gateway then honors. `find` reads the file on each check, so a
grant minted by the CLI after the gateway started is visible without a restart.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import AwareDatetime, BaseModel

from warrant.config import RUNS_DIR

logger = logging.getLogger(__name__)

GRANTS_NAME = "grants.jsonl"

# The two answers that mint a grant. The source is on the record so a reader can
# tell an approval the adjudicator gave from one a person gave.
SOURCE_ADJUDICATOR = "adjudicator"
SOURCE_HUMAN = "human"

# The bounds an approval's time box has to fall in. The adjudicator's verdict
# carries the same bounds; the CLI enforces them for a person, so a grant can
# never be open-ended from either direction.
MIN_MINUTES = 1
MAX_MINUTES = 60


class Grant(BaseModel):
    """One narrow allowance, for one task, tool, and resource, until it expires."""

    id: str
    task_id: str
    tool: str
    resource: str
    minutes: int
    created_at: AwareDatetime
    expires_at: AwareDatetime
    source: str = SOURCE_HUMAN


class GrantStore:
    """Grants as append-only JSONL, keyed by task, tool, and resource."""

    def __init__(self, root: Path | str = RUNS_DIR) -> None:
        self.root = Path(root)

    @property
    def path(self) -> Path:
        return self.root / GRANTS_NAME

    def read(self) -> list[Grant]:
        """Every grant on disk, oldest first. Unreadable lines are skipped.

        A grant line is a record, not a contract to be enforced: a line this
        version cannot parse is a line from another version, and refusing every
        later grant because of it would make an old file unusable. The skip is
        logged rather than silent.
        """
        if not self.path.exists():
            return []
        grants: list[Grant] = []
        for number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                grants.append(Grant.model_validate_json(line))
            except ValueError as error:
                logger.warning("skipping unreadable grant at %s:%d: %s", self.path, number, error)
        return grants

    def mint(
        self,
        *,
        task_id: str,
        tool: str,
        resource: str,
        minutes: int,
        source: str = SOURCE_HUMAN,
        now: datetime | None = None,
    ) -> Grant:
        """Write one grant and return it.

        The time box is bounded here as well as in the verdict, because the CLI
        is a second way to mint one and an open-ended grant would outlive the
        task it was answered for.
        """
        if not MIN_MINUTES <= minutes <= MAX_MINUTES:
            raise ValueError(f"a time box is {MIN_MINUTES}..{MAX_MINUTES} minutes, not {minutes}")
        created = now or datetime.now(UTC)
        grant = Grant(
            id=str(uuid.uuid4()),
            task_id=task_id,
            tool=tool,
            resource=resource,
            minutes=minutes,
            created_at=created,
            expires_at=created + timedelta(minutes=minutes),
            source=source,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(grant.model_dump_json() + "\n")
        return grant

    def find(
        self,
        *,
        task_id: str,
        tool: str,
        resource: str,
        now: datetime | None = None,
    ) -> Grant | None:
        """The latest unexpired grant for exactly this task, tool, and resource.

        The match is exact on all three, so a grant for one tool never answers
        another tool and a grant for one resource never answers another. The
        latest matching grant wins, which is the one a person most recently
        answered for.
        """
        at = now or datetime.now(UTC)
        matching = [
            grant
            for grant in self.read()
            if grant.task_id == task_id
            and grant.tool == tool
            and grant.resource == resource
            and grant.expires_at > at
        ]
        return matching[-1] if matching else None


def grant_policy_id(grant: Grant) -> str:
    """The policy id a granted call is logged with."""
    return f"grant:{grant.id}"
