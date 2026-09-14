"""One unit of work an agent takes on, and the chain it carries while it does.

A `Task` is what the CLI builds and what `agents/triage.py` runs. `task_id` is
a uuid4 generated when the task is built, and it is the value bound into the
on-behalf-of token and repeated on every log line the run writes.

`Chain` is the delegation triple those log lines carry: the human the work is
about, the agent client acting for them, and the task id. `sub` is the human's
login rather than the identity provider's opaque subject id, because that is
what a run reader can check against the task; `sub_id` keeps the token's own
subject claim so the line still points back at the signed token. The rest of
the token, as decoded with the signature stripped, is written once per task to
`runs/<task_id>/token.json`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, Field


class Task(BaseModel):
    """One triage or support job.

    `subject` is a one-line description for a run record. `params` carries what
    the role needs to build its first message; for a triage task that is the
    repository and the issue number.
    """

    kind: Literal["triage", "support"] = "triage"
    subject: str
    user: str
    params: dict[str, Any] = Field(default_factory=dict)
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


@dataclass(frozen=True)
class Chain:
    """The `{sub, act, task_id}` triple every line of a run carries.

    `sub` is the login the task names, which is what a reader of the run record
    wants and what the ticket's criterion asks for. The token's own `sub` claim
    is a Keycloak user id, carried separately in `sub_id`.

    The two are not interchangeable across the logs. `agents/mcp_client.py`
    writes both, while the resource server's audit line
    (`servers/gitea_mcp/server.py`) writes only the signed subject, so its `sub`
    is the UUID. Two lines for the same call join on `task_id` and
    `args_digest`, or on `sub_id`, never on `sub` alone.
    """

    sub: str
    act: str
    task_id: str
    sub_id: str | None = None
