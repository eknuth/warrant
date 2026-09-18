"""The ticket or issue a task is about, fetched by Warrant for the adjudicator.

The adjudicator has to answer whether the subject a task named justifies the
call that escalated. Warrant fetches that subject itself, with its own
credential: the ticket comes from the support database over `psycopg`, the issue
from the forge over its admin API, and neither fetch goes through the agent's
token or the MCP gateway. An agent that could choose what the adjudicator reads
could choose its own evidence.

Which record is the subject comes from the ledger, not from a claim. The first
source a task read whose kind is `ticket` or `issue` is the record the task is
about; a customer row, a repository, or a file is context rather than a subject.
The source's own id is the subject id the verdict has to cite, so the citation
check and the fetch read the same value.

The subject's text is data. It can quote an instruction, and an issue an
external author wrote is exactly the case the deny rule is for, so the prompt
says so and the fetched fields are rendered as fields rather than as
instructions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

import httpx
import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

from warrant.models import Provenance, Tier

logger = logging.getLogger(__name__)

# The source kinds that make a task's subject. Every other kind the ledger holds
# is context the adjudicator may read but not the record the task is about.
SUBJECT_KINDS = ("ticket", "issue")

# The most of a subject's own text the adjudicator sees. A ticket body is a few
# paragraphs; a cap keeps one enormous record from crowding the ledger out of
# the prompt, and the truncation is marked so the model can see it happened.
SUBJECT_TEXT_LIMIT = 4000
TRUNCATION_MARK = "\n[truncated]"

# How long a subject fetch may take before it gives up and the call waits for a
# person. Small next to the adjudicator's own timeout: a fetch that hangs means
# the database or the forge is not answering, and a slow answer is not evidence.
FETCH_TIMEOUT_S = 20.0


class SubjectSettings(BaseSettings):
    """What a subject fetch reads from `.env` and the environment.

    The same names the postgres MCP server and the gitea MCP server read, so one
    `.env` configures all three. The passwords and tokens default to empty, so
    constructing these settings never fails and importing this module needs no
    secret; a fetch without one is refused rather than attempted with an empty
    bearer.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "warrant"
    postgres_password: str = ""
    postgres_db: str = "support"
    gitea_url: str = "http://localhost:3000"
    gitea_admin_token: str = ""

    def dsn(self) -> str:
        """A connection string for the support database, built from the parts.

        Built here rather than carried as one URL so no secret is written into
        a config file or a default.
        """
        return psycopg.conninfo.make_conninfo(
            host=self.postgres_host,
            port=self.postgres_port,
            user=self.postgres_user,
            password=self.postgres_password,
            dbname=self.postgres_db,
        )


class SubjectDoc(BaseModel):
    """The ticket or issue a task named, as the adjudicator sees it.

    `id` is the ledger source's own id, which is the value a verdict has to cite
    back. `tier` is the tier Warrant classified the source with, so an external
    issue is external in the adjudicator's input as well as in the policy's.
    """

    system: str
    kind: str
    id: str
    title: str = ""
    body: str = ""
    author: str = ""
    tier: Tier = Tier.unknown
    incident_id: str | None = None


@dataclass(frozen=True)
class SubjectRef:
    """A ledger source that names the task's subject, before it is fetched."""

    system: str
    kind: str
    id: str
    author: str
    tier: Tier


class SubjectFetcher(Protocol):
    """What the gateway needs to turn a ledger source into a subject document."""

    async def __call__(self, ref: SubjectRef, /) -> SubjectDoc | None: ...


def subject_ref(provenance: Provenance) -> SubjectRef | None:
    """The first ticket or issue the task's ledger holds, or None.

    First in ledger order, which is the order the task read them. The ledger is
    the authority on what the task named: nothing the agent sends in a call body
    reaches it.
    """
    for source in provenance.sources:
        if source.kind in SUBJECT_KINDS:
            return SubjectRef(
                system=source.system,
                kind=source.kind,
                id=source.id,
                author=source.author,
                tier=source.author_tier,
            )
    return None


def truncate(text: str, limit: int = SUBJECT_TEXT_LIMIT) -> str:
    """`text` cut to `limit` characters, with the cut marked."""
    if len(text) <= limit:
        return text
    return text[:limit] + TRUNCATION_MARK


async def fetch_subject(
    ref: SubjectRef,
    *,
    settings: SubjectSettings | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> SubjectDoc | None:
    """Fetch one subject with Warrant's own credential, or None.

    A fetch that cannot be made (no credential, an unreachable database or
    forge, a subject that is gone) is None. The caller treats that as a
    deferral, because a verdict that cannot cite the subject is not a verdict.
    """
    settings = settings or SubjectSettings()
    try:
        if ref.system == "db" and ref.kind == "ticket":
            return await _fetch_ticket(ref, settings)
        if ref.system == "gitea" and ref.kind == "issue":
            return await _fetch_issue(ref, settings, transport=transport)
    except Exception as error:  # noqa: BLE001 - a fetch that fails defers the call
        logger.warning("could not fetch subject %s %s: %s", ref.system, ref.id, error)
        return None
    logger.warning("no subject fetch for %s/%s", ref.system, ref.kind)
    return None


async def _fetch_ticket(ref: SubjectRef, settings: SubjectSettings) -> SubjectDoc | None:
    """One ticket row, read over Warrant's own database connection."""
    if not settings.postgres_password:
        logger.warning("no postgres credential to fetch ticket %s", ref.id)
        return None
    try:
        ticket_id = int(ref.id)
    except ValueError:
        return None
    connection = await psycopg.AsyncConnection.connect(
        settings.dsn(), row_factory=dict_row, connect_timeout=int(FETCH_TIMEOUT_S)
    )
    async with connection:
        cursor = await connection.execute(
            "SELECT id, subject, body, author_email, status, incident_id "
            "FROM tickets WHERE id = %s",
            (ticket_id,),
        )
        row = await cursor.fetchone()
    if row is None:
        return None
    return SubjectDoc(
        system="db",
        kind="ticket",
        id=str(row["id"]),
        title=str(row["subject"] or ""),
        body=truncate(str(row["body"] or "")),
        author=str(row["author_email"] or ""),
        tier=ref.tier,
        incident_id=row["incident_id"],
    )


async def _fetch_issue(
    ref: SubjectRef,
    settings: SubjectSettings,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> SubjectDoc | None:
    """One issue, read over Warrant's own forge credential.

    The issue's id is `<owner>/<name>#<number>`, the shape the ledger records.
    Comments are not fetched: the subject is the record the task named, and the
    ledger already holds what the agent actually read.
    """
    if not settings.gitea_admin_token:
        logger.warning("no forge credential to fetch issue %s", ref.id)
        return None
    repo, separator, number = ref.id.rpartition("#")
    if not separator or not repo or not number.isdigit():
        logger.warning("issue id %r is not <owner>/<name>#<number>", ref.id)
        return None
    async with httpx.AsyncClient(
        base_url=settings.gitea_url,
        headers={"Authorization": f"token {settings.gitea_admin_token}"},
        timeout=FETCH_TIMEOUT_S,
        transport=transport,
    ) as client:
        response = await client.get(f"/api/v1/repos/{repo}/issues/{number}")
    if response.status_code != 200:
        logger.warning("forge refused issue %s: HTTP %d", ref.id, response.status_code)
        return None
    data = response.json()
    author = data.get("user") or {}
    return SubjectDoc(
        system="gitea",
        kind="issue",
        id=ref.id,
        title=str(data.get("title") or ""),
        body=truncate(str(data.get("body") or "")),
        author=str(author.get("login") or ""),
        tier=ref.tier,
    )
