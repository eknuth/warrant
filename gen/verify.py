"""Read a seeded scenario back and assert it matches the file.

The seeder can be right and the seed still be wrong: a reset can miss a table, a
commit can land under the wrong author, a message can fail to reach the inbox.
So after seeding, every object the file names is read back from the system that
holds it and compared with the file. The Gitea reads go through `GiteaForge`,
which is the same forge the W3 server registers its tools over, so the
`author_tier` this prints is the one a tool call returns.

Each check is two-directional where it can be. The scenario's objects have to be
present and match, and the system may not hold an object the scenario did not
name: the org's repository list and the graph's agent ids are compared as sets,
so a leftover repo or agent fails the readback rather than passing unnoticed.
The Gitea repository list is paged, the way the reset pages its own reads, so a
scenario with more than fifty repositories is not silently unchecked.

The output is a flat list of deterministic lines: no timestamps, no commit
shas, no generated key values, and every list sorted. Seeding one scenario
twice therefore prints the same bytes, which is what makes a re-seed provable
rather than merely plausible.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import psycopg

from scripts.seed_smoke import SeedSettings
from servers.gitea_mcp.forge import GiteaForge
from servers.mail_mcp.mail import MailSettings
from warrant.graph import Graph

from .schema import Scenario, shipped_agent_rows
from .seed import (
    CUSTOMER_SENSITIVITY,
    DEFAULT_GRAPH_DB,
    MESSAGE_ID_DOMAIN,
    TICKET_SENSITIVITY,
    require_ok,
)


@dataclass(frozen=True)
class Check:
    """One readback assertion, its verdict, and the evidence."""

    name: str
    ok: bool
    detail: str


@dataclass
class VerifyReport:
    """Every check for one scenario."""

    scenario_id: str
    checks: list[Check]

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)


def _check(name: str, ok: bool, detail: str) -> Check:
    return Check(name=name, ok=bool(ok), detail=detail)


def _expiry(value: str | None) -> datetime | None:
    """The scenario's ISO 8601 expiry as an aware datetime, or None."""
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def verify_graph(scenario: Scenario, graph_db: Path | str) -> list[Check]:
    """The scenario's agents, the shipped agent set, and the database rows."""
    checks: list[Check] = []
    with Graph(graph_db) as graph:
        rows: list[tuple[str, bool]] = []
        for agent in scenario.seed.graph.agents:
            row = graph.agent(agent.client_id)
            owner = graph.human(row.owner_human_id) if row and row.owner_human_id else None
            rows.append(
                (
                    agent.client_id,
                    row is not None
                    and owner is not None
                    and owner.login == agent.owner
                    and row.justification == agent.justification
                    and row.justification_expires_at == _expiry(agent.justification_expires_at)
                    and row.allowed_tools == list(agent.allowed_tools),
                )
            )
        missing = [client_id for client_id, ok in rows if not ok]
        checks.append(
            _check(
                "graph agents",
                not missing,
                f"{len(rows)} rows match the scenario" if not missing else f"mismatched: {missing}",
            )
        )

        expected_agents = set(shipped_agent_rows()) | {
            agent.client_id for agent in scenario.seed.graph.agents
        }
        actual_agents = {agent.id for agent in graph.agents()}
        checks.append(
            _check(
                "graph agent set",
                actual_agents == expected_agents,
                f"{len(actual_agents)} agents; "
                f"extra={sorted(actual_agents - expected_agents)} "
                f"missing={sorted(expected_agents - actual_agents)}",
            )
        )

        resources: list[tuple[str, bool]] = []
        for customer in scenario.seed.db.customers:
            row = graph.resource_named(str(customer.id), "db_customer")
            owner = graph.human(row.owner_human_id) if row else None
            resources.append(
                (
                    f"db-customer-{customer.id}",
                    row is not None
                    and owner is not None
                    and owner.login == customer.owner_login
                    and row.sensitivity == CUSTOMER_SENSITIVITY,
                )
            )
        customers = {customer.id: customer for customer in scenario.seed.db.customers}
        for ticket in scenario.seed.db.tickets:
            row = graph.resource_named(str(ticket.id), "db_ticket")
            owner_login = customers[ticket.customer_id].owner_login
            owner = graph.human(row.owner_human_id) if row else None
            resources.append(
                (
                    f"db-ticket-{ticket.id}",
                    row is not None
                    and owner is not None
                    and owner.login == owner_login
                    and row.sensitivity == TICKET_SENSITIVITY,
                )
            )
        missing = [name for name, ok in resources if not ok]
        checks.append(
            _check(
                "graph db resources",
                not missing,
                f"{len(resources)} rows match the scenario"
                if not missing
                else f"mismatched: {missing}",
            )
        )
    return checks


def _org_repo_rows(settings: SeedSettings) -> list[dict[str, Any]]:
    """Every repository in `acme`, paged, with the admin token."""
    rows: list[dict[str, Any]] = []
    with httpx.Client(
        base_url=settings.gitea_url.rstrip("/"),
        headers={"Authorization": f"token {settings.gitea_admin_token}"},
        timeout=20.0,
    ) as client:
        page = 1
        while True:
            response = require_ok(
                client.get("/api/v1/orgs/acme/repos", params={"page": page, "limit": 50}),
                f"GET /orgs/acme/repos page {page}",
            )
            batch = response.json()
            if not isinstance(batch, list):
                raise RuntimeError("GET /orgs/acme/repos did not answer a list")
            rows.extend(batch)
            if len(batch) < 50:
                return rows
            page += 1


async def _verify_gitea(
    scenario: Scenario, settings: SeedSettings, repo_rows: list[dict[str, Any]]
) -> list[Check]:
    checks: list[Check] = []
    members = set(scenario.seed.gitea.members)
    by_name = {str(row.get("full_name", "")): row for row in repo_rows}
    expected_names = {f"acme/{repo.name}" for repo in scenario.seed.gitea.repos}
    checks.append(
        _check(
            "gitea repo set",
            set(by_name) == expected_names,
            f"{len(by_name)} repos; extra={sorted(set(by_name) - expected_names)} "
            f"missing={sorted(expected_names - set(by_name))}",
        )
    )
    forge = GiteaForge(settings.gitea_url, settings.gitea_admin_token)
    try:
        for repo in sorted(scenario.seed.gitea.repos, key=lambda item: item.name):
            full_name = f"acme/{repo.name}"
            listed = by_name.get(full_name)
            private = bool(listed.get("private")) if listed is not None else None
            branch = str(listed.get("default_branch", "")) if listed is not None else ""
            checks.append(
                _check(
                    f"gitea repo {full_name}",
                    listed is not None
                    and private == (repo.visibility == "private")
                    and branch == "main",
                    f"private={private} default_branch={branch!r}",
                )
            )
            if listed is None:
                continue
            for path, file in sorted(repo.file_entries().items()):
                read = await forge.get_file(full_name, path)
                want_tier = "member" if file.author in members else "external"
                checks.append(
                    _check(
                        f"gitea file {full_name}:{path}",
                        read.content == file.content
                        and read.source.author == file.author
                        and read.source.author_tier == want_tier,
                        f"author={read.source.author} (want {file.author}) "
                        f"tier={read.source.author_tier} (want {want_tier}) "
                        f"bytes={len(read.content.encode('utf-8'))}",
                    )
                )
            for issue in sorted(repo.issues, key=lambda item: item.number):
                read = await forge.get_issue(full_name, issue.number)
                tier = "member" if issue.author in members else "external"
                comments_ok = [(comment.author, comment.body) for comment in read.comments] == [
                    (comment.author, comment.body) for comment in issue.comments
                ]
                checks.append(
                    _check(
                        f"gitea issue {full_name}#{issue.number}",
                        read.title == issue.title
                        and read.body == issue.body
                        and read.author == issue.author
                        and read.source.author_tier == tier
                        and comments_ok,
                        f"author={read.author} tier={read.source.author_tier} "
                        f"comments={len(read.comments)}",
                    )
                )
    finally:
        await forge.aclose()
    return checks


def verify_gitea(scenario: Scenario, settings: SeedSettings) -> list[Check]:
    """The org read back through the forge the W3 server wraps."""
    if not settings.gitea_admin_token:
        return [_check("gitea", False, "GITEA_ADMIN_TOKEN is not set")]
    repo_rows = _org_repo_rows(settings)
    return asyncio.run(_verify_gitea(scenario, settings, repo_rows))


def verify_postgres(scenario: Scenario, settings: SeedSettings) -> list[Check]:
    """The four support tables, compared row for row."""
    checks: list[Check] = []
    with psycopg.connect(settings.dsn()) as conn:
        customers = [
            (row[0], row[1], row[2], row[3])
            for row in conn.execute(
                "SELECT id, name, email, owner_login FROM customers ORDER BY id"
            ).fetchall()
        ]
        expected_customers = [
            (item.id, item.name, item.email, item.owner_login)
            for item in sorted(scenario.seed.db.customers, key=lambda item: item.id)
        ]
        checks.append(
            _check(
                "db customers",
                customers == expected_customers,
                f"{len(customers)} rows",
            )
        )
        tickets = [
            (row[0], row[1], row[2], row[3], row[4], row[5], row[6])
            for row in conn.execute(
                "SELECT id, customer_id, subject, body, author_email, status, incident_id "
                "FROM tickets ORDER BY id"
            ).fetchall()
        ]
        expected_tickets = [
            (
                item.id,
                item.customer_id,
                item.subject,
                item.body,
                item.author_email,
                item.status,
                item.incident_id,
            )
            for item in sorted(scenario.seed.db.tickets, key=lambda item: item.id)
        ]
        checks.append(_check("db tickets", tickets == expected_tickets, f"{len(tickets)} rows"))
        notes = [
            (row[0], row[1], row[2], row[3])
            for row in conn.execute(
                "SELECT id, ticket_id, author_login, body FROM notes ORDER BY id"
            ).fetchall()
        ]
        expected_notes = [
            (index + 1, item.ticket_id, item.author_login, item.body)
            for index, item in enumerate(scenario.seed.db.notes)
        ]
        checks.append(_check("db notes", notes == expected_notes, f"{len(notes)} rows"))
        keys = [
            (row[0], row[1], row[2], row[3])
            for row in conn.execute(
                "SELECT id, customer_id, label, revoked FROM api_keys ORDER BY id"
            ).fetchall()
        ]
        expected_keys = [
            (index + 1, item.customer_id, item.label, item.revoked)
            for index, item in enumerate(scenario.seed.db.api_keys)
        ]
        checks.append(_check("db api_keys", keys == expected_keys, f"{len(keys)} rows"))
    return checks


def verify_mail(scenario: Scenario, mail_settings: MailSettings) -> list[Check]:
    """Every seeded message, read back from the mailbox by its message id."""
    url = mail_settings.mail_url.rstrip("/")
    try:
        listing = require_ok(
            httpx.get(f"{url}/api/v1/messages", timeout=15.0), "GET /api/v1/messages"
        ).json()
    except httpx.HTTPError as error:
        return [_check("mail inbox", False, f"mailpit is unreachable: {error}")]
    messages = {
        str(item.get("MessageID", "")).strip("<>"): item for item in listing.get("messages") or []
    }
    checks: list[Check] = []
    expected_ids: list[str] = []
    for index, message in enumerate(scenario.seed.mail.inbox):
        message_id = message.message_id or f"{scenario.id}.{index}@{MESSAGE_ID_DOMAIN}"
        expected_ids.append(message_id)
        item = messages.get(message_id)
        if item is None:
            checks.append(_check(f"mail {message_id}", False, "not in the inbox"))
            continue
        detail = require_ok(
            httpx.get(f"{url}/api/v1/message/{item.get('ID', '')}", timeout=15.0),
            f"GET /api/v1/message/{item.get('ID', '')}",
        ).json()
        sender = (detail.get("From") or {}).get("Address", "")
        recipients = [entry.get("Address", "") for entry in detail.get("To") or []]
        body = str(detail.get("Text") or detail.get("HTML") or "")
        checks.append(
            _check(
                f"mail {message_id}",
                sender.lower() == message.from_address.lower()
                and [address.lower() for address in recipients] == [message.to.lower()]
                and str(detail.get("Subject", "")) == message.subject
                and body.strip() == message.body.strip(),
                f"from={sender} to={','.join(recipients)} subject={detail.get('Subject', '')}",
            )
        )
    extra = sorted(set(messages) - set(expected_ids))
    checks.append(
        _check("mail inbox total", not extra, f"{len(messages)} messages, {len(extra)} not seeded")
    )
    return checks


def verify(
    scenario: Scenario,
    *,
    settings: SeedSettings | None = None,
    mail_settings: MailSettings | None = None,
    graph_db: Path | str = DEFAULT_GRAPH_DB,
) -> VerifyReport:
    """Read every seeded object back and report each comparison."""
    settings = settings or SeedSettings()
    mail_settings = mail_settings or MailSettings()
    checks = verify_graph(scenario, graph_db)
    checks += verify_gitea(scenario, settings)
    checks += verify_postgres(scenario, settings)
    checks += verify_mail(scenario, mail_settings)
    return VerifyReport(scenario_id=scenario.id, checks=checks)


def render(report: VerifyReport) -> str:
    """The report as the deterministic text `main` prints."""
    lines = [f"verify {report.scenario_id}: {'ok' if report.ok else 'FAILED'}"]
    for check in report.checks:
        mark = "ok  " if check.ok else "FAIL"
        lines.append(f"  {mark} {check.name}: {check.detail}")
    return "\n".join(lines)


__all__ = [
    "Check",
    "VerifyReport",
    "render",
    "verify",
    "verify_gitea",
    "verify_graph",
    "verify_mail",
    "verify_postgres",
]
