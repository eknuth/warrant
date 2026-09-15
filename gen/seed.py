"""Seed one scenario, and reset everything a scenario owns.

`seed(scenario)` is total: it calls `reset` first, so a run starts from the same
state whether or not another scenario ran before it. The reset drops every
repository in the org and every non-admin Gitea user, truncates the four support
tables, deletes every Mailpit message, reloads the access graph from
`infra/graph.yml` plus the scenario's own agents, and recreates the scenario's
directory under `runs/`. Then the seed writes graph, Gitea, database, and
inbox, in that order.

The Gitea file commits are authored as the login the scenario names, through
that user's own credentials rather than the admin token. W11's `classify` reads
the last commit author of a file, so a file committed by the admin would be
`member` even when the scenario wrote an external's file. An author outside the
org is added as a repository collaborator first, which lets them commit while
staying `external` in `author_tier`.

The API keys are generated here and never written into a scenario file, a test,
or a commit. Only the label and the revoked flag are part of the scenario.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import psycopg

from scripts.gitea_bootstrap import ADMIN_USERNAME, wait_for_gitea
from scripts.seed_smoke import ORG, SeedSettings, advance_sequences, ensure_membership, ensure_user
from servers.mail_mcp.mail import MailSettings
from warrant.config import default_runs_dir, main_checkout
from warrant.graph import Graph

from .schema import DbSeed, GiteaSeed, RepoSeed, Scenario, graph_seed_data

# The paths under `runs/` a scenario owns. The eval runner and the ledger write
# under the same root, so the reset drops one scenario's directory and nothing
# else.
RUNS_SUBDIR = "scenarios"

# A Git commit message for a seeded file. Fixed, because the message is part of
# the repository state a re-seed has to reproduce.
FILE_MESSAGE = "seed {path} for the scenario"

# The sensitivity the seeder gives the graph rows it derives from the database.
# A customer row holds the account relationship, and the key table hangs off
# it, so it is confidential. A ticket is the customer's own words to the desk,
# which is internal.
CUSTOMER_SENSITIVITY = "confidential"
TICKET_SENSITIVITY = "internal"

# The domain the seeder writes seeded mail ids under. The message id is not a
# credential and nothing authenticates with it; it is the stable handle verify
# reads the message back by.
MESSAGE_ID_DOMAIN = "scenario.warrant.test"

# The four tables `infra/postgres/schema.sql` creates. The Postgres preflight
# requires all four before the reset deletes anything, so a database without the
# schema is refused rather than half-reset.
SUPPORT_TABLES = ("api_keys", "customers", "notes", "tickets")


def default_graph_db() -> Path:
    """The access graph the seeder writes and the compose gateway reads.

    `WARRANT_GRAPH_DB` wins when it is set, the same variable the gateway's own
    settings read. Otherwise the path is `runs/graph/warrant.db` under the main
    checkout, which is the directory `compose.yml` bind-mounts into the gateway
    at `/app/runs`. It is deliberately not derived from `WARRANT_RUNS_DIR`: a
    column that points its own records at another directory still has to share
    the one graph file with the gateway, or a scenario's rows would be invisible
    to the process that decides on them.
    """
    override = os.environ.get("WARRANT_GRAPH_DB")
    if override:
        return Path(override)
    return main_checkout() / "runs" / "graph" / "warrant.db"


DEFAULT_GRAPH_DB = default_graph_db()


class SeedError(RuntimeError):
    """A seeding call failed in a way the caller should see."""


@dataclass
class SeedReport:
    """What one seed wrote, and how long it took."""

    scenario_id: str
    elapsed_s: float
    repos: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    customers: int = 0
    tickets: int = 0
    messages: int = 0
    run_dir: Path | None = None


def scenario_run_dir(scenario_id: str) -> Path:
    """The `runs/` directory one scenario owns."""
    return default_runs_dir() / RUNS_SUBDIR / scenario_id


def require_ok(response: httpx.Response, what: str) -> httpx.Response:
    if response.status_code >= 400:
        raise SeedError(f"{what} -> HTTP {response.status_code}: {response.text.strip()[:200]}")
    return response


def _list_all(client: httpx.Client, path: str) -> list[dict[str, Any]]:
    """Every page of a Gitea list endpoint, on the way to a total reset."""
    items: list[dict[str, Any]] = []
    page = 1
    while True:
        response = require_ok(
            client.get(path, params={"page": page, "limit": 50}), f"GET {path} page {page}"
        )
        batch = response.json()
        if not isinstance(batch, list):
            raise SeedError(f"GET {path} did not answer a list")
        items.extend(batch)
        if len(batch) < 50:
            return items
        page += 1


def gitea_client(settings: SeedSettings) -> httpx.Client:
    """An admin-authenticated client for the seeding API."""
    if not settings.gitea_admin_token:
        raise SeedError("GITEA_ADMIN_TOKEN is not set; run scripts/gitea_bootstrap.py")
    return httpx.Client(
        base_url=settings.gitea_url.rstrip("/"),
        headers={"Authorization": f"token {settings.gitea_admin_token}"},
        timeout=20.0,
    )


@contextmanager
def _as(settings: SeedSettings, login: str) -> Iterator[httpx.Client]:
    """A client acting as one Gitea user, through their own password.

    The `git` credential is the realm's dev password, the same one the smoke
    seeder uses. It is read from `.env` and never written or printed.
    """
    if not settings.warrant_user_password:
        raise SeedError(f"WARRANT_USER_PASSWORD is not set; cannot act as {login}")
    with httpx.Client(
        base_url=settings.gitea_url.rstrip("/"),
        auth=(login, settings.warrant_user_password),
        timeout=20.0,
    ) as client:
        yield client


# -- reset -----------------------------------------------------------------


def reset_gitea(client: httpx.Client) -> None:
    """Delete every repository in the org and every non-admin user."""
    for repo in _list_all(client, f"/api/v1/orgs/{ORG}/repos"):
        full_name = repo.get("full_name", "")
        if full_name:
            require_ok(client.delete(f"/api/v1/repos/{full_name}"), f"DELETE /repos/{full_name}")
    for user in _list_all(client, "/api/v1/admin/users"):
        login = str(user.get("login", ""))
        if not login or user.get("is_admin") or login == ADMIN_USERNAME:
            continue
        # Gitea refuses to delete a user who is still in an organization, so
        # every membership comes off first.
        for org in _list_all(client, f"/api/v1/users/{login}/orgs"):
            name = str(org.get("username") or org.get("name") or "")
            if name:
                client.delete(f"/api/v1/orgs/{name}/members/{login}")
        require_ok(client.delete(f"/api/v1/admin/users/{login}"), f"DELETE /admin/users/{login}")


def reset_postgres(settings: SeedSettings) -> None:
    """Truncate the four support tables and restart their identities."""
    with psycopg.connect(settings.dsn()) as conn:
        conn.execute("TRUNCATE customers, tickets, api_keys, notes RESTART IDENTITY CASCADE")


def reset_mail(mail_settings: MailSettings) -> None:
    """Delete every message Mailpit holds."""
    url = f"{mail_settings.mail_url.rstrip('/')}/api/v1/messages"
    try:
        response = httpx.delete(url, timeout=15.0)
    except httpx.HTTPError as error:
        raise SeedError(f"mailpit is unreachable at {mail_settings.mail_url}: {error}") from error
    require_ok(response, f"DELETE {url}")


def reset_graph(scenario: Scenario | None, graph_db: Path | str = DEFAULT_GRAPH_DB) -> Graph:
    """Reload the graph from `infra/graph.yml`, then the scenario's own rows.

    The clear comes first, so a scenario that adds an agent leaves no trace of
    it for the next scenario. The shipped seed goes back in whole: the tools and
    the resources are the authority every policy and every tool call needs, and
    a scenario file seeds agents only.
    """
    graph = Graph(graph_db)
    graph.clear()
    graph.seed(graph_seed_data())
    if scenario is not None:
        graph.seed(scenario_graph_rows(scenario, graph))
    return graph


def scenario_graph_rows(scenario: Scenario, graph: Graph) -> dict[str, list[dict[str, Any]]]:
    """The scenario's agent rows and the database resource rows they resolve to.

    The ticket and customer rows are the ones W10 left to this issue. A
    `db.get_ticket` call resolves the argument `12` to the resource name `12`,
    so each row's `name` is its id as a string and its owner is the human the
    customer names. Without them a non-lead's honest read of their own ticket
    resolves to an unknown owner and the subject rule refuses it.
    """
    humans = {human.login: human.id for human in graph.humans()}
    customers = {customer.id: customer for customer in scenario.seed.db.customers}
    resources: list[dict[str, Any]] = []
    for customer in scenario.seed.db.customers:
        owner = humans.get(customer.owner_login)
        if owner is None:
            raise SeedError(
                f"customer {customer.id} names owner {customer.owner_login!r}, "
                "who is not a shipped human"
            )
        resources.append(
            {
                "id": f"db-customer-{customer.id}",
                "kind": "db_customer",
                "name": str(customer.id),
                "owner_human_id": owner,
                "sensitivity": CUSTOMER_SENSITIVITY,
            }
        )
    for ticket in scenario.seed.db.tickets:
        owner = humans.get(customers[ticket.customer_id].owner_login)
        if owner is None:
            raise SeedError(f"ticket {ticket.id} resolves to an owner that is not a shipped human")
        resources.append(
            {
                "id": f"db-ticket-{ticket.id}",
                "kind": "db_ticket",
                "name": str(ticket.id),
                "owner_human_id": owner,
                "sensitivity": TICKET_SENSITIVITY,
            }
        )
    agents = [
        {
            "id": agent.client_id,
            "client_id": agent.client_id,
            "owner_human_id": humans.get(agent.owner),
            "justification": agent.justification,
            "justification_expires_at": agent.justification_expires_at,
            "allowed_tools": list(agent.allowed_tools),
        }
        for agent in scenario.seed.graph.agents
    ]
    return {"agents": agents, "resources": resources}


def reset_runs(scenario_id: str) -> Path:
    """Give this scenario a fresh `runs/` directory."""
    directory = scenario_run_dir(scenario_id)
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def write_seed_manifest(report: SeedReport) -> Path:
    """Write what this seed left in the scenario's run root.

    The file is a deterministic record: no timestamp and no secret. W15 points
    `WARRANT_RUNS_DIR` at this directory for one cell, so every task record the
    cell makes lands under a root the next seed of that scenario clears. A
    reader can tell which scenario the stack currently holds from this file.
    """
    directory = report.run_dir or scenario_run_dir(report.scenario_id)
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {
        "scenario_id": report.scenario_id,
        "repos": list(report.repos),
        "users": list(report.users),
        "customers": report.customers,
        "tickets": report.tickets,
        "messages": report.messages,
    }
    target = directory / "seed.json"
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def preflight(settings: SeedSettings, mail_settings: MailSettings) -> None:
    """Check every system is reachable and ready before the reset deletes anything.

    A partial reset is worse than a refused one: the org comes back empty while
    the database still holds the previous scenario, and the caller sees a
    traceback rather than the name of the system that was down. Every check runs
    first, and each failure names the system.

    Postgres is checked for the four support tables and not only for a socket.
    A database that answers and has no schema would otherwise pass this point,
    the org would be deleted, and the seeder would fail on its first insert.
    """
    with gitea_client(settings) as client:
        try:
            wait_for_gitea(client, settings.gitea_url.rstrip("/"))
            response = client.get(f"/api/v1/orgs/{ORG}")
        except (SystemExit, Exception) as exc:
            raise SeedError(f"gitea preflight failed at {settings.gitea_url}: {exc}") from exc
        if response.status_code != 200:
            raise SeedError(
                f"gitea preflight: org {ORG} is missing (HTTP {response.status_code}); "
                "run scripts/gitea_bootstrap.py"
            )
    try:
        with psycopg.connect(settings.dsn(), connect_timeout=5) as conn:
            conn.execute("select 1")
            rows = conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
            ).fetchall()
    except psycopg.Error as exc:
        raise SeedError(
            f"postgres preflight failed at {settings.postgres_host}:{settings.postgres_port}: {exc}"
        ) from exc
    present = {str(row[0]) for row in rows}
    missing = sorted(set(SUPPORT_TABLES) - present)
    if missing:
        raise SeedError(
            f"postgres preflight: the support schema is missing {missing} in "
            f"{settings.postgres_db}; run `make reset` to load infra/postgres/schema.sql"
        )
    url = f"{mail_settings.mail_url.rstrip('/')}/api/v1/messages"
    try:
        response = httpx.get(url, timeout=15.0)
    except httpx.HTTPError as exc:
        raise SeedError(f"mailpit preflight failed at {mail_settings.mail_url}: {exc}") from exc
    if response.status_code >= 400:
        raise SeedError(f"mailpit preflight GET {url} -> HTTP {response.status_code}")


def reset(
    scenario: Scenario | None = None,
    *,
    settings: SeedSettings | None = None,
    mail_settings: MailSettings | None = None,
    graph_db: Path | str = DEFAULT_GRAPH_DB,
) -> None:
    """Drop everything a scenario owns, then put the shipped graph back.

    Called with no scenario, this is the standalone `reset` command: the org,
    the database, and the inbox come back empty and the graph is the shipped
    one. Called with a scenario, the graph also carries the scenario's agents
    and its ticket and customer rows. Every system is checked before any delete,
    and a failure during a step is reported with the step's name.
    """
    settings = settings or SeedSettings()
    mail_settings = mail_settings or MailSettings()
    preflight(settings, mail_settings)
    with gitea_client(settings) as client:
        try:
            reset_gitea(client)
        except SeedError:
            raise
        except Exception as exc:
            raise SeedError(f"gitea reset failed: {exc}") from exc
    try:
        reset_postgres(settings)
    except SeedError:
        raise
    except psycopg.Error as exc:
        raise SeedError(f"postgres reset failed: {exc}") from exc
    try:
        reset_mail(mail_settings)
    except SeedError:
        raise
    except httpx.HTTPError as exc:
        raise SeedError(f"mailpit reset failed: {exc}") from exc
    try:
        with reset_graph(scenario, graph_db):
            pass
    except SeedError:
        raise
    except Exception as exc:
        raise SeedError(f"graph reset failed: {exc}") from exc
    if scenario is not None:
        reset_runs(scenario.id)


# -- seed ------------------------------------------------------------------


def _repo_full_name(repo: RepoSeed) -> str:
    return f"{ORG}/{repo.name}"


def ensure_repo(client: httpx.Client, repo: RepoSeed) -> str:
    """Create one repository in the org, at the visibility the scenario names."""
    full_name = _repo_full_name(repo)
    response = client.post(
        f"/api/v1/orgs/{ORG}/repos",
        json={
            "name": repo.name,
            "auto_init": True,
            "default_branch": "main",
            "private": repo.visibility == "private",
        },
    )
    require_ok(response, f"POST /orgs/{ORG}/repos ({repo.name})")
    return full_name


def ensure_collaborator(client: httpx.Client, full_name: str, login: str) -> None:
    """Give a non-member write access, so their commit is authored as them."""
    response = client.put(
        f"/api/v1/repos/{full_name}/collaborators/{login}", json={"permission": "write"}
    )
    if response.status_code not in (200, 201, 204):
        raise SeedError(
            f"could not add {login} to {full_name}: "
            f"HTTP {response.status_code} {response.text.strip()[:200]}"
        )


def write_file(client: httpx.Client, full_name: str, path: str, content: str) -> None:
    """Create or replace one file through the client that authored it."""
    existing = client.get(f"/api/v1/repos/{full_name}/contents/{path}", params={"ref": "main"})
    body: dict[str, Any] = {
        "branch": "main",
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "message": FILE_MESSAGE.format(path=path),
    }
    if existing.status_code == 200:
        body["sha"] = existing.json()["sha"]
        response = client.put(f"/api/v1/repos/{full_name}/contents/{path}", json=body)
    else:
        response = client.post(f"/api/v1/repos/{full_name}/contents/{path}", json=body)
    require_ok(response, f"write {full_name}:{path}")


def create_issue(client: httpx.Client, full_name: str, title: str, body: str) -> int:
    response = require_ok(
        client.post(f"/api/v1/repos/{full_name}/issues", json={"title": title, "body": body}),
        f"file an issue in {full_name}",
    )
    return int(response.json()["number"])


def create_comment(client: httpx.Client, full_name: str, number: int, body: str) -> None:
    require_ok(
        client.post(f"/api/v1/repos/{full_name}/issues/{number}/comments", json={"body": body}),
        f"comment on {full_name}#{number}",
    )


def seed_gitea(client: httpx.Client, settings: SeedSettings, gitea: GiteaSeed) -> list[str]:
    """Create the org's users, memberships, repositories, files, and issues."""
    for login in gitea.members:
        ensure_user(client, settings, login)
        ensure_membership(client, login)
    for login in gitea.externals:
        ensure_user(client, settings, login)
    members = set(gitea.members)
    full_names: list[str] = []
    for repo in gitea.repos:
        full_name = ensure_repo(client, repo)
        full_names.append(full_name)
        for path, file in sorted(repo.file_entries().items()):
            assert file.author is not None  # the schema refuses a file with no author
            if file.author not in members:
                ensure_collaborator(client, full_name, file.author)
            with _as(settings, file.author) as author:
                write_file(author, full_name, path, file.content)
        for issue in sorted(repo.issues, key=lambda item: item.number):
            if issue.author not in members:
                ensure_collaborator(client, full_name, issue.author)
            with _as(settings, issue.author) as author:
                number = create_issue(author, full_name, issue.title, issue.body)
            if number != issue.number:
                raise SeedError(
                    f"{full_name} assigned issue number {number}, "
                    f"but the scenario declares {issue.number}; the numbers have to match"
                )
            for comment in issue.comments:
                if comment.author not in members:
                    ensure_collaborator(client, full_name, comment.author)
                with _as(settings, comment.author) as author:
                    create_comment(author, full_name, number, comment.body)
    return full_names


def seed_postgres(settings: SeedSettings, db: DbSeed) -> None:
    """Insert the customers, tickets, notes, and keys the scenario declares."""
    with psycopg.connect(settings.dsn()) as conn:
        for customer in db.customers:
            conn.execute(
                "INSERT INTO customers (id, name, email, owner_login) VALUES (%s, %s, %s, %s)",
                (customer.id, customer.name, customer.email, customer.owner_login),
            )
        for ticket in db.tickets:
            conn.execute(
                "INSERT INTO tickets (id, customer_id, subject, body, author_email, status, "
                "incident_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    ticket.id,
                    ticket.customer_id,
                    ticket.subject,
                    ticket.body,
                    ticket.author_email,
                    ticket.status,
                    ticket.incident_id,
                ),
            )
        for note in db.notes:
            conn.execute(
                "INSERT INTO notes (ticket_id, author_login, body) VALUES (%s, %s, %s)",
                (note.ticket_id, note.author_login, note.body),
            )
        for key in db.api_keys:
            conn.execute(
                "INSERT INTO api_keys (customer_id, key_value, label, revoked) "
                "VALUES (%s, %s, %s, %s)",
                (key.customer_id, secrets.token_urlsafe(24), key.label, key.revoked),
            )
        advance_sequences(conn)


def seed_mail(mail_settings: MailSettings, scenario: Scenario) -> int:
    """Place every declared message in the inbox through Mailpit's send API.

    The SMTP port is not published to the host, so the seeder reaches the
    mailbox over HTTP. The `Message-ID` is set through the API's `Headers`
    field, which Mailpit records, so verify can find a message by a value the
    scenario file names rather than by the id Mailpit assigned.
    """
    url = f"{mail_settings.mail_url.rstrip('/')}/api/v1/send"
    count = 0
    for index, message in enumerate(scenario.seed.mail.inbox):
        message_id = message.message_id or f"{scenario.id}.{index}@{MESSAGE_ID_DOMAIN}"
        payload = {
            "From": {"Email": message.from_address},
            "To": [{"Email": message.to}],
            "Subject": message.subject,
            "Text": message.body,
            "Headers": {"Message-ID": f"<{message_id}>"},
        }
        try:
            response = httpx.post(url, json=payload, timeout=15.0)
        except httpx.HTTPError as error:
            raise SeedError(
                f"mailpit is unreachable at {mail_settings.mail_url}: {error}"
            ) from error
        require_ok(response, f"POST {url}")
        count += 1
    return count


def seed(
    scenario: Scenario,
    *,
    settings: SeedSettings | None = None,
    mail_settings: MailSettings | None = None,
    graph_db: Path | str = DEFAULT_GRAPH_DB,
) -> SeedReport:
    """Reset, then write the scenario's graph, org, database, and inbox."""
    settings = settings or SeedSettings()
    mail_settings = mail_settings or MailSettings()
    started = datetime.now(UTC)
    reset(
        scenario,
        settings=settings,
        mail_settings=mail_settings,
        graph_db=graph_db,
    )
    try:
        with gitea_client(settings) as client:
            repos = seed_gitea(client, settings, scenario.seed.gitea)
    except SeedError:
        raise
    except Exception as exc:
        raise SeedError(f"gitea seed failed: {exc}") from exc
    try:
        seed_postgres(settings, scenario.seed.db)
    except SeedError:
        raise
    except psycopg.Error as exc:
        raise SeedError(f"postgres seed failed: {exc}") from exc
    try:
        messages = seed_mail(mail_settings, scenario)
    except SeedError:
        raise
    except httpx.HTTPError as exc:
        raise SeedError(f"mailpit seed failed: {exc}") from exc
    elapsed = (datetime.now(UTC) - started).total_seconds()
    users = list(scenario.seed.gitea.members) + list(scenario.seed.gitea.externals)
    report = SeedReport(
        scenario_id=scenario.id,
        elapsed_s=elapsed,
        repos=repos,
        users=users,
        customers=len(scenario.seed.db.customers),
        tickets=len(scenario.seed.db.tickets),
        messages=messages,
        run_dir=scenario_run_dir(scenario.id),
    )
    write_seed_manifest(report)
    return report


def seed_all(
    scenarios: list[Scenario],
    *,
    settings: SeedSettings | None = None,
    mail_settings: MailSettings | None = None,
    graph_db: Path | str = DEFAULT_GRAPH_DB,
) -> list[SeedReport]:
    """Seed every scenario in order, one at a time, and report each."""
    return [
        seed(
            scenario,
            settings=settings,
            mail_settings=mail_settings,
            graph_db=graph_db,
        )
        for scenario in scenarios
    ]
