"""The access graph: who exists, what can act, and what can be touched.

Four tables in one SQLite file, `warrant.db` by default, reached through the
stdlib `sqlite3` module with a thin repository on top. There is no ORM because
there is no need for one: the engine reads single rows by id, and a loader
writes single rows from a YAML seed.

A resource is one of five kinds: a repository, a database table, a database
ticket row, a database customer row, or a mailbox. The ticket and customer kinds
are rows rather than containers, because the postgres MCP server names one by id
and the subject rule then reads that row's owner.

The seed is `infra/graph.yml` and `load()` is idempotent: it upserts on id, so
running `python -m warrant.graph load infra/graph.yml` twice leaves the same
graph, not two copies of it.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

DEFAULT_DB = Path("warrant.db")
DEFAULT_SEED = Path("infra/graph.yml")

SCHEMA = """
CREATE TABLE IF NOT EXISTS humans (
    id     TEXT PRIMARY KEY,
    login  TEXT NOT NULL,
    groups TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS agents (
    id                       TEXT PRIMARY KEY,
    client_id                TEXT NOT NULL,
    owner_human_id           TEXT REFERENCES humans(id),
    justification            TEXT NOT NULL DEFAULT '',
    justification_expires_at TEXT,
    allowed_tools            TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS tools (
    id            TEXT PRIMARY KEY,
    server        TEXT NOT NULL,
    name          TEXT NOT NULL,
    action_kind   TEXT NOT NULL CHECK (action_kind IN ('read', 'write', 'send')),
    resource_kind TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resources (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL CHECK (
        kind IN ('repo', 'db_table', 'db_ticket', 'db_customer', 'mailbox')
    ),
    name           TEXT NOT NULL,
    owner_human_id TEXT NOT NULL REFERENCES humans(id),
    sensitivity    TEXT NOT NULL CHECK (sensitivity IN ('public', 'internal', 'confidential'))
);
"""


@dataclass(frozen=True)
class Human:
    id: str
    login: str
    groups: list[str]


@dataclass(frozen=True)
class Agent:
    id: str
    client_id: str
    owner_human_id: str | None
    justification: str
    justification_expires_at: datetime | None
    allowed_tools: list[str]


@dataclass(frozen=True)
class Tool:
    id: str
    server: str
    name: str
    action_kind: str
    resource_kind: str


@dataclass(frozen=True)
class Resource:
    id: str
    kind: str
    name: str
    owner_human_id: str
    sensitivity: str


def _load_json_list(raw: str) -> list[str]:
    value = json.loads(raw)
    if not isinstance(value, list):
        raise ValueError(f"expected a JSON list, got {raw!r}")
    return [str(item) for item in value]


def _parse_time(raw: str | None) -> datetime | None:
    if raw is None or raw == "":
        return None
    value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value


def _require(data: Mapping[str, Any], key: str) -> Any:
    if key not in data:
        raise ValueError(f"graph entry is missing {key!r}: {dict(data)!r}")
    return data[key]


class Graph:
    """A thin repository over the SQLite access graph."""

    def __init__(self, path: Path | str = DEFAULT_DB) -> None:
        self.path = Path(path)
        # The ledger and the decision log create their parent directory, so this
        # sink does too rather than failing where the others succeed. An
        # in-memory database has no parent to make.
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Graph:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def clear(self) -> None:
        """Delete every row, children before parents.

        The scenario seeder reloads the whole graph from `infra/graph.yml` and
        then the scenario's own agents, so it needs the tables emptied first:
        an upsert leaves a row from the previous scenario behind, and a stale
        agent is authority a run must not inherit. The four names are literals
        in this file, so the loop cannot carry a caller's text into SQL.
        """
        for table in ("resources", "agents", "tools", "humans"):
            self._conn.execute(f"DELETE FROM {table}")
        self._conn.commit()

    def seed(self, data: Mapping[str, Any]) -> dict[str, int]:
        """Upsert a whole graph from a parsed seed mapping.

        Rows are written in dependency order (humans, then agents and
        resources) so the foreign keys hold.
        """
        humans = list(data.get("humans", []))
        agents = list(data.get("agents", []))
        tools = list(data.get("tools", []))
        resources = list(data.get("resources", []))

        for row in humans:
            self._conn.execute(
                """
                INSERT INTO humans (id, login, groups) VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    login = excluded.login,
                    groups = excluded.groups
                """,
                (
                    _require(row, "id"),
                    _require(row, "login"),
                    json.dumps(list(row.get("groups", []))),
                ),
            )
        for row in agents:
            self._conn.execute(
                """
                INSERT INTO agents (
                    id, client_id, owner_human_id, justification,
                    justification_expires_at, allowed_tools
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    client_id = excluded.client_id,
                    owner_human_id = excluded.owner_human_id,
                    justification = excluded.justification,
                    justification_expires_at = excluded.justification_expires_at,
                    allowed_tools = excluded.allowed_tools
                """,
                (
                    _require(row, "id"),
                    _require(row, "client_id"),
                    row.get("owner_human_id"),
                    row.get("justification", ""),
                    row.get("justification_expires_at"),
                    json.dumps(list(row.get("allowed_tools", []))),
                ),
            )
        for row in tools:
            self._conn.execute(
                """
                INSERT INTO tools (id, server, name, action_kind, resource_kind)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    server = excluded.server,
                    name = excluded.name,
                    action_kind = excluded.action_kind,
                    resource_kind = excluded.resource_kind
                """,
                (
                    _require(row, "id"),
                    _require(row, "server"),
                    _require(row, "name"),
                    _require(row, "action_kind"),
                    _require(row, "resource_kind"),
                ),
            )
        for row in resources:
            self._conn.execute(
                """
                INSERT INTO resources (id, kind, name, owner_human_id, sensitivity)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    kind = excluded.kind,
                    name = excluded.name,
                    owner_human_id = excluded.owner_human_id,
                    sensitivity = excluded.sensitivity
                """,
                (
                    _require(row, "id"),
                    _require(row, "kind"),
                    _require(row, "name"),
                    _require(row, "owner_human_id"),
                    _require(row, "sensitivity"),
                ),
            )
        self._conn.commit()
        return {
            "humans": len(humans),
            "agents": len(agents),
            "tools": len(tools),
            "resources": len(resources),
        }

    def resource_named(self, name: str, kind: str | None = None) -> Resource | None:
        """The resource row whose `name` is `name`, optionally of `kind`.

        A tool call carries a name (`acme/widgets`, `public.orders`,
        `support@acme.test`) while the engine and the policies key on the
        graph's id. This is that lookup. With two rows sharing a name and no
        kind to tell them apart, the lowest id wins rather than an arbitrary
        one, so the same call resolves the same way on every run.

        A caller that cannot accept a tie wants `resources_named` and a count
        instead: this one answer says nothing about how many rows matched.
        """
        if kind is None:
            row = self._row("SELECT id FROM resources WHERE name = ? ORDER BY id LIMIT 1", name)
        else:
            row = self._row(
                "SELECT id FROM resources WHERE name = ? AND kind = ? ORDER BY id LIMIT 1",
                name,
                kind,
            )
        if row is None:
            return None
        return self.resource(row["id"])

    def resources_named(self, name: str, kind: str | None = None) -> list[Resource]:
        """Every resource row whose `name` is `name`, optionally of `kind`.

        The plural of `resource_named`, ordered by id. A caller that has to know
        whether a name identifies one row or several, rather than being handed
        the lowest id, uses this: `search_customers` takes free text, and a
        query matching no row or more than one is not a subject to decide
        against.
        """
        if kind is None:
            rows = self._rows("SELECT id FROM resources WHERE name = ? ORDER BY id", name)
        else:
            rows = self._rows(
                "SELECT id FROM resources WHERE name = ? AND kind = ? ORDER BY id",
                name,
                kind,
            )
        return [resource for row in rows if (resource := self.resource(row["id"])) is not None]

    def human(self, entity_id: str) -> Human | None:
        row = self._row("SELECT * FROM humans WHERE id = ?", entity_id)
        if row is None:
            return None
        return Human(id=row["id"], login=row["login"], groups=_load_json_list(row["groups"]))

    def agent(self, entity_id: str) -> Agent | None:
        row = self._row("SELECT * FROM agents WHERE id = ?", entity_id)
        if row is None:
            return None
        return Agent(
            id=row["id"],
            client_id=row["client_id"],
            owner_human_id=row["owner_human_id"],
            justification=row["justification"],
            justification_expires_at=_parse_time(row["justification_expires_at"]),
            allowed_tools=_load_json_list(row["allowed_tools"]),
        )

    def tool(self, entity_id: str) -> Tool | None:
        row = self._row("SELECT * FROM tools WHERE id = ?", entity_id)
        if row is None:
            return None
        return Tool(
            id=row["id"],
            server=row["server"],
            name=row["name"],
            action_kind=row["action_kind"],
            resource_kind=row["resource_kind"],
        )

    def resource(self, entity_id: str) -> Resource | None:
        row = self._row("SELECT * FROM resources WHERE id = ?", entity_id)
        if row is None:
            return None
        return Resource(
            id=row["id"],
            kind=row["kind"],
            name=row["name"],
            owner_human_id=row["owner_human_id"],
            sensitivity=row["sensitivity"],
        )

    def humans(self) -> list[Human]:
        rows = self._rows("SELECT id FROM humans ORDER BY id")
        return [human for row in rows if (human := self.human(row["id"])) is not None]

    def agents(self) -> list[Agent]:
        rows = self._rows("SELECT id FROM agents ORDER BY id")
        return [agent for row in rows if (agent := self.agent(row["id"])) is not None]

    def tools(self) -> list[Tool]:
        rows = self._rows("SELECT id FROM tools ORDER BY id")
        return [tool for row in rows if (tool := self.tool(row["id"])) is not None]

    def resources(self) -> list[Resource]:
        rows = self._rows("SELECT id FROM resources ORDER BY id")
        return [resource for row in rows if (resource := self.resource(row["id"])) is not None]

    def _row(self, query: str, *params: object) -> sqlite3.Row | None:
        return self._conn.execute(query, params).fetchone()

    def _rows(self, query: str, *params: object) -> Iterable[sqlite3.Row]:
        return self._conn.execute(query, params).fetchall()


def load(seed_path: Path | str = DEFAULT_SEED, db: Path | str = DEFAULT_DB) -> Graph:
    """Create or open `db` and upsert the seed at `seed_path` into it."""
    data = yaml.safe_load(Path(seed_path).read_text())
    if not isinstance(data, Mapping):
        raise ValueError(f"{seed_path} did not parse to a mapping")
    graph = Graph(db)
    graph.seed(data)
    return graph


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warrant.graph", description="The Warrant access graph.")
    sub = parser.add_subparsers(dest="command", required=True)
    load_parser = sub.add_parser("load", help="seed the graph from a YAML file")
    load_parser.add_argument("path", nargs="?", default=str(DEFAULT_SEED))
    load_parser.add_argument("--db", default=str(DEFAULT_DB))
    args = parser.parse_args(argv)

    if args.command == "load":
        with load(args.path, args.db) as graph:
            counts = {
                "humans": len(graph.humans()),
                "agents": len(graph.agents()),
                "tools": len(graph.tools()),
                "resources": len(graph.resources()),
            }
        summary = ", ".join(f"{name}={count}" for name, count in counts.items())
        print(f"loaded {args.path} into {args.db}: {summary}")
        return 0
    parser.error(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
