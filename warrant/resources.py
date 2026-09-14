"""Turn a tool call's arguments into the resource the access graph knows.

Cedar decides on `Resource::"<id>"`, and the graph is keyed by id, but a tool
call carries a name: a repository as `owner/name`, a table as `public.orders`,
a mailbox as an address. This module is the one place that maps the second to
the first. The extractor is chosen by the resource kind the graph records for
the tool, so a tool the graph has classified as touching a repo is read for its
`repo` argument and nothing else.

The extractor reads the arguments only. It never invents a resource and never
falls back to the task or the actor, so a call that names nothing resolvable
becomes an unknown resource and the engine's sentinel owner applies.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from warrant.graph import Graph

REPO = "repo"
DB_TABLE = "db_table"
MAILBOX = "mailbox"

# The table a statement reads or writes. `FROM public.orders`, `JOIN
# public.orders o`, and the quoted spellings a migration might use. The first
# match is the resource, which is the table a simple statement touches; a
# statement touching several tables is a W7 policy question, not this one's.
_TABLE = re.compile(
    r"\b(?:from|join|update|into)\s+[\"']?([A-Za-z_][\w.]*)[\"']?",
    re.IGNORECASE,
)


def _first(value: Any) -> str | None:
    """A string argument, or the first element of a recipient list."""
    if isinstance(value, str):
        return value or None
    if isinstance(value, (list, tuple)):
        return next((item for item in value if isinstance(item, str) and item), None)
    return None


def extract_resource(resource_kind: str, args: Mapping[str, Any]) -> str | None:
    """The resource name a tool call names, or None when it names none.

    The kind comes from the graph's tool row, so this is not the caller's word
    about what it is touching.
    """
    if resource_kind == REPO:
        return _first(args.get("repo"))
    if resource_kind == DB_TABLE:
        explicit = _first(args.get("table"))
        if explicit is not None:
            return explicit
        statement = _first(args.get("sql"))
        if statement is None:
            return None
        match = _TABLE.search(statement)
        return match.group(1) if match else None
    if resource_kind == MAILBOX:
        return _first(args.get("to"))
    return None


def resolve_resource(graph: Graph | None, resource_kind: str, name: str | None) -> str:
    """The graph's id for a resource name, or the name itself when unknown.

    A name the graph does not know is passed through as the resource id so the
    engine presents it with `kind` and `sensitivity` `unknown` and a sentinel
    owner. That is the deny-safe direction: an unlisted resource cannot match a
    permit that keys on ownership or classification.
    """
    if name is None:
        return ""
    if graph is None:
        return name
    row = graph.resource_named(name, resource_kind)
    return row.id if row is not None else name
