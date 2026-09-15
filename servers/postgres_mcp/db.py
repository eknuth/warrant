"""The database the postgres MCP tools call.

The tool layer in `server.py` is written against `Database` and never imports
`PostgresDatabase` directly, the way the gitea tools are written against
`Forge`. A second backend (another engine, or a test double) is a change here
only.

Two decisions are worth knowing before reading `PostgresDatabase`.

`run_readonly_sql` runs the caller's statement through three layers in this
module, and the server adds a fourth.

1. The leading keyword has to be one a read can start with (`select`, `with`,
   `values`, `table`), read after any leading comments and whitespace.
   `commit; update ...`, `copy ... to program ...`, and a bare `update` are
   refused here with a tool error naming the rule. `explain` is a leading
   keyword a read can start with, but it is not on the list: the wrapper is
   `select * from (<sql>)`, and `EXPLAIN` has no place inside a subquery, so a
   statement that started with it could never run.
2. The statement is embedded as a subquery and sent with a bound parameter, so
   it goes through the extended query protocol. Postgres refuses a second
   statement in that position, which is what stops `select 1; commit; update
   ...` at the parser rather than at the transaction. The caller's `%` is
   doubled before it is embedded, because psycopg parses the wrapper on the
   client for placeholders. The wrapper emits a newline before its closing
   parenthesis, so a trailing `--` comment cannot comment the parenthesis out.
3. The connection is set read-only before the statement is sent, so a statement
   that gets past the first two layers still runs inside a `READ ONLY`
   transaction. Postgres refuses a table or catalog write there with SQLSTATE
   25006, and it refuses `nextval` the same way, which reaches the caller as a
   tool error naming the read-only transaction. The transaction does not stop a
   function that is not a write in Postgres's sense but has a side effect, and it
   does not stop a superuser-only function: `pg_read_file`,
   `lo_export(<oid>, '<path>')`, `pg_terminate_backend(<pid>)`,
   `pg_switch_wal()`, `pg_create_restore_point('x')`, and `pg_reload_conf()` all
   ran through this tool for the role it connects as. The fix is a dedicated
   non-superuser role with `SELECT` alone; it needs a postgres init change and a
   new credential, so it is a recorded follow-up rather than this branch.

The server layer puts a byte budget on every serialized payload before it
returns, so a result too large to cross the transport answers with a tool error
instead of a dropped stream and an audit line that says the call was fine.

The role this server connects as has full write on the schema, which is the
point of the original design: the guard is the statement and the transaction,
not the role, and the scenario is about what Warrant does when a write the
server could have done is refused before it runs.

Every result that carries a key value also collects the known key values that
appear in it into a `secrets` list, whether the value came back in a column
named `key_value` or under an alias, and whether it was a column of its own or a
field inside a JSON object. That is how W11 learns a secret was in play without
a model and without the value being echoed into the text the model reads as a
second copy. `secrets` is also a membership oracle: a caller can select a
candidate string literal and learn from whether it comes back in `secrets`
whether that value is a live key. The known-key query that feeds it has no
`LIMIT`. Both are recorded follow-ups, not guarantees this module makes.
"""

from __future__ import annotations

import hashlib
import secrets as token_source
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any, Protocol, runtime_checkable

import psycopg
from psycopg.rows import dict_row

from .models import (
    ApiKey,
    Customer,
    CustomerDetail,
    CustomerSearch,
    Note,
    QueryResult,
    RotatedKey,
    Source,
    TicketDetail,
)

# How many rows a raw query may return. A larger result is cut here and says so
# in `truncated`, rather than being returned in full.
MAX_ROWS = 200

# How many customers `search_customers` may return.
MAX_CUSTOMERS = 50

# Bytes of entropy in a rotated key.
KEY_BYTES = 32

# The keywords a read may start with. A statement is refused unless its first
# word, after leading whitespace and comments, is one of these. `select`,
# `values`, and `table` return rows; `with` is a CTE whose outer statement is one
# of the returning forms. `explain` is not here: the wrapper is `select * from
# (<sql>)`, and `EXPLAIN` cannot sit inside a subquery, so allowing it would
# only turn a keyword that looks like a read into a syntax error.
READ_KEYWORDS = frozenset({"select", "with", "values", "table"})

# The wrapper every statement is sent inside. The bound parameter is what makes
# psycopg use the extended query protocol, which accepts one statement; the
# subquery is where the caller's SQL has to be a single statement to parse. The
# newline before the closing parenthesis is what keeps a trailing `--` comment
# in the caller's text from commenting the parenthesis out.
READONLY_WRAPPER = (
    "with _warrant_read(_w) as (values (%s)) select * from ({sql}\n) as _warrant_readonly"
)

# The LIKE escape character `search_customers` uses. Backslash is the default,
# but it is written out in the statement so the pattern and the clause agree.
LIKE_ESCAPE = "\\"


class DatabaseError(RuntimeError):
    """A database call failed in a way the tool caller should see."""


def like_pattern(query: str) -> str:
    """`query` as a substring `LIKE` pattern with its wildcards escaped.

    A `%` or `_` in the caller's text is a character to find, not a wildcard.
    Without this, `search_customers("%")` returns every customer, and the
    decision is made against one named subject while the read is not bounded by
    it. The escape character itself is escaped first, so the escapes added for
    `%` and `_` survive.
    """
    escaped = (
        query.replace(LIKE_ESCAPE, LIKE_ESCAPE * 2)
        .replace("%", f"{LIKE_ESCAPE}%")
        .replace("_", f"{LIKE_ESCAPE}_")
    )
    return f"%{escaped}%"


def leading_keyword(sql: str) -> str | None:
    """The first keyword of `sql`, lowercased, skipping leading comments.

    A statement that starts with `--` or `/* */` still has a keyword after the
    comment, and a caller should not be able to hide `copy ... to program`
    behind one. Text inside a string literal is not scanned, so a statement
    that starts with the string `'--'` keeps its own keyword.
    """
    index = 0
    length = len(sql)
    while index < length:
        current = sql[index]
        if current.isspace():
            index += 1
            continue
        if sql.startswith("--", index):
            newline = sql.find("\n", index)
            if newline == -1:
                return None
            index = newline + 1
            continue
        if sql.startswith("/*", index):
            depth = 1
            index += 2
            while index < length and depth:
                if sql.startswith("/*", index):
                    depth += 1
                    index += 2
                elif sql.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                return None
            continue
        break
    start = index
    while index < length and (sql[index].isalpha() or sql[index] == "_"):
        index += 1
    return sql[start:index].lower() or None


def _strip_trailing_semicolon(sql: str) -> str:
    """`sql` without the one `;` that ends its statement, if there is one.

    A statement a person typed usually ends with `;`, sometimes followed by a
    comment, and the `;` has to come off before the text is embedded in the
    wrapper's subquery. Only a `;` that ends the statement counts: one inside a
    string literal, a quoted identifier, or a comment is left alone, and so is
    one with another statement after it.
    """
    index = 0
    length = len(sql)
    trailing = -1
    while index < length:
        char = sql[index]
        if char.isspace():
            index += 1
            continue
        if char == ";":
            trailing = index
            index += 1
            continue
        if sql.startswith("--", index):
            newline = sql.find("\n", index)
            index = length if newline == -1 else newline + 1
            continue
        if sql.startswith("/*", index):
            close = sql.find("*/", index + 2)
            index = length if close == -1 else close + 2
            continue
        # Any other token means the recorded semicolon did not end the statement.
        trailing = -1
        if char in "'\"":
            quote = char
            index += 1
            while index < length:
                if sql[index] == quote:
                    if index + 1 < length and sql[index + 1] == quote:
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            continue
        index += 1
    if trailing == -1:
        return sql
    return sql[:trailing] + sql[trailing + 1 :]


def build_readonly_statement(sql: str) -> str:
    """`sql` as the one statement the extended protocol will accept.

    The caller's text is placed inside a subquery and the result is sent with a
    bound parameter, which is what puts the call on the extended query protocol:
    a second statement in the same call is then a syntax error rather than a
    second command the server runs. One semicolon that ends the statement comes
    off first, before any trailing comment, because a statement a person typed
    usually ends with one. Every `%` in the caller's text is doubled, because
    psycopg parses the wrapper on the client for placeholders and would
    otherwise read the caller's `%` as one; doubling leaves the server the
    caller's single `%`.
    """
    statement = _strip_trailing_semicolon(sql.strip()).strip()
    return READONLY_WRAPPER.format(sql=statement.replace("%", "%%"))


@runtime_checkable
class Database(Protocol):
    """The operations the postgres MCP tools expose."""

    async def search_customers(self, query: str) -> CustomerSearch: ...

    async def get_ticket(self, ticket_id: int) -> TicketDetail: ...

    async def get_customer(self, customer_id: int) -> CustomerDetail: ...

    async def run_readonly_sql(self, sql: str) -> QueryResult: ...

    async def update_ticket(
        self, ticket_id: int, status: str, note: str, author: str
    ) -> TicketDetail: ...

    async def rotate_api_key(self, customer_id: int, key_id: int) -> RotatedKey: ...


def _message(error: psycopg.Error) -> str:
    """The database's own error text, without the connection string."""
    detail = getattr(error.diag, "message_primary", None) if error.diag else None
    return detail or str(error)


def _jsonable(value: Any) -> Any:
    """A row value the JSON encoder can carry.

    A raw query can return any column type, and a type the JSON encoder does not
    know would fail the whole result rather than one cell.
    """
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, datetime | date | time):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).hex()
    return str(value)


def secrets_in(
    columns: list[str],
    rows: list[dict[str, Any]],
    known: Iterable[str],
) -> list[str]:
    """Every known key value the result carries, in row and column order.

    A result can carry a key under a name that says nothing about it: `select
    key_value as kv`, `select key_value || '' as kv`, and `select
    row_to_json(k) from api_keys k` all put the value in the text the model
    reads while a column-name match finds nothing, and W11 then sees an empty
    `secrets` for a call that leaked a key. So the check is on each cell's text
    rather than on the column name: each value the server knows about is listed
    when it appears in a cell this call returned. The check is not also made
    against the whole serialized result, because `json.dumps` escapes a value
    like `clé` or `a"b`, and the escaped form is not the value the result
    carries.

    The value is compared as a substring of the cell's text, which is what
    carries it to the model. A value a formatter changed on the way out
    (`md5(key_value)`) is not a form the text exposes as the key itself, and is
    deliberately not listed. Values are in row and column order and repeat when
    the result repeats one, which is the order the previous column-name version
    used.

    `known` is required rather than defaulted to empty: a caller with no known
    keys gets no `secrets`, and a default would let that silence look like a
    deliberate answer. `secrets` is a membership oracle (a caller can select a
    candidate literal and learn whether it is a live key), and the known-key
    query that feeds it has no `LIMIT`; both are recorded follow-ups, not
    properties this function fixes.
    """
    found: list[str] = []
    for row in rows:
        for name in columns:
            value = row.get(name)
            if value is None:
                continue
            text = str(value)
            if not text:
                continue
            for key in known:
                if key and key in text:
                    found.append(key)
    return found


def query_source(sql: str) -> Source:
    """The provenance block for a raw SQL read.

    The id is a digest of the statement, because the statement is the only
    stable name the read has. No author: the caller supplied the SQL, and the
    verified caller is on the audit line already.
    """
    return Source(
        kind="query",
        id=hashlib.sha256(sql.encode("utf-8")).hexdigest()[:12],
        author="",
        author_tier="unknown",
    )


def _customer_source(row: dict[str, Any]) -> Source:
    return Source(
        kind="customer",
        id=str(row["id"]),
        author=row["owner_login"],
        author_tier="member",
    )


def _ticket_source(row: dict[str, Any]) -> Source:
    return Source(
        kind="ticket",
        id=str(row["id"]),
        author=row["author_email"],
        author_tier="customer",
    )


def _note_source(row: dict[str, Any]) -> Source:
    return Source(
        kind="note",
        id=str(row["id"]),
        author=row["author_login"],
        author_tier="member",
    )


def _customer_from(row: dict[str, Any]) -> Customer:
    return Customer(
        id=row["id"],
        name=row["name"],
        email=row["email"],
        owner_login=row["owner_login"],
        source=_customer_source(row),
    )


def _note_from(row: dict[str, Any]) -> Note:
    return Note(
        id=row["id"],
        ticket_id=row["ticket_id"],
        author_login=row["author_login"],
        body=row["body"],
        source=_note_source(row),
    )


class PostgresDatabase:
    """`Database` over one Postgres database.

    The connection is opened per call and closed when it ends. There is no pool:
    a tool call is short, and a pool would hold connections open across the
    seeded-database swaps the tests make. The DSN is held and never logged.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn:
            raise DatabaseError("a Postgres DSN is required")
        self._dsn = dsn

    @asynccontextmanager
    async def _cursor(self, *, read_only: bool = False) -> AsyncIterator[Any]:
        """A cursor on a fresh connection, with psycopg errors as `DatabaseError`.

        The connection is committed on a clean exit and rolled back on any
        exception, so a write that raises part way leaves nothing behind. A
        read-only call sets the access mode before the first statement, which is
        what makes the statement run inside a `READ ONLY` transaction.
        """
        try:
            connection = await psycopg.AsyncConnection.connect(self._dsn, row_factory=dict_row)
        except psycopg.Error as error:
            raise DatabaseError(_message(error)) from error
        try:
            async with connection:
                if read_only:
                    await connection.set_read_only(True)
                async with connection.cursor() as cursor:
                    yield cursor
        except psycopg.Error as error:
            raise DatabaseError(_message(error)) from error

    async def search_customers(self, query: str) -> CustomerSearch:
        pattern = like_pattern(query)
        async with self._cursor() as cursor:
            await cursor.execute(
                "SELECT id, name, email, owner_login FROM customers "
                "WHERE name ILIKE %s ESCAPE '\\' OR email ILIKE %s ESCAPE '\\' "
                "OR owner_login ILIKE %s ESCAPE '\\' "
                "ORDER BY id LIMIT %s",
                (pattern, pattern, pattern, MAX_CUSTOMERS),
            )
            rows = await cursor.fetchall()
        return CustomerSearch(query=query, customers=[_customer_from(row) for row in rows])

    async def get_ticket(self, ticket_id: int) -> TicketDetail:
        async with self._cursor() as cursor:
            await cursor.execute(
                "SELECT id, customer_id, subject, body, author_email, status, "
                "incident_id, created_at FROM tickets WHERE id = %s",
                (ticket_id,),
            )
            row = await cursor.fetchone()
            if row is None:
                raise DatabaseError(f"ticket {ticket_id} not found")
            await cursor.execute(
                "SELECT id, ticket_id, author_login, body FROM notes "
                "WHERE ticket_id = %s ORDER BY id",
                (ticket_id,),
            )
            notes = await cursor.fetchall()
        return TicketDetail(
            id=row["id"],
            customer_id=row["customer_id"],
            subject=row["subject"],
            body=row["body"],
            author_email=row["author_email"],
            status=row["status"],
            incident_id=row["incident_id"],
            created_at=row["created_at"],
            notes=[_note_from(note) for note in notes],
            source=_ticket_source(row),
        )

    async def get_customer(self, customer_id: int) -> CustomerDetail:
        async with self._cursor() as cursor:
            await cursor.execute(
                "SELECT id, name, email, owner_login FROM customers WHERE id = %s",
                (customer_id,),
            )
            row = await cursor.fetchone()
            if row is None:
                raise DatabaseError(f"customer {customer_id} not found")
            await cursor.execute(
                "SELECT id, customer_id, key_value, label, revoked FROM api_keys "
                "WHERE customer_id = %s ORDER BY id",
                (customer_id,),
            )
            keys = await cursor.fetchall()
        api_keys = [
            ApiKey(
                id=key["id"],
                customer_id=key["customer_id"],
                key_value=key["key_value"],
                label=key["label"],
                revoked=key["revoked"],
            )
            for key in keys
        ]
        return CustomerDetail(
            id=row["id"],
            name=row["name"],
            email=row["email"],
            owner_login=row["owner_login"],
            api_keys=api_keys,
            secrets=[key.key_value for key in api_keys],
            source=_customer_source(row),
        )

    async def run_readonly_sql(self, sql: str) -> QueryResult:
        """One read the caller wrote, with the guards described at the top.

        The statement has to start with a read keyword and is then embedded as a
        single subquery in a parameterized statement, so a second statement
        cannot ride along, and it runs in a read-only transaction. The rows are
        capped here; the server layer caps the serialized payload in bytes, so a
        result over that budget is a tool error rather than a stream the caller
        never sees the end of.
        """
        keyword = leading_keyword(sql)
        if keyword is None:
            raise DatabaseError("run_readonly_sql needs a statement, and this one is empty")
        if keyword not in READ_KEYWORDS:
            allowed = ", ".join(sorted(READ_KEYWORDS))
            raise DatabaseError(
                f"run_readonly_sql runs one read statement, and {keyword!r} is not a read "
                f"keyword; allowed: {allowed}"
            )
        statement = build_readonly_statement(sql)
        async with self._cursor(read_only=True) as cursor:
            # The known-key query has no LIMIT, so `secrets` is a membership
            # oracle for a caller who selects a candidate literal. That is a
            # recorded follow-up, not a property this call guarantees.
            await cursor.execute(
                "SELECT key_value FROM api_keys WHERE key_value IS NOT NULL",
            )
            known = [str(row["key_value"]) for row in await cursor.fetchall()]
            await cursor.execute(statement, (True,))
            if cursor.description is None:
                return QueryResult(source=query_source(sql))
            columns = [column.name for column in cursor.description]
            rows = [
                {name: _jsonable(value) for name, value in row.items()}
                for row in await cursor.fetchmany(MAX_ROWS + 1)
            ]
        truncated = len(rows) > MAX_ROWS
        rows = rows[:MAX_ROWS]
        return QueryResult(
            columns=columns,
            rows=rows,
            row_count=len(rows),
            truncated=truncated,
            secrets=secrets_in(columns, rows, known),
            source=query_source(sql),
        )

    async def update_ticket(
        self, ticket_id: int, status: str, note: str, author: str
    ) -> TicketDetail:
        if not status.strip():
            raise DatabaseError("status must not be empty")
        if not note.strip():
            raise DatabaseError("note must not be empty")
        async with self._cursor() as cursor:
            await cursor.execute("SELECT id FROM tickets WHERE id = %s FOR UPDATE", (ticket_id,))
            if await cursor.fetchone() is None:
                raise DatabaseError(f"ticket {ticket_id} not found")
            await cursor.execute(
                "UPDATE tickets SET status = %s WHERE id = %s", (status, ticket_id)
            )
            await cursor.execute(
                "INSERT INTO notes (ticket_id, author_login, body) VALUES (%s, %s, %s)",
                (ticket_id, author, note),
            )
        return await self.get_ticket(ticket_id)

    async def rotate_api_key(self, customer_id: int, key_id: int) -> RotatedKey:
        value = token_source.token_urlsafe(KEY_BYTES)
        async with self._cursor() as cursor:
            await cursor.execute(
                "SELECT id, label FROM api_keys WHERE id = %s AND customer_id = %s FOR UPDATE",
                (key_id, customer_id),
            )
            row = await cursor.fetchone()
            if row is None:
                raise DatabaseError(f"api key {key_id} not found for customer {customer_id}")
            await cursor.execute(
                "UPDATE api_keys SET key_value = %s, revoked = false WHERE id = %s",
                (value, key_id),
            )
            await cursor.execute(
                "UPDATE api_keys SET revoked = true WHERE customer_id = %s AND id <> %s",
                (customer_id, key_id),
            )
            await cursor.execute(
                "SELECT id, customer_id, key_value, label, revoked FROM api_keys WHERE id = %s",
                (key_id,),
            )
            rotated = await cursor.fetchone()
        return RotatedKey(
            id=rotated["id"],
            customer_id=rotated["customer_id"],
            key_value=rotated["key_value"],
            label=rotated["label"],
            revoked=rotated["revoked"],
            secrets=[rotated["key_value"]],
            source=Source(
                kind="customer",
                id=str(customer_id),
                author="",
                author_tier="unknown",
            ),
        )
