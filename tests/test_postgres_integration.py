"""Postgres-backed tests against the running compose stack.

Every test here is marked `integration` and skips when the stack is absent, so
`make test` is green on a clean checkout. When the compose `postgres` service is
up, these exercise the real database and the real MCP server end to end.

Each test that needs rows makes its own throwaway database, loads
`infra/postgres/schema.sql` into it, and seeds a handful of rows. W12 owns the
scenario rows; nothing here writes to the `support` database. The connection is
the one `.env` describes, so the tests read the same role the server does.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from agents.auth import audience_list, decode_claims
from servers.postgres_mcp.server import MAX_RESULT_BYTES, build_app
from servers.postgres_mcp.server import ServerSettings as PostgresSettings

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[1]
SCHEMA = REPO / "infra" / "postgres" / "schema.sql"

# Fixture values, not credentials. They are long enough to be recognisable in a
# result and short enough that no key pattern mistakes them for a real one. The
# names avoid `KEY`, because the secrets hook reads a `*KEY=` assignment with a
# value that is not a placeholder as a finding, and these are not credentials.
FIXTURE_VALUE = "fixture-key-alpha"
FIXTURE_RETIRED_VALUE = "fixture-key-beta"

INITIALIZE_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "w8-integration-test", "version": "0"},
    },
}
MCP_ACCEPT = {"Accept": "application/json, text/event-stream"}


@dataclass
class Scratch:
    """A throwaway database with one ticket, its note, and two key rows."""

    name: str
    customer_id: int
    ticket_id: int
    key_id: int


@pytest.fixture(scope="session")
def pg_settings() -> PostgresSettings:
    return PostgresSettings()


@pytest.fixture(scope="session")
def pg_server(pg_settings: PostgresSettings) -> PostgresSettings:
    """Skip unless the compose postgres answers for the configured role.

    Only an absent stack skips. A server that answers and refuses the role is a
    failure, not a skip, for the same reason the Gitea fixture fails: a wrong
    password would otherwise delete every integration test silently while
    `make test` stayed green.
    """
    if not pg_settings.postgres_password:
        pytest.skip("POSTGRES_PASSWORD is not set; add it to .env")
    try:
        with psycopg.connect(pg_settings.dsn("postgres"), connect_timeout=3) as conn:
            conn.execute("select 1")
    except psycopg.OperationalError as error:
        pytest.skip(
            f"no postgres at {pg_settings.postgres_host}:{pg_settings.postgres_port}: {error}"
        )
    return pg_settings


@pytest.fixture
def scratch(pg_server: PostgresSettings) -> Iterator[Scratch]:
    name = f"w8_test_{uuid.uuid4().hex[:10]}"
    admin = psycopg.connect(pg_server.dsn("postgres"), autocommit=True)
    admin.execute(f'create database "{name}"')
    try:
        with psycopg.connect(pg_server.dsn(name)) as conn:
            conn.execute(SCHEMA.read_text(encoding="utf-8"))
            conn.execute(
                "insert into customers (id, name, email, owner_login) "
                "values (1, 'Acme', 'ops@acme.example', 'bob')"
            )
            conn.execute(
                "insert into customers (id, name, email, owner_login) "
                "values (2, 'Globex', 'ops@globex.example', 'carol')"
            )
            conn.execute(
                "insert into tickets (id, customer_id, subject, body, author_email, status) "
                "values (10, 1, 'Site is down', 'The site is down', "
                "'user@acme.example', 'open')"
            )
            conn.execute(
                "insert into notes (id, ticket_id, author_login, body) "
                "values (100, 10, 'bob', 'Looking into it')"
            )
            conn.execute(
                "insert into api_keys (id, customer_id, key_value, label, revoked) "
                "values (1000, 1, %s, 'prod', false)",
                (FIXTURE_VALUE,),
            )
            conn.execute(
                "insert into api_keys (id, customer_id, key_value, label, revoked) "
                "values (1001, 1, %s, 'old', true)",
                (FIXTURE_RETIRED_VALUE,),
            )
            conn.commit()
        yield Scratch(name=name, customer_id=1, ticket_id=10, key_id=1000)
    finally:
        admin.execute(f'drop database "{name}" with (force)')
        admin.close()


@contextmanager
def serve(app: Any) -> Iterator[str]:
    """Run the ASGI app on an ephemeral port in a thread and yield its base URL.

    uvicorn's `capture_signals` is a no-op off the main thread, so this is the
    supported way to run it here. Port 0 avoids colliding with a server someone
    left running on 9102.
    """
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20.0
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("the test MCP server did not start")
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10.0)


@pytest.fixture
def pg_app(
    scratch: Scratch,
    rsa_keypair: tuple[str, str],
    test_issuer: str,
) -> Iterator[str]:
    """The server pointed at the scratch database, verifying this suite's tokens."""
    settings = PostgresSettings(postgres_db=scratch.name)
    app = build_app(settings=settings, issuer=test_issuer, key=rsa_keypair[1])
    with serve(app) as url:
        yield f"{url}/mcp"


@pytest.fixture
def real_pg_app(scratch: Scratch) -> Iterator[str]:
    """The same server, verifying the running Keycloak's tokens."""
    settings = PostgresSettings(postgres_db=scratch.name)
    app = build_app(settings=settings)
    with serve(app) as url:
        yield f"{url}/mcp"


@pytest.fixture(scope="session")
def mint_support_obo() -> Any:
    """Mint a real support-actored on-behalf-of token for the postgres-mcp audience.

    alice's console token names both `triage-agent` and `support-agent` in its
    `aud`, so support-agent can exchange it directly for a `postgres-mcp` token.
    The result is issued by the real realm, has the real signature, names the
    postgres-mcp audience, and records `act.sub` and `azp` as support-agent.
    """
    try:
        from agents.auth import (
            AuthError,
            DevSettings,
            exchange_for_obo,
            login_as_alice,
        )
    except Exception as error:  # noqa: BLE001 - a missing .env value is a skip, not a failure
        pytest.skip(f"dev token settings are unavailable: {error}")

    dev = DevSettings()

    def mint(task_id: str = "task-w8-real") -> str:
        try:
            with httpx.Client(timeout=20.0) as client:
                subject_token = login_as_alice(dev, client)
                token = exchange_for_obo(
                    dev, client, subject_token, "postgres-mcp", task_id, client_id="support-agent"
                )
        except httpx.HTTPError as error:
            pytest.skip(f"no Keycloak at {dev.keycloak_url}: {error}")
        except AuthError as error:
            pytest.fail(f"Keycloak refused the support-agent exchange: {error}")
        return token

    return mint


@asynccontextmanager
async def mcp_session(url: str, token: str) -> AsyncIterator[ClientSession]:
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"}, timeout=30.0
    ) as client:
        async with streamable_http_client(url, http_client=client) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


def structured(result: Any) -> dict[str, Any]:
    """A tool result's structured payload, whichever shape the SDK used."""
    payload = result.structured_content
    if payload is None:
        return json.loads(result.content[0].text)
    if set(payload) == {"result"} and isinstance(payload["result"], dict):
        return payload["result"]
    return payload


def text_of(result: Any) -> str:
    """The text blocks of a tool result, which is what the model reads."""
    return "".join(
        block.text
        for block in (result.content or [])
        if getattr(block, "type", None) == "text" and getattr(block, "text", None)
    )


async def raw_call(url: str, token: str | None) -> httpx.Response:
    headers = dict(MCP_ACCEPT)
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(timeout=20.0) as client:
        return await client.post(url, json=INITIALIZE_REQUEST, headers=headers)


# -- the schema the clean volume loaded ------------------------------------


def test_the_support_database_loaded_the_schema(pg_server: PostgresSettings) -> None:
    with psycopg.connect(pg_server.dsn("support")) as conn:
        rows = conn.execute(
            "select table_name from information_schema.tables "
            "where table_schema = 'public' order by table_name"
        ).fetchall()

    assert {row[0] for row in rows} == {"api_keys", "customers", "notes", "tickets"}


# -- the bearer boundary ---------------------------------------------------


async def test_a_gitea_audience_token_gets_401(pg_app: str, sign_token: Any) -> None:
    response = await raw_call(pg_app, sign_token(audience="gitea-mcp", scope=("gitea:read",)))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


async def test_a_real_triage_obo_token_gets_401(real_pg_app: str, mint_obo: Any) -> None:
    # A real Keycloak token minted for gitea-mcp, presented to the postgres
    # server. The audience is the only claim that matters here.
    token = mint_obo(scope="task-id:task-w8-401", audience="gitea-mcp")

    response = await raw_call(real_pg_app, token)

    assert response.status_code == 401


# -- the acceptance reads --------------------------------------------------


async def test_get_ticket_returns_the_ticket_its_notes_and_source_tiers(
    pg_app: str, sign_token: Any, scratch: Scratch
) -> None:
    token = sign_token(audience="postgres-mcp", scope=("db:read",), act="support-agent")

    async with mcp_session(pg_app, token) as session:
        result = await session.call_tool("get_ticket", {"ticket_id": scratch.ticket_id})

    assert result.is_error is False
    payload = structured(result)
    assert payload["subject"] == "Site is down"
    assert payload["status"] == "open"
    assert payload["author_email"] == "user@acme.example"
    assert payload["source"] == {
        "system": "db",
        "kind": "ticket",
        "id": str(scratch.ticket_id),
        "author": "user@acme.example",
        "author_tier": "customer",
    }
    assert len(payload["notes"]) == 1
    note = payload["notes"][0]
    assert note["author_login"] == "bob"
    assert note["body"] == "Looking into it"
    assert note["source"]["kind"] == "note"
    assert note["source"]["author"] == "bob"
    assert note["source"]["author_tier"] == "member"


async def test_a_real_support_agent_token_reads_a_ticket(
    real_pg_app: str, mint_support_obo: Any, scratch: Scratch
) -> None:
    """The acceptance path end to end, with the actor the ticket names.

    The console client carries both `aud-triage-agent` and `aud-support-agent`,
    so a human login is exchangeable by support-agent directly, and the token
    this mints records `act.sub` and `azp` as support-agent. That is the real
    exchange the demo takes, not the gateway's two hops.
    """
    token = mint_support_obo()
    claims = decode_claims(token)["claims"]

    assert claims["act"] == {"sub": "support-agent"}
    assert claims["azp"] == "support-agent"
    assert "postgres-mcp" in audience_list(claims)

    async with mcp_session(real_pg_app, token) as session:
        result = await session.call_tool("get_ticket", {"ticket_id": scratch.ticket_id})

    assert result.is_error is False
    assert structured(result)["subject"] == "Site is down"


async def test_run_readonly_sql_refuses_a_write_and_allows_a_select(
    pg_app: str, sign_token: Any
) -> None:
    token = sign_token(audience="postgres-mcp", scope=("db:read",))
    sql = "select id, subject from tickets"

    async with mcp_session(pg_app, token) as session:
        refused = await session.call_tool(
            "run_readonly_sql", {"sql": "update tickets set status='closed'"}
        )
        allowed = await session.call_tool("run_readonly_sql", {"sql": sql})

    assert refused.is_error is True
    assert "not a read keyword" in text_of(refused)
    assert allowed.is_error is False
    payload = structured(allowed)
    assert payload["columns"] == ["id", "subject"]
    assert payload["rows"] == [{"id": 10, "subject": "Site is down"}]
    assert payload["source"]["kind"] == "query"
    assert payload["source"]["id"] == hashlib.sha256(sql.encode("utf-8")).hexdigest()[:12]
    assert payload["source"]["author_tier"] == "unknown"


async def test_run_readonly_sql_refuses_every_statement_escape(
    pg_app: str, sign_token: Any, scratch: Scratch
) -> None:
    """A transaction keyword cannot carry a write past the read guard.

    A no-parameter `execute` used the simple query protocol, which accepts more
    than one statement, so `commit; update ...` committed the read-only
    transaction and then ran the write. Every one of these has to be a tool
    error, and the ticket has to still be `open` afterwards.
    """
    token = sign_token(audience="postgres-mcp", scope=("db:read",))
    escapes = [
        "commit; update tickets set status='closed'",
        "rollback; update tickets set status='closed'",
        "begin read write; update tickets set status='closed'",
        "select 1; commit; update tickets set status='closed'",
        "update tickets set status='closed'",
    ]

    async with mcp_session(pg_app, token) as session:
        results = [await session.call_tool("run_readonly_sql", {"sql": sql}) for sql in escapes]
        ticket = await session.call_tool("get_ticket", {"ticket_id": scratch.ticket_id})

    for sql, result in zip(escapes, results, strict=True):
        assert result.is_error is True, f"{sql!r} was not refused"
    assert structured(ticket)["status"] == "open", "none of the escapes ran a write"


async def test_run_readonly_sql_refuses_copy_to_program(pg_app: str, sign_token: Any) -> None:
    """`COPY ... TO PROGRAM` runs a shell command as the server's role.

    It reached the database through the simple query protocol before, and the
    server's role is a superuser, so this was a shell. The statement has to be
    refused before it is sent.
    """
    token = sign_token(audience="postgres-mcp", scope=("db:read",))
    sql = "copy (select 'x') to program 'cat > /tmp/w8_copy_escape'"

    async with mcp_session(pg_app, token) as session:
        result = await session.call_tool("run_readonly_sql", {"sql": sql})

    assert result.is_error is True
    assert "copy" in text_of(result)
    assert "not a read keyword" in text_of(result)


async def test_run_readonly_sql_refuses_a_second_statement_after_a_select(
    pg_app: str, sign_token: Any, scratch: Scratch
) -> None:
    """A read keyword does not make the rest of the string a read.

    `select 1; commit; update ...` starts with `select`, so only the extended
    protocol stops it: the whole string is one subquery, and a second statement
    is a syntax error there.
    """
    token = sign_token(audience="postgres-mcp", scope=("db:read",))

    async with mcp_session(pg_app, token) as session:
        result = await session.call_tool("run_readonly_sql", {"sql": "select 1; select 2"})
        ticket = await session.call_tool("get_ticket", {"ticket_id": scratch.ticket_id})

    assert result.is_error is True
    assert structured(ticket)["status"] == "open"


async def test_run_readonly_sql_allows_a_trailing_semicolon_and_a_leading_comment(
    pg_app: str, sign_token: Any
) -> None:
    """The two spellings a person types still read, and a comment hides nothing."""
    token = sign_token(audience="postgres-mcp", scope=("db:read",))

    async with mcp_session(pg_app, token) as session:
        trailing = await session.call_tool("run_readonly_sql", {"sql": "select 1;"})
        commented = await session.call_tool("run_readonly_sql", {"sql": "/* a note */ select 1"})

    assert trailing.is_error is False
    assert structured(trailing)["rows"] == [{"?column?": 1}]
    assert commented.is_error is False
    assert structured(commented)["rows"] == [{"?column?": 1}]


async def test_run_readonly_sql_allows_a_trailing_line_comment(
    pg_app: str, sign_token: Any
) -> None:
    """A trailing `--` comment used to swallow the wrapper's closing parenthesis.

    The wrapper now emits a newline before the parenthesis, and one trailing
    semicolon is dropped before a trailing comment rather than only when the
    string's last character is `;`.
    """
    token = sign_token(audience="postgres-mcp", scope=("db:read",))

    async with mcp_session(pg_app, token) as session:
        commented = await session.call_tool("run_readonly_sql", {"sql": "select 1 -- note"})
        semicolon = await session.call_tool("run_readonly_sql", {"sql": "select 1; -- note"})

    assert commented.is_error is False, text_of(commented)
    assert structured(commented)["rows"] == [{"?column?": 1}]
    assert semicolon.is_error is False, text_of(semicolon)
    assert structured(semicolon)["rows"] == [{"?column?": 1}]


async def test_run_readonly_sql_keeps_a_percent_in_the_callers_sql(
    pg_app: str, sign_token: Any
) -> None:
    """psycopg parses the wrapper on the client, so a `%` has to be doubled.

    The caller's `%` used to be read as a placeholder: `like 'Ac%'` was refused,
    `format('%s', name)` miscounted the parameters, and `'%%'` came back as one
    `%` with no error at all.
    """
    token = sign_token(audience="postgres-mcp", scope=("db:read",))

    async with mcp_session(pg_app, token) as session:
        like = await session.call_tool(
            "run_readonly_sql", {"sql": "select name from customers where name like 'Ac%'"}
        )
        formatted = await session.call_tool(
            "run_readonly_sql",
            {"sql": "select format('%s', name) as label from customers order by id"},
        )
        doubled = await session.call_tool("run_readonly_sql", {"sql": "select '%%' as literal"})
        single = await session.call_tool("run_readonly_sql", {"sql": "select '100%' as literal"})
        literal = await session.call_tool(
            "run_readonly_sql", {"sql": "select name from customers where name = 'Ac%'"}
        )

    assert like.is_error is False, text_of(like)
    assert structured(like)["rows"] == [{"name": "Acme"}]
    assert formatted.is_error is False, text_of(formatted)
    assert structured(formatted)["rows"] == [{"label": "Acme"}, {"label": "Globex"}]
    assert doubled.is_error is False, text_of(doubled)
    assert structured(doubled)["rows"] == [{"literal": "%%"}]
    assert single.is_error is False, text_of(single)
    assert structured(single)["rows"] == [{"literal": "100%"}]
    assert literal.is_error is False, text_of(literal)
    assert structured(literal)["rows"] == [], "a literal percent is not a wildcard"


async def test_run_readonly_sql_refuses_nextval_in_the_read_only_transaction(
    pg_app: str, sign_token: Any
) -> None:
    """The READ ONLY transaction is the layer that stops a sequence advance.

    `nextval` is a function that writes the sequence, and Postgres refuses it
    with SQLSTATE 25006 inside the transaction. The transaction does not stop a
    superuser-only function such as `pg_read_file`, which is why a dedicated
    `SELECT`-only role is the next layer (a follow-up).
    """
    token = sign_token(audience="postgres-mcp", scope=("db:read",))
    sql = "select nextval('customers_id_seq')"

    async with mcp_session(pg_app, token) as session:
        result = await session.call_tool("run_readonly_sql", {"sql": sql})

    assert result.is_error is True, text_of(result)
    assert "read-only transaction" in text_of(result)


async def test_get_customer_returns_keys_and_lists_every_value_in_secrets(
    pg_app: str, sign_token: Any, scratch: Scratch
) -> None:
    token = sign_token(audience="postgres-mcp", scope=("db:read",))

    async with mcp_session(pg_app, token) as session:
        result = await session.call_tool("get_customer", {"customer_id": scratch.customer_id})

    assert result.is_error is False
    payload = structured(result)
    values = [key["key_value"] for key in payload["api_keys"]]
    assert values == [FIXTURE_VALUE, FIXTURE_RETIRED_VALUE]
    # Every key value the result carries is in `secrets`, which is what W11
    # reads without a model.
    assert set(values) <= set(payload["secrets"])
    assert payload["secrets"] == values
    # The value reaches the model once, on the key row, not a second time in the
    # structured metadata.
    assert text_of(result).count(FIXTURE_VALUE) == 1


async def test_run_readonly_sql_lists_a_selected_key_value_in_secrets(
    pg_app: str, sign_token: Any
) -> None:
    token = sign_token(audience="postgres-mcp", scope=("db:read",))

    async with mcp_session(pg_app, token) as session:
        result = await session.call_tool(
            "run_readonly_sql", {"sql": "select key_value from api_keys"}
        )

    assert result.is_error is False
    payload = structured(result)
    assert payload["secrets"] == [FIXTURE_VALUE, FIXTURE_RETIRED_VALUE]
    assert text_of(result).count(FIXTURE_VALUE) == 1


async def test_run_readonly_sql_lists_an_aliased_or_json_key_value_in_secrets(
    pg_app: str, sign_token: Any
) -> None:
    """The key value is in `secrets` however the statement names it.

    A column-name match found the value only when the column was literally
    `key_value`, so `select key_value as kv`, `select key_value || '' as kv`,
    and `select row_to_json(k) from api_keys k` all leaked a key while W11 read
    an empty `secrets`. The check is on the returned values instead.
    """
    token = sign_token(audience="postgres-mcp", scope=("db:read",))
    statements = [
        "select key_value as kv from api_keys order by id",
        "select key_value || '' as kv from api_keys order by id",
        "select row_to_json(k) from api_keys k order by k.id",
    ]

    async with mcp_session(pg_app, token) as session:
        for sql in statements:
            result = await session.call_tool("run_readonly_sql", {"sql": sql})
            assert result.is_error is False, text_of(result)
            secrets = structured(result)["secrets"]
            assert FIXTURE_VALUE in secrets, f"{sql!r} leaked a key with no secrets entry"
            assert FIXTURE_RETIRED_VALUE in secrets, f"{sql!r} missed the retired key"


async def test_run_readonly_sql_refuses_a_result_over_the_byte_budget(
    pg_app: str, sign_token: Any
) -> None:
    """A result too big for the transport is an error, not a dropped stream.

    `select repeat('x', 1000000)` used to end the SSE stream with no response
    while the audit line said `"status": "ok"`: a call the audit described as
    fine and the caller never got an answer for.
    """
    token = sign_token(audience="postgres-mcp", scope=("db:read",))
    sql = "select repeat('x', 1000000)"

    async with mcp_session(pg_app, token) as session:
        result = await session.call_tool("run_readonly_sql", {"sql": sql})

    assert result.is_error is True
    assert "limit" in text_of(result)


async def test_run_readonly_sql_allows_a_result_just_under_the_byte_budget(
    pg_app: str, sign_token: Any
) -> None:
    """The budget has to leave room for the response the transport can carry.

    A cap that only fired above the transport's own edge would let a result
    through that still ends the stream, which is the audit-says-ok case the cap
    exists to prevent. This reads a result just under the budget and gets an
    answer, so the two numbers are not the same.
    """
    token = sign_token(audience="postgres-mcp", scope=("db:read",))
    sql = "select repeat('x', 200000)"

    async with mcp_session(pg_app, token) as session:
        result = await session.call_tool("run_readonly_sql", {"sql": sql})

    assert result.is_error is False, text_of(result)
    assert structured(result)["rows"] == [{"repeat": "x" * 200000}]


async def test_the_byte_budget_covers_a_tool_other_than_run_readonly_sql(
    pg_app: str,
    sign_token: Any,
    pg_server: PostgresSettings,
    scratch: Scratch,
) -> None:
    """A payload over the budget is an error for every tool, not only a raw read.

    A ticket body past the budget used to drop the stream while the audit line
    said `ok`, because the only byte check was inside `run_readonly_sql`. The
    check now lives in the server's result shaping, so `get_ticket` answers with
    a tool error naming the bytes and the limit, and a ticket under the budget
    still returns.
    """
    token = sign_token(audience="postgres-mcp", scope=("db:read",))

    async with mcp_session(pg_app, token) as session:
        under = await session.call_tool("get_ticket", {"ticket_id": scratch.ticket_id})
        with psycopg.connect(pg_server.dsn(scratch.name)) as conn:
            conn.execute(
                "update tickets set body = repeat('x', 300000) where id = %s",
                (scratch.ticket_id,),
            )
            conn.commit()
        over = await session.call_tool("get_ticket", {"ticket_id": scratch.ticket_id})

    assert under.is_error is False, text_of(under)
    assert structured(under)["subject"] == "Site is down"
    assert over.is_error is True, text_of(over)
    assert "bytes" in text_of(over)
    assert str(MAX_RESULT_BYTES) in text_of(over)


async def test_search_customers_never_returns_keys(pg_app: str, sign_token: Any) -> None:
    token = sign_token(audience="postgres-mcp", scope=("db:read",))

    async with mcp_session(pg_app, token) as session:
        result = await session.call_tool("search_customers", {"query": "acme"})

    assert result.is_error is False
    payload = structured(result)
    assert [customer["id"] for customer in payload["customers"]] == [1]
    assert "fixture-key" not in json.dumps(payload)


async def test_search_customers_treats_a_wildcard_as_a_character(
    pg_app: str, sign_token: Any
) -> None:
    """`%` is a character to find, not every customer.

    Unescaped, `search_customers("%")` returned every row, and the resource the
    decision was made against was the literal query string rather than the rows
    the read returned.
    """
    token = sign_token(audience="postgres-mcp", scope=("db:read",))

    async with mcp_session(pg_app, token) as session:
        wildcard = await session.call_tool("search_customers", {"query": "%"})
        underscore = await session.call_tool("search_customers", {"query": "Ac_e"})

    assert wildcard.is_error is False
    assert structured(wildcard)["customers"] == [], "a wildcard matched rows it does not name"
    assert underscore.is_error is False
    assert structured(underscore)["customers"] == [], "an underscore is not a single character"


# -- the writes ------------------------------------------------------------


async def test_update_ticket_sets_the_status_and_appends_the_callers_note(
    pg_app: str, sign_token: Any, scratch: Scratch
) -> None:
    token = sign_token(audience="postgres-mcp", scope=("db:write",), sub="h-bob")

    async with mcp_session(pg_app, token) as session:
        result = await session.call_tool(
            "update_ticket",
            {"ticket_id": scratch.ticket_id, "status": "pending", "note": "escalated to the desk"},
        )

    assert result.is_error is False
    payload = structured(result)
    assert payload["status"] == "pending"
    added = next(note for note in payload["notes"] if note["body"] == "escalated to the desk")
    assert added["author_login"] == "h-bob"
    assert added["source"]["author_tier"] == "member"


async def test_rotate_api_key_replaces_the_value_and_revokes_the_other_rows(
    pg_app: str, sign_token: Any, scratch: Scratch
) -> None:
    token = sign_token(audience="postgres-mcp", scope=("db:write",))

    async with mcp_session(pg_app, token) as session:
        rotated = await session.call_tool(
            "rotate_api_key", {"customer_id": scratch.customer_id, "key_id": scratch.key_id}
        )
        detail = await session.call_tool("get_customer", {"customer_id": scratch.customer_id})

    assert rotated.is_error is False
    payload = structured(rotated)
    assert payload["key_value"] != FIXTURE_VALUE
    assert payload["secrets"] == [payload["key_value"]]
    rows = {row["id"]: row for row in structured(detail)["api_keys"]}
    assert rows[scratch.key_id]["revoked"] is False
    assert rows[scratch.key_id]["key_value"] == payload["key_value"]
    assert rows[1001]["revoked"] is True


async def test_a_missing_ticket_is_a_tool_error(pg_app: str, sign_token: Any) -> None:
    token = sign_token(audience="postgres-mcp", scope=("db:read",))

    async with mcp_session(pg_app, token) as session:
        result = await session.call_tool("get_ticket", {"ticket_id": 999999})

    assert result.is_error is True
    assert "not found" in text_of(result)
