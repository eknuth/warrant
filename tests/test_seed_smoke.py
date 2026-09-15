"""The smoke seeder's support rows, against a throwaway database.

`scripts/seed_smoke.py` writes one customer, one honest ticket, and one API key
into the support database. These tests load the real schema into a database of
their own and run the seeder against it, so what is checked is the SQL rather
than a mock: that the three rows land, that a second run adds no second key,
that the ticket is reset to its open state, and that the identity sequences move
past the seeded ids.

Marked `integration`, so they skip when the compose stack is absent.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import psycopg
import pytest

from scripts.seed_smoke import (
    CUSTOMER_EMAIL,
    CUSTOMER_ID,
    CUSTOMER_OWNER,
    TICKET_ID,
    SeedSettings,
    seed_postgres,
)
from tests.fixtures.auth import require_postgres

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[1]
SCHEMA = REPO / "infra" / "postgres" / "schema.sql"


@pytest.fixture
def scratch_settings() -> Iterator[SeedSettings]:
    """A throwaway database with the support schema and no rows.

    Only an absent stack skips. A server that answers and refuses the role is a
    failure, not a skip, through the same `require_postgres` the W8 postgres
    fixture uses.
    """
    base = SeedSettings()
    require_postgres(base)
    name = f"w10_seed_{uuid.uuid4().hex[:10]}"
    admin = psycopg.connect(base.dsn("postgres"), autocommit=True)
    admin.execute(f'create database "{name}"')
    try:
        with psycopg.connect(base.dsn(name)) as conn:
            conn.execute(SCHEMA.read_text(encoding="utf-8"))
            conn.commit()
        yield SeedSettings(postgres_db=name)
    finally:
        admin.execute(f'drop database "{name}" with (force)')
        admin.close()


def test_the_seed_writes_one_customer_one_ticket_and_one_key(
    scratch_settings: SeedSettings,
) -> None:
    added = seed_postgres(scratch_settings)

    assert added is True
    with psycopg.connect(scratch_settings.dsn()) as conn:
        customer = conn.execute(
            "SELECT name, email, owner_login FROM customers WHERE id = %s", (CUSTOMER_ID,)
        ).fetchone()
        ticket = conn.execute(
            "SELECT customer_id, author_email, status, incident_id FROM tickets WHERE id = %s",
            (TICKET_ID,),
        ).fetchone()
        keys = conn.execute(
            "SELECT count(*) FROM api_keys WHERE customer_id = %s", (CUSTOMER_ID,)
        ).fetchone()

    assert customer is not None and customer[1] == CUSTOMER_EMAIL
    assert customer[2] == CUSTOMER_OWNER
    assert ticket == (CUSTOMER_ID, CUSTOMER_EMAIL, "open", None)
    assert keys == (1,)


def test_a_second_run_adds_no_second_key(scratch_settings: SeedSettings) -> None:
    assert seed_postgres(scratch_settings) is True

    assert seed_postgres(scratch_settings) is False
    with psycopg.connect(scratch_settings.dsn()) as conn:
        keys = conn.execute(
            "SELECT count(*) FROM api_keys WHERE customer_id = %s", (CUSTOMER_ID,)
        ).fetchone()
    assert keys == (1,)


def test_a_second_run_resets_the_ticket(scratch_settings: SeedSettings) -> None:
    """A smoked ticket comes back open and un-noted, so the next run is the same."""
    seed_postgres(scratch_settings)
    with psycopg.connect(scratch_settings.dsn()) as conn:
        conn.execute("UPDATE tickets SET status = 'closed' WHERE id = %s", (TICKET_ID,))
        conn.execute(
            "INSERT INTO notes (ticket_id, author_login, body) VALUES (%s, %s, %s)",
            (TICKET_ID, "support-agent", "answered"),
        )
        conn.commit()

    seed_postgres(scratch_settings)

    with psycopg.connect(scratch_settings.dsn()) as conn:
        status = conn.execute("SELECT status FROM tickets WHERE id = %s", (TICKET_ID,)).fetchone()
        notes = conn.execute(
            "SELECT count(*) FROM notes WHERE ticket_id = %s", (TICKET_ID,)
        ).fetchone()
    assert status == ("open",)
    assert notes == (0,)


def test_the_sequences_move_past_the_seeded_ids(scratch_settings: SeedSettings) -> None:
    """A later default insert must not reuse the seeded customer's id."""
    seed_postgres(scratch_settings)

    with psycopg.connect(scratch_settings.dsn()) as conn:
        row = conn.execute(
            "INSERT INTO customers (name, email, owner_login) VALUES (%s, %s, %s) RETURNING id",
            ("Someone Else", "else@acme.test", "bob"),
        ).fetchone()
        conn.commit()

    assert row is not None and row[0] > CUSTOMER_ID
