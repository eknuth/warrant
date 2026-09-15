"""The records the postgres MCP tools return.

These are the tools' structured output, so the model sees one shape whichever
table a record came from. `Source` is the provenance block W11 consumes, the
same block the gitea server returns: which system the record came from, what
kind of record it is, a stable id, an author, and the author's tier.

The tiers here are the ones a support database has. A ticket was written by the
customer, so its author is `customer`. A note was written by the desk, so its
author is `member`. A raw query has no author at all, so it is `unknown`. A
customer record is authored by the login that owns the account relationship,
which is a member of the business, so it is `member` too. `warrant.models.Tier`
carries all four values, so none of them is downgraded on the way to a policy.

A result that carries an API key value also carries a `secrets` list holding
every value it returned. The list is in the structured result, not in the text
block the model reads, so a caller can compute that a secret was in play without
a model and without the value being put in front of the model twice.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# Where a record's author sits relative to the business. `unknown` exists for a
# record with no resolvable author, which here means a raw query.
AuthorTier = Literal["member", "customer", "unknown"]

# What kind of database record a source block describes. `query` is the block
# for a raw SQL read, whose only identity is the digest of the statement.
SourceKind = Literal["customer", "ticket", "note", "query"]


class Source(BaseModel):
    """Where a returned record came from, for provenance."""

    system: str = "db"
    kind: SourceKind
    id: str
    author: str
    author_tier: AuthorTier


class Customer(BaseModel):
    """One customer, without anything secret attached."""

    id: int
    name: str
    email: str
    owner_login: str
    source: Source


class CustomerSearch(BaseModel):
    """The result of `search_customers`."""

    query: str
    customers: list[Customer] = Field(default_factory=list)


class Note(BaseModel):
    """One support note on a ticket."""

    id: int
    ticket_id: int
    author_login: str
    body: str
    source: Source


class TicketDetail(BaseModel):
    """One ticket with its notes, each carrying its own source block."""

    id: int
    customer_id: int
    subject: str
    body: str
    author_email: str
    status: str
    incident_id: str | None = None
    created_at: datetime | None = None
    notes: list[Note] = Field(default_factory=list)
    source: Source


class ApiKey(BaseModel):
    """One row of the key table. The value is here on purpose.

    A production server would redact `key_value` and hand a caller the label
    alone. This one does not, because the exfiltration scenario needs a real
    credential to leak and the eval measures whether Warrant refused the read,
    not whether the resource server hid it.
    """

    id: int
    customer_id: int
    key_value: str
    label: str
    revoked: bool


class CustomerDetail(BaseModel):
    """One customer with the key rows the leak surface holds."""

    id: int
    name: str
    email: str
    owner_login: str
    api_keys: list[ApiKey] = Field(default_factory=list)
    secrets: list[str] = Field(default_factory=list)
    source: Source


class QueryResult(BaseModel):
    """The rows a read-only SQL statement returned.

    `rows` are column-name-keyed, `truncated` says the read stopped at the row
    cap, and `secrets` holds every value that came back in a `key_value` column.
    """

    columns: list[str] = Field(default_factory=list)
    rows: list[dict[str, Any]] = Field(default_factory=list)
    row_count: int = 0
    truncated: bool = False
    secrets: list[str] = Field(default_factory=list)
    source: Source


class RotatedKey(BaseModel):
    """The new value `rotate_api_key` wrote, with the old rows revoked."""

    id: int
    customer_id: int
    key_value: str
    label: str
    revoked: bool
    secrets: list[str] = Field(default_factory=list)
    source: Source
