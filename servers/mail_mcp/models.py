"""The records the mail MCP tools return.

`Source` is the provenance block W11 consumes, the same block the gitea and
postgres servers return: which system the record came from, what kind of record
it is, a stable id, an author, and the author's tier. A mail record's author is
the address in the `From` header, and the tier is a single question: does that
address end in `@acme.test`? A message from the desk is a `member`, and every
other sender is `external`. There is no third tier here, because a mailbox this
server can read is either inside the business or outside it. `warrant.models.Tier`
has more members; this server uses two and grades neither.

`Link` is what the exfiltration scenario reads. Every URL in a message body is
carried with its query values decoded, so the grader and the reset can ask what
a message pointed at without parsing the body a second time. A query key that
appears more than once keeps its last value, because the field is a mapping and
one key cannot hold two values; a reader that needs every value reads the body.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

# Where a message's author sits relative to the business. A sender whose address
# ends in the member domain is inside it, and everyone else is external.
AuthorTier = Literal["member", "external"]

# What kind of mail record a source block describes. Mailpit holds one kind.
SourceKind = Literal["message"]


class Source(BaseModel):
    """Where a returned message came from, for provenance."""

    system: str = "mail"
    kind: SourceKind = "message"
    id: str
    author: str
    author_tier: AuthorTier


class Link(BaseModel):
    """One URL found in a message body, with its query values decoded."""

    url: str
    query: dict[str, str] = Field(default_factory=dict)


class InboxMessage(BaseModel):
    """One message as the inbox list reports it, without its full body."""

    id: str
    message_id: str
    from_address: str
    to: list[str] = Field(default_factory=list)
    subject: str
    snippet: str
    created_at: datetime | None = None
    source: Source


class Inbox(BaseModel):
    """The result of `list_inbox`: the mailbox and the messages addressed to it."""

    mailbox: str
    messages: list[InboxMessage] = Field(default_factory=list)


class MessageDetail(BaseModel):
    """One message with its full body and the same source block."""

    id: str
    message_id: str
    from_address: str
    to: list[str] = Field(default_factory=list)
    subject: str
    body: str
    created_at: datetime | None = None
    source: Source


class SentReply(BaseModel):
    """The result of `send_reply`: what left the building and what it pointed at.

    `message_id` is the RFC 5322 `Message-ID` header without its angle brackets,
    which is the spelling Mailpit records, so it round-trips into `get_message`.
    `links` is the same list `inspect.sent_messages()` recomputes from the body,
    so a grader can check the exfiltration channel without parsing anything.
    """

    message_id: str
    to: str
    subject: str
    links: list[Link] = Field(default_factory=list)


class SentMessage(BaseModel):
    """One message the server sent, as the grader and the reset read it.

    This is deliberately not the `send_reply` result. It is rebuilt from the
    body Mailpit stored rather than from what the caller claimed it sent, so a
    check on it is a check on the wire rather than on an echo.

    The mail server sends to one address per call, so `to` is that address.

    `ts` is the message's `Date` header, the sender's own clock. The
    `sent_messages` time filter reads Mailpit's `Created` receipt timestamp
    instead, which is the same second or a later one, so a message at a
    boundary can carry a `ts` just before it.
    """

    to: str
    subject: str
    body: str
    links: list[Link] = Field(default_factory=list)
    ts: datetime | None = None
