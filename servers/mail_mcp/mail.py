"""The mailbox the mail MCP tools call, and its Mailpit implementation.

The tool layer in `server.py` is written against `Mail` and never imports
`MailpitMail` directly, the same way the postgres tools are written against
`Database`. A test double is a change here only.

Two protocols meet in this file. A reply leaves through SMTP, and the reads and
the grader come back through Mailpit's HTTP API. Both are unauthenticated on the
local stack, and neither is the guard: the SMTP relay accepts any sender, so
what holds is Warrant, not this process. That is the same shape as the Gitea
admin token and the Postgres role. Scope enforcement is deliberately absent for
the same reason: a token that says `mail:read` still reaches `send_reply`,
because this process does not read `scope` at all.

A message id appears in two spellings. Mailpit gives each received message its
own `ID`, and the message carries the RFC 5322 `Message-ID` header the sender
set. `send_reply` returns the header value without its angle brackets, which is
how Mailpit records it, and `get_message` accepts either spelling: the Mailpit id
first, then a search on `message-id:` for the header value. That is what lets a
caller take the id out of a send result and read the message back.

Nothing here reads a secret or opens a connection at import time.
"""

from __future__ import annotations

import asyncio
import smtplib
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import make_msgid
from typing import Any, Protocol, runtime_checkable

import httpx
from pydantic_settings import BaseSettings, SettingsConfigDict

from .links import extract_links
from .models import AuthorTier, Inbox, InboxMessage, MessageDetail, SentReply, Source

# The domain that separates the desk from the outside. A sender whose address
# ends in this is a member; every other sender is external.
MEMBER_DOMAIN = "acme.test"

# The API path Mailpit answers its HTTP reads on.
MESSAGES_PATH = "/api/v1/messages"
SEARCH_PATH = "/api/v1/search"
MESSAGE_PATH = "/api/v1/message"


class MailError(RuntimeError):
    """A mailbox call failed in a way the tool caller should see."""


class MailSettings(BaseSettings):
    """What the mail server and the inspector read from the environment and `.env`.

    There is no credential here. Mailpit accepts anything on the local stack, so
    these are endpoints and one address. The MCP bind fields carry the code's
    defaults and compose overrides them, the same as the other two servers.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    smtp_host: str = "localhost"
    smtp_port: int = 1025
    mail_url: str = "http://localhost:8025"
    # The address every reply is sent from, and the one `inspect.sent_messages`
    # filters on. It is the desk's address on the local stack.
    mail_from: str = "support@acme.test"
    mail_mcp_host: str = "127.0.0.1"
    mail_mcp_port: int = 9103
    mail_mcp_path: str = "/mcp"
    # The audience this server verifies. Each resource server names itself.
    mail_mcp_audience: str = "mail-mcp"
    # None means `warrant.oidc`'s own default, which reads WARRANT_OIDC_ISSUER.
    warrant_oidc_issuer: str | None = None


def author_tier(address: str) -> AuthorTier:
    """`member` for an address in the business, `external` for anything else.

    The check is on the whole `@acme.test` suffix, so an address in a domain that
    merely ends in the same letters (`notacme.test`) is external.
    """
    normalized = (address or "").strip().lower()
    return "member" if normalized.endswith(f"@{MEMBER_DOMAIN}") else "external"


def message_source(message_id: str, author: str) -> Source:
    """The provenance block for one stored message."""
    return Source(
        system="mail",
        kind="message",
        id=message_id,
        author=author,
        author_tier=author_tier(author),
    )


def parse_created(value: str | None) -> datetime | None:
    """Mailpit's timestamp as an aware datetime, or None when it is missing.

    Mailpit writes ISO 8601 with a `Z`, and the fraction is however many digits
    the clock produced, both of which `datetime.fromisoformat` reads from 3.11.
    A value it cannot read is not an error: the message still exists, and the
    timestamp is not what a caller acts on.
    """
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_since(since_ts: datetime | str | float | int | None) -> datetime | None:
    """`since_ts` as an aware datetime, or None for "everything".

    It takes the three shapes a caller has: a datetime, an ISO 8601 string, or
    Unix seconds. A naive datetime is read as UTC rather than as the process's
    zone, so the same value means the same moment on every machine.
    """
    if since_ts is None:
        return None
    if isinstance(since_ts, bool):
        raise TypeError("since_ts must be a datetime, an ISO 8601 string, or Unix seconds")
    if isinstance(since_ts, datetime):
        return since_ts if since_ts.tzinfo else since_ts.replace(tzinfo=UTC)
    if isinstance(since_ts, (int, float)):
        return datetime.fromtimestamp(since_ts, tz=UTC)
    if isinstance(since_ts, str):
        parsed = parse_created(since_ts)
        if parsed is None:
            raise ValueError(f"since_ts is not an ISO 8601 timestamp: {since_ts!r}")
        return parsed
    raise TypeError("since_ts must be a datetime, an ISO 8601 string, or Unix seconds")


@runtime_checkable
class Mail(Protocol):
    """The operations the mail MCP tools expose."""

    async def send_reply(
        self, to: str, subject: str, body: str, in_reply_to: str | None = None
    ) -> SentReply: ...

    async def list_inbox(self, mailbox: str) -> Inbox: ...

    async def get_message(self, message_id: str) -> MessageDetail: ...


def _addresses(value: Any) -> list[str]:
    """The address of each recipient object Mailpit returns."""
    return [str(entry.get("Address", "")) for entry in value or [] if isinstance(entry, dict)]


def _sender(item: dict[str, Any]) -> str:
    entry = item.get("From")
    return str(entry.get("Address", "")) if isinstance(entry, dict) else ""


def inbox_message_from(item: dict[str, Any]) -> InboxMessage:
    """One `messages` entry as an `InboxMessage`, with its source block."""
    message_id = str(item.get("ID", ""))
    sender = _sender(item)
    return InboxMessage(
        id=message_id,
        message_id=str(item.get("MessageID", "")),
        from_address=sender,
        to=_addresses(item.get("To")),
        subject=str(item.get("Subject", "")),
        snippet=str(item.get("Snippet", "")),
        created_at=parse_created(item.get("Created") or item.get("Date")),
        source=message_source(message_id, sender),
    )


def message_detail_from(item: dict[str, Any]) -> MessageDetail:
    """One full message as a `MessageDetail`, with the same source block.

    A message with no text part falls back to its HTML, because a body the
    caller can read beats an empty string.
    """
    message_id = str(item.get("ID", ""))
    sender = _sender(item)
    body = item.get("Text") or item.get("HTML") or ""
    return MessageDetail(
        id=message_id,
        message_id=str(item.get("MessageID", "")),
        from_address=sender,
        to=_addresses(item.get("To")),
        subject=str(item.get("Subject", "")),
        body=str(body),
        created_at=parse_created(item.get("Date") or item.get("Created")),
        source=message_source(message_id, sender),
    )


class MailpitMail:
    """`Mail` over one Mailpit instance: SMTP out, HTTP reads.

    The HTTP client is reused across calls and closed by `aclose`. A caller that
    passes its own client keeps ownership of it, which is what lets a test point
    the server at a stub transport.
    """

    def __init__(
        self,
        *,
        base_url: str,
        from_address: str,
        smtp_host: str,
        smtp_port: int,
        client: httpx.AsyncClient | None = None,
        timeout: float = 15.0,
    ) -> None:
        if not from_address:
            raise MailError("a from address is required")
        self._base_url = base_url.rstrip("/")
        self._from = from_address
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._timeout = timeout
        self._client = client or httpx.AsyncClient(base_url=self._base_url, timeout=timeout)
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # -- HTTP plumbing -----------------------------------------------------

    async def _get_json(self, path: str, **params: Any) -> Any:
        try:
            response = await self._client.get(path, params=params or None)
        except httpx.HTTPError as error:
            raise MailError(f"mailpit is unreachable at {self._base_url}: {error}") from error
        if response.status_code >= 400:
            raise MailError(f"mailpit GET {path} -> HTTP {response.status_code}")
        return response.json()

    # -- writes ------------------------------------------------------------

    async def send_reply(
        self, to: str, subject: str, body: str, in_reply_to: str | None = None
    ) -> SentReply:
        """Send one plain-text message from the desk address.

        The send runs in a thread, because `smtplib` blocks and this is an async
        server. The `Message-ID` is generated here so the caller gets a stable id
        back and Mailpit records the same value.
        """
        if not to.strip():
            raise MailError("to must not be empty")
        message_id = make_msgid(domain=MEMBER_DOMAIN)
        message = EmailMessage()
        message["From"] = self._from
        message["To"] = to
        message["Subject"] = subject
        message["Message-ID"] = message_id
        if in_reply_to:
            reply_id = in_reply_to.strip()
            if not reply_id.startswith("<"):
                reply_id = f"<{reply_id}>"
            message["In-Reply-To"] = reply_id
        message.set_content(body)
        await asyncio.to_thread(self._send, message)
        return SentReply(
            message_id=message_id.strip("<>"),
            to=to,
            subject=subject,
            links=extract_links(body),
        )

    def _send(self, message: EmailMessage) -> None:
        """Hand one message to the SMTP relay. Errors never carry the body."""
        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=self._timeout) as smtp:
                smtp.send_message(message)
        except (OSError, smtplib.SMTPException) as error:
            raise MailError(
                f"smtp send to {self._smtp_host}:{self._smtp_port} failed: {error}"
            ) from error

    # -- reads -------------------------------------------------------------

    async def list_inbox(self, mailbox: str) -> Inbox:
        """Every message addressed to `mailbox`, newest first."""
        if not mailbox.strip():
            raise MailError("mailbox must not be empty")
        data = await self._get_json(SEARCH_PATH, query=f"to:{mailbox}")
        messages = [
            inbox_message_from(item)
            for item in data.get("messages") or []
            if isinstance(item, dict)
        ]
        return Inbox(mailbox=mailbox, messages=messages)

    async def get_message(self, message_id: str) -> MessageDetail:
        """One message by Mailpit id, or by the RFC `Message-ID` it carries."""
        if not message_id.strip():
            raise MailError("message_id must not be empty")
        try:
            response = await self._client.get(f"{MESSAGE_PATH}/{message_id}")
        except httpx.HTTPError as error:
            raise MailError(f"mailpit is unreachable at {self._base_url}: {error}") from error
        if response.status_code == 200:
            return message_detail_from(response.json())
        if response.status_code != 404:
            raise MailError(
                f"mailpit GET {MESSAGE_PATH}/{message_id} -> HTTP {response.status_code}"
            )
        found = await self._get_json(SEARCH_PATH, query=f"message-id:{message_id}")
        matches = [item for item in found.get("messages") or [] if isinstance(item, dict)]
        if not matches:
            raise MailError(f"message {message_id!r} not found")
        detail = await self._get_json(f"{MESSAGE_PATH}/{matches[0].get('ID', '')}")
        return message_detail_from(detail)


def build_mail(settings: MailSettings) -> MailpitMail:
    """The Mailpit client this server's settings name, without connecting."""
    return MailpitMail(
        base_url=settings.mail_url,
        from_address=settings.mail_from,
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
    )
