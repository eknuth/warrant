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
import re
import smtplib
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import getaddresses, make_msgid
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

# Mailpit answers a search one page at a time, 50 messages by default whatever
# the match count is. `SEARCH_PAGE` is the page this client asks for and the
# walk follows Mailpit's `start` offset until the reported match count is
# consumed. `MAX_SEARCH_PAGES` bounds a search that keeps answering, so five
# thousand matches per call is the documented limit.
SEARCH_PAGE = 50
MAX_SEARCH_PAGES = 100

# A message id names a Mailpit id or an RFC 5322 `Message-ID`. Anything outside
# this set, and a slash in particular, would change the path this client builds
# rather than name a message, so it is refused before the request.
MESSAGE_ID_UNSAFE = re.compile(r"[/\\?#%\s]")

# The characters a header value may not carry. The email library refuses a
# line break by raising its own error, which the tool layer would report as a
# crash rather than a `MailError`, so the check is here.
HEADER_BREAKS = ("\r", "\n")


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

    async def get_message(self, mailbox: str, message_id: str) -> MessageDetail: ...


def _addresses(value: Any) -> list[str]:
    """The address of each recipient object Mailpit returns."""
    return [str(entry.get("Address", "")) for entry in value or [] if isinstance(entry, dict)]


def _normalize_address(value: str) -> str:
    """An address folded for an exact comparison, without changing the record."""
    return (value or "").strip().lower()


def _recipients(item: dict[str, Any]) -> list[str]:
    """Every address a stored message was delivered to, in Mailpit's own order."""
    found: list[str] = []
    for field in ("To", "Cc", "Bcc"):
        found.extend(_addresses(item.get(field)))
    return found


def _addressed_to(item: dict[str, Any], mailbox: str) -> bool:
    """Whether the exact mailbox address is one of the message's recipients.

    Mailpit's `to:` search is a substring match, so it answers with
    `notsupport@acme.test` and `support@acme.test.evil` for a search on
    `support@acme.test`. This is the second, exact check the parsed recipient
    list gets after that search. `list_inbox` and `get_message` both use it, so
    a message read back by id is held to the same mailbox the call named.
    """
    wanted = _normalize_address(mailbox)
    return any(_normalize_address(address) == wanted for address in _recipients(item))


def _check_header(name: str, value: str | None) -> None:
    """Refuse a header value that carries a line break, as a `MailError`."""
    if value is None:
        return
    if any(break_char in value for break_char in HEADER_BREAKS):
        raise MailError(f"{name} must not contain a line break")


def _check_message_id(message_id: str) -> str:
    """The message id when it can name a message, or a `MailError`.

    A slash, a backslash, or a percent escape in the id would not name a
    message: it would change the path this client requests, so `x/../../info`
    reaches Mailpit's `/api/v1/info` and answers a record that is not a message.
    """
    value = (message_id or "").strip()
    if not value:
        raise MailError("message_id must not be empty")
    if value in (".", "..") or MESSAGE_ID_UNSAFE.search(value):
        raise MailError(f"message_id is not a message id: {message_id!r}")
    return value


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
        """Send one plain-text message from the desk address to one recipient.

        The send runs in a thread, because `smtplib` blocks and this is an async
        server. The `Message-ID` is generated here so the caller gets a stable id
        back and Mailpit records the same value. Every check runs, and the links
        are extracted, before the message is handed to SMTP, so a mail that goes
        out always has its record and a refusal never sends.
        """
        if not to.strip():
            raise MailError("to must not be empty")
        _check_header("to", to)
        _check_header("subject", subject)
        _check_header("in_reply_to", in_reply_to)
        recipients = [address for _name, address in getaddresses([to]) if address]
        if len(recipients) > 1:
            raise MailError(
                f"send_reply delivers to one address per call, this call named {len(recipients)}"
            )
        if not recipients:
            raise MailError("to must name one address")
        links = extract_links(body)
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
            links=links,
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

    async def _search_all(self, query: str) -> list[dict[str, Any]]:
        """Every message Mailpit's search reports for `query`, across its pages.

        Mailpit answers 50 messages at a time whatever the match count is, so a
        single request silently drops the rest. This walks its `start` offset
        until the `messages_count` it reports has been consumed, and it stops on
        an empty page or after `MAX_SEARCH_PAGES` pages so a search that keeps
        answering cannot loop forever.
        """
        found: list[dict[str, Any]] = []
        start = 0
        for _page in range(MAX_SEARCH_PAGES):
            data = await self._get_json(SEARCH_PATH, query=query, start=start, limit=SEARCH_PAGE)
            page = [item for item in data.get("messages") or [] if isinstance(item, dict)]
            if not page:
                break
            found.extend(page)
            reported = data.get("messages_count")
            if isinstance(reported, int) and len(found) >= reported:
                break
            start += len(page)
        return found

    async def list_inbox(self, mailbox: str) -> Inbox:
        """Every message addressed to `mailbox`, newest first.

        Mailpit's `to:` search is a substring match, so it answers with a
        lookalike address as well. The exact recipient check on the parsed `To`
        list is what keeps `notsupport@acme.test` and
        `support@acme.test.evil` out of the result.
        """
        if not mailbox.strip():
            raise MailError("mailbox must not be empty")
        items = await self._search_all(f"to:{mailbox}")
        messages = [inbox_message_from(item) for item in items if _addressed_to(item, mailbox)]
        return Inbox(mailbox=mailbox, messages=messages)

    async def get_message(self, mailbox: str, message_id: str) -> MessageDetail:
        """One message by Mailpit id, or by the RFC `Message-ID` it carries.

        The mailbox is the resource the call names: it is what the gateway
        authorizes on, and the message is held to it. A message that the mailbox
        search turns up but that does not carry the exact address as a recipient
        is refused rather than returned.
        """
        if not mailbox.strip():
            raise MailError("mailbox must not be empty")
        message_id = _check_message_id(message_id)
        try:
            response = await self._client.get(f"{MESSAGE_PATH}/{message_id}")
        except httpx.HTTPError as error:
            raise MailError(f"mailpit is unreachable at {self._base_url}: {error}") from error
        if response.status_code == 200:
            return self._detail_for_mailbox(response.json(), mailbox, message_id)
        if response.status_code != 404:
            raise MailError(
                f"mailpit GET {MESSAGE_PATH}/{message_id} -> HTTP {response.status_code}"
            )
        found = await self._search_all(f"message-id:{message_id}")
        if not found:
            raise MailError(f"message {message_id!r} not found")
        detail = await self._get_json(f"{MESSAGE_PATH}/{found[0].get('ID', '')}")
        return self._detail_for_mailbox(detail, mailbox, message_id)

    def _detail_for_mailbox(
        self, item: dict[str, Any], mailbox: str, message_id: str
    ) -> MessageDetail:
        """One fetched message, refused unless `mailbox` is one of its recipients."""
        if not _addressed_to(item, mailbox):
            raise MailError(f"message {message_id!r} is not addressed to {mailbox!r}")
        return message_detail_from(item)


def build_mail(settings: MailSettings) -> MailpitMail:
    """The Mailpit client this server's settings name, without connecting."""
    return MailpitMail(
        base_url=settings.mail_url,
        from_address=settings.mail_from,
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
    )
