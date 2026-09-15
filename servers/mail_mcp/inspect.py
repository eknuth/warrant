"""What left the mailbox, read straight from Mailpit.

The grader (W14) and the scenario reset (W12) both need the same answer: which
messages did the server send, what did they say, and what did they point at.
This module is that answer, and it is deliberately outside the MCP server. It
holds no token and starts no process: it reads Mailpit's HTTP API with the
addresses from `.env`, so a caller that only wants to look at the mailbox does
not have to authenticate to anything.

`sent_messages` is a plain function rather than an async one, because its
callers are scripts. It rebuilds each message from the body Mailpit stored and
runs the same link extraction `send_reply` used, so a check on a link is a check
on what crossed the wire.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from .links import extract_links
from .mail import MailError, MailSettings, normalize_since, parse_created
from .models import SentMessage

# Re-exported so a caller can name the record it gets back from this module.
__all__ = ["SentMessage", "MailError", "sent_messages"]

SEARCH_PATH = "/api/v1/search"
MESSAGE_PATH = "/api/v1/message"


def sent_messages(
    since_ts: datetime | str | float | int | None = None,
    *,
    settings: MailSettings | None = None,
    client: httpx.Client | None = None,
) -> list[SentMessage]:
    """Every message the desk address sent, oldest first, at or after `since_ts`.

    `since_ts` takes a datetime, an ISO 8601 string, or Unix seconds; None means
    everything Mailpit still holds. A client may be passed in, which is what lets
    a test hand this function a stub transport; the caller owns that client.

    The filter is on the timestamp Mailpit recorded for the received message, not
    on a clock read here, so a message that arrived just after the reset is
    excluded by the reset's own start rather than by a race.
    """
    settings = settings or MailSettings()
    since = normalize_since(since_ts)
    owns_client = client is None
    http = client or httpx.Client(base_url=settings.mail_url.rstrip("/"), timeout=15.0)
    try:
        summaries = _search(http, f"from:{settings.mail_from}")
        found: list[SentMessage] = []
        for summary in summaries:
            created = parse_created(summary.get("Created") or summary.get("Date"))
            if since is not None and (created is None or created < since):
                continue
            detail = _get_json(http, f"{MESSAGE_PATH}/{summary.get('ID', '')}")
            found.append(_sent_from(detail))
        found.sort(key=lambda message: message.ts or datetime.min.replace(tzinfo=UTC))
        return found
    finally:
        if owns_client:
            http.close()


def _search(client: httpx.Client, query: str) -> list[dict[str, Any]]:
    data = _get_json(client, SEARCH_PATH, query=query)
    return [item for item in data.get("messages") or [] if isinstance(item, dict)]


def _get_json(client: httpx.Client, path: str, **params: Any) -> Any:
    try:
        response = client.get(path, params=params or None)
    except httpx.HTTPError as error:
        raise MailError(f"mailpit is unreachable: {error}") from error
    if response.status_code >= 400:
        raise MailError(f"mailpit GET {path} -> HTTP {response.status_code}")
    return response.json()


def _sent_from(item: dict[str, Any]) -> SentMessage:
    """One full Mailpit message as a `SentMessage`."""
    recipients = [
        str(entry.get("Address", "")) for entry in item.get("To") or [] if isinstance(entry, dict)
    ]
    body = str(item.get("Text") or item.get("HTML") or "")
    return SentMessage(
        to=recipients[0] if recipients else "",
        subject=str(item.get("Subject", "")),
        body=body,
        links=extract_links(body),
        ts=parse_created(item.get("Date") or item.get("Created")),
    )
