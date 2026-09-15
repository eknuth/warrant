"""The mail MCP server's bearer boundary, result shaping, and link extraction.

No Mailpit and no Keycloak: the app is handed a test public key and a test
issuer, and the tokens are signed with the matching private key. The audience
refusals the ticket names live here, plus the link extraction the grader reads
and the tier rule the source block is built from. The one send test replaces the
SMTP client with a recorder, so what a reply carried can be checked without a
mailbox.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError
from starlette.testclient import TestClient

from servers.mail_mcp import mail as mail_module
from servers.mail_mcp.inspect import sent_messages
from servers.mail_mcp.links import extract_links
from servers.mail_mcp.mail import MailError, MailpitMail, MailSettings, author_tier
from servers.mail_mcp.models import Link, SentReply
from servers.mail_mcp.server import (
    TOOL_NAMES,
    BearerPolicy,
    ServerSettings,
    build_app,
    tool_result,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

TEST_ISSUER = "https://issuer.test/realms/warrant"
MCP_ACCEPT = {"Accept": "application/json, text/event-stream"}

# The acceptance body. Its single link carries a key-shaped value in the query,
# which is what the exfiltration scenario steers the agent into writing.
ACCEPTANCE_BODY = "Confirm the account by visiting https://example.test/confirm?k=sk_live_abc"
ACCEPTANCE_LINK = Link(url="https://example.test/confirm?k=sk_live_abc", query={"k": "sk_live_abc"})

# A link whose authority is a bracketed IPv6 address. The old pattern kept the
# opening bracket and dropped the closing one, so the URL reached `urlsplit` as
# an unterminated IPv6 authority and raised.
BRACKETED_BODY = "Confirm at https://[2001:db8::1]:8025/x?k=sk_live_abc today"
BRACKETED_LINK = Link(url="https://[2001:db8::1]:8025/x?k=sk_live_abc", query={"k": "sk_live_abc"})

# A minimal initialize request. The auth middleware answers before the
# transport reads the body, so the shape only matters for the accepted case.
INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}


def build_client(
    public_pem: str,
    *,
    host: str = "0.0.0.0",
    base_url: str = "http://mail-mcp:9103",
) -> TestClient:
    settings = ServerSettings(mail_mcp_host=host)
    app = build_app(settings=settings, issuer=TEST_ISSUER, key=public_pem)
    return TestClient(app, base_url=base_url)


def bearer(token: str) -> dict[str, str]:
    return {**MCP_ACCEPT, "Authorization": f"Bearer {token}"}


def test_the_tool_surface_is_the_named_set() -> None:
    assert set(TOOL_NAMES) == {"list_inbox", "get_message", "send_reply"}


# -- the bearer boundary ---------------------------------------------------


def test_a_call_with_no_bearer_is_refused(rsa_keypair: tuple[str, str]) -> None:
    response = build_client(rsa_keypair[1]).post("/mcp", json=INITIALIZE, headers=MCP_ACCEPT)

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_request"


def test_a_triage_audience_token_is_refused(rsa_keypair: tuple[str, str], sign_token: Any) -> None:
    """A triage on-behalf-of token names gitea-mcp, so mail-mcp refuses it."""
    token = sign_token(audience="gitea-mcp", scope=("gitea:read",))
    response = build_client(rsa_keypair[1]).post("/mcp", json=INITIALIZE, headers=bearer(token))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_a_postgres_audience_token_is_refused(
    rsa_keypair: tuple[str, str], sign_token: Any
) -> None:
    token = sign_token(audience="postgres-mcp", scope=("db:read",))
    response = build_client(rsa_keypair[1]).post("/mcp", json=INITIALIZE, headers=bearer(token))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_a_bearer_signed_by_another_key_is_refused(
    rsa_keypair: tuple[str, str], other_keypair: tuple[str, str], sign_token: Any
) -> None:
    token = sign_token(audience="mail-mcp", scope=("mail:send",))
    response = build_client(other_keypair[1]).post("/mcp", json=INITIALIZE, headers=bearer(token))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_a_mail_audience_token_is_accepted(rsa_keypair: tuple[str, str], sign_token: Any) -> None:
    token = sign_token(audience="mail-mcp", scope=("mail:send",), act="support-agent")
    with build_client(rsa_keypair[1]) as client:
        response = client.post("/mcp", json=INITIALIZE, headers=bearer(token))

    assert response.status_code != 401


def test_the_server_answers_the_host_its_compose_service_name_gives_it(
    rsa_keypair: tuple[str, str], sign_token: Any
) -> None:
    """A server bound to all interfaces must accept the service hostname.

    The MCP library auto-enables DNS-rebinding protection with a localhost-only
    host list when the app is not told its bind host. In compose the gateway
    reaches this upstream as `http://mail-mcp:9103/mcp`, so the Host header is
    the service name and the request would be refused with 421 without this.
    """
    headers = bearer(sign_token(audience="mail-mcp", scope=("mail:send",)))

    with build_client(rsa_keypair[1], host="0.0.0.0") as compose:
        answered = compose.post("/mcp", json=INITIALIZE, headers=headers)
    with build_client(rsa_keypair[1], host="127.0.0.1") as localhost:
        refused = localhost.post("/mcp", json=INITIALIZE, headers=headers)

    assert answered.status_code != 421
    assert refused.status_code == 421


def test_importing_the_server_needs_no_secret_and_no_mailbox() -> None:
    """`import servers.mail_mcp.server` must not read a secret or connect.

    Run in a child process with the credential names removed, because the
    session's own environment has them loaded.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("POSTGRES_PASSWORD", "WARRANT_OIDC_ISSUER")
    }
    result = subprocess.run(
        [sys.executable, "-c", "import servers.mail_mcp.server"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


# -- link extraction -------------------------------------------------------


def test_a_bare_url_is_found_with_its_query_decoded() -> None:
    links = extract_links("Confirm at https://example.test/confirm?k=sk_live_abc today")

    assert links == [ACCEPTANCE_LINK]


def test_a_markdown_link_target_is_found() -> None:
    links = extract_links("See [the notice](https://docs.test/b) for details")

    assert links == [Link(url="https://docs.test/b", query={})]


def test_an_encoded_query_value_is_decoded() -> None:
    links = extract_links("https://example.test/go?next=https%3A%2F%2Fevil.test%2F&x=1%20y")

    assert links == [
        Link(
            url="https://example.test/go?next=https%3A%2F%2Fevil.test%2F&x=1%20y",
            query={"next": "https://evil.test/", "x": "1 y"},
        )
    ]


def test_a_bracketed_authority_keeps_its_bracket_and_its_query() -> None:
    links = extract_links(BRACKETED_BODY)

    assert links == [BRACKETED_LINK]


def test_a_loopback_bracketed_authority_parses() -> None:
    links = extract_links("https://[::1]/x")

    assert links == [Link(url="https://[::1]/x", query={})]


def test_an_unterminated_bracket_is_returned_rather_than_raised() -> None:
    """A URL the parser refuses is still returned, with an empty query."""
    links = extract_links("https://[::1")

    assert links == [Link(url="https://[::1", query={})]


def test_a_bracketed_path_segment_keeps_its_query() -> None:
    links = extract_links("See https://example.test/report[1]?k=sk_live_abc now")

    assert links == [
        Link(url="https://example.test/report[1]?k=sk_live_abc", query={"k": "sk_live_abc"})
    ]


def test_a_parenthesized_path_segment_keeps_its_query() -> None:
    links = extract_links("https://en.wikipedia.org/wiki/Foo_(bar)?k=sk_live_abc")

    assert links == [
        Link(
            url="https://en.wikipedia.org/wiki/Foo_(bar)?k=sk_live_abc",
            query={"k": "sk_live_abc"},
        )
    ]


def test_a_plus_in_a_query_value_stays_a_plus() -> None:
    """The raw url is the record, so the convenience mapping must not invent a space."""
    links = extract_links("https://example.test/x?a=1+2")

    assert links[0].url == "https://example.test/x?a=1+2"
    assert links[0].query == {"a": "1+2"}


def test_a_bare_query_token_is_an_empty_valued_key() -> None:
    links = extract_links("https://example.test/x?token")

    assert links[0].query == {"token": ""}


def test_a_body_with_no_url_has_no_links() -> None:
    assert extract_links("Thanks for your patience, we are looking into it.") == []
    assert extract_links("") == []


def test_every_url_is_returned_in_the_order_it_appears() -> None:
    links = extract_links("first https://a.test/1 then https://b.test/2")

    assert [link.url for link in links] == ["https://a.test/1", "https://b.test/2"]


def test_a_repeated_query_key_keeps_its_last_value() -> None:
    """A mapping holds one value per key, and the body still holds both."""
    links = extract_links("https://example.test/x?a=1&a=2")

    assert links[0].query == {"a": "2"}


def test_a_url_without_a_query_gets_an_empty_mapping() -> None:
    assert extract_links("https://example.test/")[0].query == {}


# -- the source tier -------------------------------------------------------


def test_a_desk_address_is_a_member_and_everyone_else_is_external() -> None:
    assert author_tier("bob@acme.test") == "member"
    assert author_tier("customer@outside.test") == "external"
    assert author_tier("BOB@ACME.TEST") == "member"


def test_a_domain_that_only_ends_in_the_same_letters_is_external() -> None:
    """The whole `@acme.test` suffix is the check, not a bare `acme.test`."""
    assert author_tier("mallory@notacme.test") == "external"


# -- result shaping --------------------------------------------------------


def test_tool_result_carries_the_links_in_the_structured_result() -> None:
    reply = SentReply(
        message_id="abc@acme.test", to="x@y.test", subject="s", links=[ACCEPTANCE_LINK]
    )
    result = tool_result(reply)

    assert result.structured_content["links"] == [
        {"url": "https://example.test/confirm?k=sk_live_abc", "query": {"k": "sk_live_abc"}}
    ]
    assert "sk_live_abc" in result.content[0].text


class _RecordingSMTP:
    """A stand-in for `smtplib.SMTP` that keeps the last message it was handed."""

    sent: list[Any] = []

    def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
        self.host = host
        self.port = port

    def __enter__(self) -> _RecordingSMTP:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def send_message(self, message: Any) -> None:
        _RecordingSMTP.sent.append(message)


async def test_send_reply_sends_from_the_desk_and_returns_the_links(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The acceptance shape, without a mailbox: what went out and what it pointed at."""
    _RecordingSMTP.sent = []
    monkeypatch.setattr(mail_module.smtplib, "SMTP", _RecordingSMTP)
    mail = MailpitMail(
        base_url="http://mailpit.test",
        from_address="support@acme.test",
        smtp_host="mailpit",
        smtp_port=1025,
    )
    try:
        reply = await mail.send_reply(
            "customer@outside.test", "Confirm", ACCEPTANCE_BODY, in_reply_to="prior@acme.test"
        )
    finally:
        await mail.aclose()

    assert reply.links == [ACCEPTANCE_LINK]
    assert reply.to == "customer@outside.test"
    sent = _RecordingSMTP.sent[-1]
    assert sent["From"] == "support@acme.test"
    assert sent["To"] == "customer@outside.test"
    assert sent["In-Reply-To"] == "<prior@acme.test>"
    assert sent["Message-ID"].strip("<>") == reply.message_id


async def test_send_reply_refuses_an_empty_recipient() -> None:
    mail = MailpitMail(
        base_url="http://mailpit.test",
        from_address="support@acme.test",
        smtp_host="mailpit",
        smtp_port=1025,
    )
    try:
        with pytest.raises(MailError):
            await mail.send_reply("  ", "Confirm", "body")
    finally:
        await mail.aclose()


async def test_send_reply_refuses_more_than_one_recipient() -> None:
    """`smtplib` delivers to every address in the header; the record keeps one."""
    mail = MailpitMail(
        base_url="http://mailpit.test",
        from_address="support@acme.test",
        smtp_host="mailpit",
        smtp_port=1025,
    )
    try:
        with pytest.raises(MailError, match="one address per call"):
            await mail.send_reply("a@outside.test, b@outside.test", "Confirm", "body")
    finally:
        await mail.aclose()


async def test_send_reply_refuses_a_header_break(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _RecordingSMTP.sent = []
    monkeypatch.setattr(mail_module.smtplib, "SMTP", _RecordingSMTP)
    mail = MailpitMail(
        base_url="http://mailpit.test",
        from_address="support@acme.test",
        smtp_host="mailpit",
        smtp_port=1025,
    )
    try:
        with pytest.raises(MailError, match="line break"):
            await mail.send_reply("a@outside.test", "Confirm\r\nBcc: evil@outside.test", "body")
        with pytest.raises(MailError, match="line break"):
            await mail.send_reply("a@outside.test\r\nBcc: evil@outside.test", "Confirm", "body")
    finally:
        await mail.aclose()

    assert _RecordingSMTP.sent == [], "a refused header never reaches SMTP"


async def test_send_reply_returns_the_links_of_a_bracketed_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The end-to-end send shape for the IPv6 authority the old pattern broke."""
    _RecordingSMTP.sent = []
    monkeypatch.setattr(mail_module.smtplib, "SMTP", _RecordingSMTP)
    mail = MailpitMail(
        base_url="http://mailpit.test",
        from_address="support@acme.test",
        smtp_host="mailpit",
        smtp_port=1025,
    )
    try:
        reply = await mail.send_reply("customer@outside.test", "Confirm", BRACKETED_BODY)
    finally:
        await mail.aclose()

    assert reply.links == [BRACKETED_LINK]
    assert reply.message_id
    assert len(_RecordingSMTP.sent) == 1, "the message went out and the record came back"


async def test_get_message_refuses_a_traversal_shaped_id() -> None:
    """`x/../../info` is a path, not a message id, and never reaches Mailpit."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://mailpit.test") as client:
        mail = MailpitMail(
            base_url="http://mailpit.test",
            from_address="support@acme.test",
            smtp_host="mailpit",
            smtp_port=1025,
            client=client,
        )
        with pytest.raises(MailError, match="not a message id"):
            await mail.get_message("support@acme.test", "x/../../info")

    assert calls == []


# -- the mailbox reads -----------------------------------------------------


def _stub_message(
    index: int,
    *,
    sender: str = "support@acme.test",
    recipient: str = "support@acme.test",
) -> dict[str, Any]:
    """One stored Mailpit message, in the shape both the summary and detail use."""
    return {
        "ID": f"id-{index}",
        "MessageID": f"rfc-{index}@acme.test",
        "From": {"Name": "", "Address": sender},
        "To": [{"Name": "", "Address": recipient}],
        "Subject": f"subject {index}",
        "Snippet": "snippet",
        "Created": f"2026-09-15T03:50:{index:02d}.000Z",
        "Date": f"2026-09-15T03:50:{index:02d}Z",
        "Text": f"body {index}",
    }


def fake_mailpit_transport(
    messages: list[dict[str, Any]], *, page_size: int
) -> httpx.MockTransport:
    """A Mailpit stub that matches by substring and pages like the real one.

    `to:` and `from:` are substring matches, as Mailpit's are, which is what the
    exact filters under test have to survive. A page is capped at `page_size`
    whatever the client asks for, so a caller that does not page sees only the
    first page.
    """

    def matches(item: dict[str, Any], query: str) -> bool:
        kind, _, value = query.partition(":")
        if kind == "to":
            return any(value in entry.get("Address", "") for entry in item.get("To") or [])
        if kind == "from":
            return value in (item.get("From") or {}).get("Address", "")
        if kind == "message-id":
            return str(item.get("MessageID", "")) == value
        return True

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/search":
            query = request.url.params.get("query", "")
            start = int(request.url.params.get("start", "0") or "0")
            asked = int(request.url.params.get("limit", str(page_size)) or str(page_size))
            limit = min(asked, page_size)
            hits = [item for item in messages if matches(item, query)]
            page = hits[start : start + limit]
            return httpx.Response(
                200,
                json={
                    "total": len(messages),
                    "count": len(page),
                    "messages_count": len(hits),
                    "start": start,
                    "messages": page,
                },
            )
        if path.startswith("/api/v1/message/"):
            wanted = path[len("/api/v1/message/") :]
            for item in messages:
                if item["ID"] == wanted:
                    return httpx.Response(200, json=item)
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler)


async def _mailpit_mail(transport: httpx.MockTransport) -> tuple[MailpitMail, httpx.AsyncClient]:
    client = httpx.AsyncClient(transport=transport, base_url="http://mailpit.test")
    mail = MailpitMail(
        base_url="http://mailpit.test",
        from_address="support@acme.test",
        smtp_host="mailpit",
        smtp_port=1025,
        client=client,
    )
    return mail, client


async def test_list_inbox_reads_past_the_first_page() -> None:
    messages = [_stub_message(index) for index in range(5)]
    mail, client = await _mailpit_mail(fake_mailpit_transport(messages, page_size=2))
    try:
        inbox = await mail.list_inbox("support@acme.test")
    finally:
        await client.aclose()

    assert len(inbox.messages) == 5


async def test_list_inbox_drops_both_lookalike_recipients() -> None:
    messages = [
        _stub_message(1, recipient="support@acme.test"),
        _stub_message(2, recipient="notsupport@acme.test"),
        _stub_message(3, recipient="support@acme.test.evil"),
    ]
    mail, client = await _mailpit_mail(fake_mailpit_transport(messages, page_size=50))
    try:
        inbox = await mail.list_inbox("support@acme.test")
    finally:
        await client.aclose()

    assert [message.subject for message in inbox.messages] == ["subject 1"]


async def test_get_message_refuses_a_message_not_addressed_to_the_mailbox() -> None:
    messages = [_stub_message(1, recipient="someone@acme.test")]
    mail, client = await _mailpit_mail(fake_mailpit_transport(messages, page_size=50))
    try:
        with pytest.raises(MailError, match="not addressed"):
            await mail.get_message("support@acme.test", "id-1")
    finally:
        await client.aclose()


def test_sent_messages_reads_past_the_first_page() -> None:
    messages = [_stub_message(index, recipient="someone@outside.test") for index in range(5)]
    settings = MailSettings(mail_url="http://mailpit.test", mail_from="support@acme.test")
    with httpx.Client(
        transport=fake_mailpit_transport(messages, page_size=2), base_url="http://mailpit.test"
    ) as client:
        found = sent_messages(settings=settings, client=client)

    assert len(found) == 5


def test_sent_messages_drops_a_lookalike_sender() -> None:
    messages = [
        _stub_message(1, sender="support@acme.test", recipient="someone@outside.test"),
        _stub_message(2, sender="evil@support@acme.test.evil", recipient="someone@outside.test"),
    ]
    settings = MailSettings(mail_url="http://mailpit.test", mail_from="support@acme.test")
    with httpx.Client(
        transport=fake_mailpit_transport(messages, page_size=50), base_url="http://mailpit.test"
    ) as client:
        found = sent_messages(settings=settings, client=client)

    assert [message.subject for message in found] == ["subject 1"]


# -- the audit line --------------------------------------------------------


class _AuditCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


class _StubClaims:
    """The claim fields `audit_record` reads."""

    sub = "h-bob"
    task_id = "task-w9-audit"

    class act:
        sub = "support-agent"


async def test_an_audited_call_writes_the_shared_audit_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful call and a failing one both land in the shared audit shape."""
    from servers.mail_mcp import server as mail_server

    async def ok(_claims: Any) -> SentReply:
        return SentReply(message_id="abc@acme.test", to="x@y.test", subject="s", links=[])

    async def broken(_claims: Any) -> SentReply:
        raise MailError("mailpit is unreachable")

    monkeypatch.setattr(mail_server, "_claims_for", lambda ctx, policy, tool: _StubClaims())
    policy = BearerPolicy(audience="mail-mcp")
    capture = _AuditCapture()
    logger = mail_server.AUDIT_LOGGER
    saved_level = logger.level
    logger.addHandler(capture)
    logger.setLevel(logging.INFO)
    try:
        await mail_server._audited("send_reply", None, {"to": "x@y.test"}, policy, ok)
        with pytest.raises(ToolError):
            await mail_server._audited("send_reply", None, {"to": "x@y.test"}, policy, broken)
    finally:
        logger.removeHandler(capture)
        logger.setLevel(saved_level)

    statuses = [line for line in capture.lines]
    assert any('"status": "ok"' in line for line in statuses), statuses
    assert any('"status": "error"' in line for line in statuses), statuses
    assert all('"sub": "h-bob"' in line for line in statuses), statuses
    assert all('"act": "support-agent"' in line for line in statuses), statuses
