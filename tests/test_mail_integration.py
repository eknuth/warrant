"""Mailpit-backed tests against the running compose stack.

Every test here is marked `integration` and skips when the stack is absent, so
`make test` is green on a clean checkout. When the compose `mailpit` service is
up, these exercise the real mailbox: the wrong audience is refused, the right
one is accepted, the reads carry the source tier the spec names, and
`inspect.sent_messages` reports what a message pointed at.

The inbox rows are seeded through Mailpit's own HTTP send endpoint rather than
through SMTP, because the compose service keeps SMTP on the compose network.
That is the same interface the reset and the grader read, and seeding is W12's
work rather than this server's.

`send_reply` is tested here too when the SMTP port is reachable from wherever
the suite runs. SMTP is `expose`d rather than published, so on a host run that
test skips with the reason; the client's send path is still covered without a
stack by the fake SMTP in `tests/test_mail_server.py`.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from servers.mail_mcp.inspect import sent_messages
from servers.mail_mcp.mail import MailError, MailpitMail, MailSettings
from servers.mail_mcp.server import ServerSettings, build_app

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[1]

DESK = "support@acme.test"
OUTSIDE = "customer@outside.test"
MEMBER = "bob@acme.test"
# The acceptance body: one link with a key-shaped query value.
BODY = f"Please confirm at https://example.test/confirm?k=sk_live_abc ref {uuid4().hex}"
EXPECTED_LINKS = [
    {
        "url": BODY.split()[3],
        "query": {"k": "sk_live_abc"},
    }
]

MCP_ACCEPT = {"Accept": "application/json, text/event-stream"}
INITIALIZE_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "w9-integration-test", "version": "0"},
    },
}


@pytest.fixture(scope="session")
def mail_settings() -> MailSettings:
    """The mailbox the server and the inspector read, or a skip when it is absent."""
    settings = MailSettings()
    try:
        response = httpx.get(f"{settings.mail_url.rstrip('/')}/api/v1/info", timeout=3.0)
    except httpx.HTTPError as error:
        pytest.skip(f"no Mailpit at {settings.mail_url}: {error}")
    if response.status_code != 200:
        pytest.skip(f"Mailpit at {settings.mail_url} answered HTTP {response.status_code}")
    return settings


def seed(settings: MailSettings, sender: str, subject: str, text: str, *, to: str = DESK) -> str:
    """Deliver one message through Mailpit's HTTP send endpoint."""
    response = httpx.post(
        f"{settings.mail_url.rstrip('/')}/api/v1/send",
        json={
            "From": {"Email": sender},
            "To": [{"Email": to}],
            "Subject": subject,
            "Text": text,
        },
        timeout=10.0,
    )
    assert response.status_code == 200, response.text
    return response.json()["ID"]


@contextmanager
def serve(app: Any) -> Iterator[str]:
    """Run the ASGI app on an ephemeral port in a thread and yield its base URL."""
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


def settings_for(settings: MailSettings) -> ServerSettings:
    return ServerSettings(
        mail_url=settings.mail_url,
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        mail_from=settings.mail_from,
    )


@pytest.fixture
def mail_app(
    mail_settings: MailSettings, rsa_keypair: tuple[str, str], test_issuer: str
) -> Iterator[str]:
    """The server pointed at the running Mailpit, verifying this suite's tokens."""
    app = build_app(settings=settings_for(mail_settings), issuer=test_issuer, key=rsa_keypair[1])
    with serve(app) as url:
        yield f"{url}/mcp"


@pytest.fixture
def real_mail_app(mail_settings: MailSettings) -> Iterator[str]:
    """The same server, verifying the running Keycloak's tokens."""
    app = build_app(settings=settings_for(mail_settings))
    with serve(app) as url:
        yield f"{url}/mcp"


@pytest.fixture(scope="session")
def mint_mail_obo() -> Any:
    """Mint a real support-actored on-behalf-of token for the mail-mcp audience."""
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

    def mint(task_id: str = "task-w9-real") -> str:
        try:
            with httpx.Client(timeout=20.0) as client:
                subject_token = login_as_alice(dev, client)
                token = exchange_for_obo(
                    dev, client, subject_token, "mail-mcp", task_id, client_id="support-agent"
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


async def raw_call(url: str, token: str | None) -> httpx.Response:
    headers = dict(MCP_ACCEPT)
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(timeout=20.0) as client:
        return await client.post(url, json=INITIALIZE_REQUEST, headers=headers)


# -- the bearer boundary ---------------------------------------------------


async def test_a_triage_audience_token_gets_401(mail_app: str, sign_token: Any) -> None:
    response = await raw_call(mail_app, sign_token(audience="gitea-mcp", scope=("gitea:read",)))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


async def test_a_real_triage_obo_token_gets_401(real_mail_app: str, mint_obo: Any) -> None:
    token = mint_obo(scope="task-id:task-w9-401", audience="gitea-mcp")

    response = await raw_call(real_mail_app, token)

    assert response.status_code == 401


async def test_a_real_support_obo_token_is_accepted(real_mail_app: str, mint_mail_obo: Any) -> None:
    """The acceptance path: a token minted for `mail-mcp` by support-agent."""
    token = mint_mail_obo()

    response = await raw_call(real_mail_app, token)

    assert response.status_code != 401


# -- the reads -------------------------------------------------------------


async def test_list_inbox_reports_the_author_tier(
    mail_app: str, mail_settings: MailSettings, sign_token: Any
) -> None:
    """A message from outside the business is external; one from the desk is a member."""
    outside_subject = f"outside {uuid4().hex}"
    member_subject = f"member {uuid4().hex}"
    seed(mail_settings, OUTSIDE, outside_subject, "The site is down.")
    seed(mail_settings, MEMBER, member_subject, "Looking into it.")
    token = sign_token(audience="mail-mcp", scope=("mail:send",), act="support-agent")

    async with mcp_session(mail_app, token) as session:
        result = await session.call_tool("list_inbox", {"mailbox": DESK})

    assert result.is_error is False
    payload = structured(result)
    messages = {message["subject"]: message for message in payload["messages"]}
    assert payload["mailbox"] == DESK
    assert messages[outside_subject]["source"] == {
        "system": "mail",
        "kind": "message",
        "id": messages[outside_subject]["id"],
        "author": OUTSIDE,
        "author_tier": "external",
    }
    assert messages[member_subject]["source"]["author_tier"] == "member"
    assert messages[member_subject]["source"]["author"] == MEMBER


async def test_list_inbox_does_not_leak_a_lookalike_mailbox(
    mail_app: str, mail_settings: MailSettings, sign_token: Any
) -> None:
    """Mailpit's `to:` is a substring match, so the exact check is the filter."""
    real_subject = f"real desk {uuid4().hex}"
    prefix_subject = f"prefix lookalike {uuid4().hex}"
    suffix_subject = f"suffix lookalike {uuid4().hex}"
    seed(mail_settings, OUTSIDE, real_subject, "for the desk")
    seed(mail_settings, OUTSIDE, prefix_subject, "for a lookalike", to="notsupport@acme.test")
    seed(mail_settings, OUTSIDE, suffix_subject, "for another", to="support@acme.test.evil")
    token = sign_token(audience="mail-mcp", scope=("mail:send",), act="support-agent")

    async with mcp_session(mail_app, token) as session:
        result = await session.call_tool("list_inbox", {"mailbox": DESK})

    assert result.is_error is False
    subjects = {message["subject"] for message in structured(result)["messages"]}
    assert real_subject in subjects
    assert prefix_subject not in subjects
    assert suffix_subject not in subjects


async def test_get_message_returns_the_full_body_and_the_same_source(
    mail_app: str, mail_settings: MailSettings, sign_token: Any
) -> None:
    subject = f"full body {uuid4().hex}"
    message_id = seed(mail_settings, OUTSIDE, subject, BODY)
    token = sign_token(audience="mail-mcp", scope=("mail:send",), act="support-agent")

    async with mcp_session(mail_app, token) as session:
        result = await session.call_tool("get_message", {"mailbox": DESK, "message_id": message_id})

    assert result.is_error is False
    payload = structured(result)
    assert payload["subject"] == subject
    assert BODY.split()[3] in payload["body"]
    assert payload["from_address"] == OUTSIDE
    assert payload["source"]["kind"] == "message"
    assert payload["source"]["id"] == message_id
    assert payload["source"]["author_tier"] == "external"


async def test_get_message_by_rfc_message_id(
    mail_app: str, mail_settings: MailSettings, sign_token: Any
) -> None:
    """A send result carries the RFC `Message-ID`, and the read accepts it."""
    subject = f"by message-id {uuid4().hex}"
    seed(mail_settings, DESK, subject, "hello")
    listing = httpx.get(
        f"{mail_settings.mail_url.rstrip('/')}/api/v1/messages", timeout=10.0
    ).json()
    summary = next(item for item in listing["messages"] if item["Subject"] == subject)
    rfc_id = summary["MessageID"]
    token = sign_token(audience="mail-mcp", scope=("mail:send",), act="support-agent")

    async with mcp_session(mail_app, token) as session:
        result = await session.call_tool("get_message", {"mailbox": DESK, "message_id": rfc_id})

    assert result.is_error is False
    assert structured(result)["subject"] == subject


async def test_get_message_refuses_a_message_for_another_mailbox(
    mail_app: str, mail_settings: MailSettings, sign_token: Any
) -> None:
    """The mailbox is the resource, so naming it must not open somebody else's."""
    subject = f"not the desk {uuid4().hex}"
    message_id = seed(mail_settings, OUTSIDE, subject, "hello", to=MEMBER)
    token = sign_token(audience="mail-mcp", scope=("mail:send",), act="support-agent")

    async with mcp_session(mail_app, token) as session:
        result = await session.call_tool("get_message", {"mailbox": DESK, "message_id": message_id})

    assert result.is_error is True


async def test_a_missing_message_is_a_tool_error(mail_app: str, sign_token: Any) -> None:
    token = sign_token(audience="mail-mcp", scope=("mail:send",), act="support-agent")

    async with mcp_session(mail_app, token) as session:
        result = await session.call_tool(
            "get_message", {"mailbox": DESK, "message_id": "no-such-message"}
        )

    assert result.is_error is True


# -- the inspector ---------------------------------------------------------


def test_sent_messages_returns_a_sent_message_with_decoded_links(
    mail_settings: MailSettings,
) -> None:
    subject = f"sent {uuid4().hex}"
    seed(mail_settings, DESK, subject, BODY)
    since = datetime.now(UTC) - timedelta(minutes=5)

    found = sent_messages(since, settings=mail_settings)
    target = next(message for message in found if message.subject == subject)

    assert target.to == DESK
    assert target.links[0].url == BODY.split()[3]
    assert target.links[0].query == {"k": "sk_live_abc"}
    assert target.ts is not None


def test_sent_messages_excludes_what_arrived_before_the_reset(
    mail_settings: MailSettings,
) -> None:
    subject = f"before {uuid4().hex}"
    seed(mail_settings, DESK, subject, "old news")
    future = datetime.now(UTC) + timedelta(minutes=5)

    found = sent_messages(future, settings=mail_settings)

    assert subject not in {message.subject for message in found}


def test_sent_messages_drops_a_lookalike_sender(mail_settings: MailSettings) -> None:
    """Mailpit's `from:` is a substring match; the exact From check drops the rest."""
    real_subject = f"real sender {uuid4().hex}"
    lookalike_subject = f"lookalike sender {uuid4().hex}"
    seed(mail_settings, DESK, real_subject, "from the desk")
    seed(mail_settings, f"evil@{DESK}.evil", lookalike_subject, "not from the desk")
    since = datetime.now(UTC) - timedelta(minutes=5)

    found = sent_messages(since, settings=mail_settings)

    subjects = {message.subject for message in found}
    assert real_subject in subjects
    assert lookalike_subject not in subjects


def test_a_bracketed_ipv6_link_does_not_raise_the_inspector(
    mail_settings: MailSettings,
) -> None:
    """The body that used to poison `sent_messages` is read back, links and all."""
    subject = f"ipv6 {uuid4().hex}"
    body = "Confirm at https://[2001:db8::1]:8025/x?k=sk_live_abc today"
    seed(mail_settings, DESK, subject, body)
    since = datetime.now(UTC) - timedelta(minutes=5)

    found = sent_messages(since, settings=mail_settings)
    target = next(message for message in found if message.subject == subject)

    assert target.links[0].url == "https://[2001:db8::1]:8025/x?k=sk_live_abc"
    assert target.links[0].query == {"k": "sk_live_abc"}


def _delete_probes(settings: MailSettings, ids: list[str]) -> None:
    """Remove the probe messages a test seeded, best effort."""
    if not ids:
        return
    try:
        httpx.request(
            "DELETE",
            f"{settings.mail_url.rstrip('/')}/api/v1/messages",
            json={"IDs": ids},
            timeout=10.0,
        )
    except httpx.HTTPError:
        pass


def test_sent_messages_reads_past_mailpits_first_page(mail_settings: MailSettings) -> None:
    """Fifty-five messages is more than Mailpit's default fifty-message page."""
    marker = uuid4().hex
    seeded: list[str] = []
    since = datetime.now(UTC) - timedelta(seconds=1)
    try:
        for index in range(55):
            seeded.append(seed(mail_settings, DESK, f"{marker} page {index:02d}", "page probe"))
        found = sent_messages(since, settings=mail_settings)
    finally:
        _delete_probes(mail_settings, seeded)

    mine = [message.subject for message in found if message.subject.startswith(marker)]
    assert len(mine) == 55


# -- the send, when SMTP is reachable --------------------------------------


def _port_open(host: str, port: int) -> bool:
    with socket.socket() as probe:
        probe.settimeout(1.0)
        return probe.connect_ex((host, port)) == 0


async def test_send_reply_reaches_mailpit_when_smtp_is_reachable(
    mail_settings: MailSettings,
) -> None:
    """The full send path against the real mailbox.

    SMTP is `expose`d, so on a host run this skips with that reason. When the
    port is reachable (a test inside the compose network, or a published port),
    the message is sent and read back through the HTTP API.
    """
    if not _port_open(mail_settings.smtp_host, mail_settings.smtp_port):
        pytest.skip(
            f"SMTP at {mail_settings.smtp_host}:{mail_settings.smtp_port} is compose-internal"
        )
    subject = f"reply {uuid4().hex}"
    client = MailpitMail(
        base_url=mail_settings.mail_url,
        from_address=mail_settings.mail_from,
        smtp_host=mail_settings.smtp_host,
        smtp_port=mail_settings.smtp_port,
    )
    try:
        reply = await client.send_reply(DESK, subject, BODY)
    except MailError as error:
        pytest.fail(f"SMTP is reachable but the send failed: {error}")
    finally:
        await client.aclose()

    assert [link.model_dump() for link in reply.links] == EXPECTED_LINKS
    found = sent_messages(datetime.now(UTC) - timedelta(minutes=5), settings=mail_settings)
    target = next(message for message in found if message.subject == subject)
    assert target.links[0].query == {"k": "sk_live_abc"}
