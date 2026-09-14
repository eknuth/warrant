"""The gateway's request path, with a fake engine and a fake upstream.

Two layers are faked so the tests can name one behavior each. The engine is a
class that returns a chosen verdict and appends the decision the way the Cedar
engine does, so a line appears in `decisions.jsonl` for every evaluated call.
The upstream is either a fake client (for the verdict tests) or a real MCP
server on an ephemeral port behind the real streamable-HTTP client (for the
discovery, forwarding, and read-tagging tests).

Nothing here reaches Keycloak, Gitea, or the model.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent, Tool
from starlette.testclient import TestClient

from warrant import oidc
from warrant.engine import PolicyEngine
from warrant.gateway import (
    Gateway,
    GatewayError,
    GatewaySettings,
    StreamableHTTPUpstream,
    UpstreamServer,
    args_digest,
    build_app,
    extract_sources,
    load_servers,
)
from warrant.graph import Graph
from warrant.graph import load as load_graph
from warrant.log import DecisionLog
from warrant.models import AuthzRequest, Decision, Verdict
from warrant.provenance import Ledger
from warrant.resources import extract_resource, resolve_resource

REPO = Path(__file__).resolve().parents[1]
SEED = REPO / "infra" / "graph.yml"
SERVERS_FILE = REPO / "infra" / "servers.yml"

INITIALIZE_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "w6-gateway-test", "version": "0"},
    },
}
MCP_ACCEPT = {"Accept": "application/json, text/event-stream"}

GITEA = UpstreamServer(
    name="gitea-mcp", prefix="gitea", url="http://127.0.0.1:1/mcp", audience="gitea-mcp"
)


def claims_for(
    *,
    sub: str = "7d05f1c9-b47f-44b7-8356-343bcc0da494",
    act: str = "triage-agent",
    task_id: str | None = "task-1",
    audience: str = "warrant",
    exp_offset: int = 300,
) -> oidc.Claims:
    payload: dict[str, Any] = {
        "sub": sub,
        "act": {"sub": act},
        "azp": act,
        "aud": [audience],
        "scope": "gitea:read",
        "groups": ["owners"],
        "exp": int(time.time()) + exp_offset,
        "iss": "https://issuer.test/realms/warrant",
    }
    if task_id is not None:
        payload["task_id"] = [task_id]
    return oidc.Claims.model_validate(payload)


class FakeEngine:
    """A `PolicyEngine` that returns a chosen verdict and logs it."""

    def __init__(
        self,
        *,
        decision_log: DecisionLog,
        verdict: Verdict = Verdict.allow,
        policy_ids: list[str] | None = None,
        reasons: list[str] | None = None,
    ) -> None:
        self.decision_log = decision_log
        self.verdict = verdict
        self.policy_ids = policy_ids or []
        self.reasons = reasons or []
        self.requests: list[AuthzRequest] = []

    def decide(self, req: AuthzRequest) -> Decision:
        self.requests.append(req)
        decision = Decision(
            verdict=self.verdict,
            policy_ids=list(self.policy_ids),
            reasons=list(self.reasons),
            request=req,
            mode="full",
        )
        self.decision_log.append(decision)
        return decision

    def explain(self, req: AuthzRequest) -> str:
        return f"{req.tool}: {self.verdict.value}"


class FakeUpstream:
    """An `UpstreamClient` that records calls and returns a canned result."""

    def __init__(self, *, tools: list[Tool] | None = None, result: CallToolResult | None = None):
        self.tools = tools or []
        self.result = result or CallToolResult(
            content=[TextContent(type="text", text="{}")], is_error=False
        )
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.bearers: list[str] = []

    async def list_tools(self, server: UpstreamServer, bearer: str) -> list[Tool]:
        self.bearers.append(bearer)
        return list(self.tools)

    async def call_tool(
        self, server: UpstreamServer, name: str, arguments: dict[str, Any], bearer: str
    ) -> CallToolResult:
        self.calls.append((server.name, name, arguments))
        self.bearers.append(bearer)
        return self.result


@pytest.fixture
def graph_db(tmp_path: Path) -> Iterator[Graph]:
    with load_graph(SEED, tmp_path / "warrant.db") as opened:
        yield opened


def make_gateway(
    tmp_path: Path,
    graph: Graph,
    engine: PolicyEngine,
    *,
    servers: list[UpstreamServer] | None = None,
    upstream: Any = None,
    runs_dir: Path | None = None,
    client_secret: str = "",
    exchange_transport: Any = None,
) -> Gateway:
    runs = runs_dir or tmp_path / "runs"
    settings = GatewaySettings(warrant_agent_client_secret=client_secret)
    return Gateway(
        graph=graph,
        engine=engine,
        ledger=Ledger(runs),
        decision_log=engine.decision_log,  # type: ignore[attr-defined]
        servers=servers or [GITEA],
        settings=settings,
        upstream=upstream,
        exchange_transport=exchange_transport,
        runs_dir=runs,
    )


def source_payload(source_id: str = "acme/widgets#1") -> dict[str, Any]:
    return {
        "number": 1,
        "title": "README says port 8080, but the code uses 8081",
        "source": {
            "system": "gitea",
            "kind": "issue",
            "id": source_id,
            "author": "bob",
            "author_tier": "member",
        },
    }


# -- the server list and the resource extractors ---------------------------


def test_load_servers_reads_the_shipped_file() -> None:
    servers = load_servers(SERVERS_FILE)

    assert [(s.name, s.prefix, s.audience) for s in servers] == [
        ("gitea-mcp", "gitea", "gitea-mcp")
    ]


def test_load_servers_refuses_a_file_without_a_servers_list(tmp_path: Path) -> None:
    path = tmp_path / "servers.yml"
    path.write_text("upstreams: []\n")

    with pytest.raises(GatewayError):
        load_servers(path)


def test_load_servers_refuses_a_repeated_prefix(tmp_path: Path) -> None:
    path = tmp_path / "servers.yml"
    path.write_text(
        "servers:\n"
        "  - {name: a, prefix: gitea, url: http://a/mcp, audience: a}\n"
        "  - {name: b, prefix: gitea, url: http://b/mcp, audience: b}\n"
    )

    with pytest.raises(GatewayError, match="prefix"):
        load_servers(path)


def test_a_repo_argument_becomes_the_repository(graph_db: Graph) -> None:
    name = extract_resource("repo", {"repo": "acme/widgets", "number": 1})

    assert name == "acme/widgets"
    assert resolve_resource(graph_db, "repo", name) == "repo-acme-widgets"


def test_a_sql_statement_becomes_its_table(graph_db: Graph) -> None:
    name = extract_resource("db_table", {"sql": "select id from public.orders where id = 1"})

    assert name == "public.orders"
    assert resolve_resource(graph_db, "db_table", name) == "table-orders"


def test_an_explicit_table_argument_wins_over_the_statement() -> None:
    assert extract_resource("db_table", {"table": "public.orders", "sql": "select 1"}) == (
        "public.orders"
    )


def test_a_recipient_becomes_the_mailbox(graph_db: Graph) -> None:
    name = extract_resource("mailbox", {"to": "support@acme.example", "body": "hi"})

    assert resolve_resource(graph_db, "mailbox", name) == "mailbox-support"


def test_an_unknown_resource_name_is_passed_through() -> None:
    assert resolve_resource(None, "repo", "acme/unknown") == "acme/unknown"
    assert resolve_resource(None, "repo", None) == ""


def test_extract_sources_keeps_the_record_that_carried_the_block() -> None:
    payload = {"issue": source_payload(), "other": {"source": source_payload("acme/widgets#2")}}

    found = extract_sources(payload)

    assert [block["id"] for block, _ in found] == ["acme/widgets#1", "acme/widgets#2"]
    assert found[0][1]["number"] == 1


# -- the request path ------------------------------------------------------


async def test_an_allowed_read_is_forwarded_and_its_source_recorded(
    tmp_path: Path, graph_db: Graph
) -> None:
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow, policy_ids=["permit-read"])
    payload = source_payload()
    upstream = FakeUpstream(
        result=CallToolResult(
            content=[TextContent(type="text", text=json.dumps(payload))], is_error=False
        )
    )
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=upstream)

    result = await gateway.call_tool(
        "gitea.get_issue", {"repo": "acme/widgets", "number": 1}, claims=claims_for(), token=""
    )

    assert result is upstream.result
    assert upstream.calls == [("gitea-mcp", "get_issue", {"repo": "acme/widgets", "number": 1})]
    sources = gateway.ledger.get("task-1").sources
    assert [source.id for source in sources] == ["acme/widgets#1"]
    assert sources[0].digest
    assert engine.requests[0].action_kind.value == "read"
    assert engine.requests[0].resource == "repo-acme-widgets"
    assert len(log.read("task-1")) == 1


async def test_a_write_call_takes_its_action_kind_from_the_graph(
    tmp_path: Path, graph_db: Graph
) -> None:
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)
    upstream = FakeUpstream()
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=upstream)

    await gateway.call_tool(
        "gitea.create_issue_comment",
        {"repo": "acme/widgets", "number": 1, "body": "hi"},
        claims=claims_for(),
        token="",
    )

    assert engine.requests[0].action_kind.value == "write"
    assert upstream.calls[0][1] == "create_issue_comment"


async def test_a_denied_call_is_not_forwarded_and_carries_the_reasons(
    tmp_path: Path, graph_db: Graph
) -> None:
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(
        decision_log=log,
        verdict=Verdict.deny,
        policy_ids=["forbid-comment"],
        reasons=["forbid matched: forbid-comment"],
    )
    upstream = FakeUpstream()
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=upstream)

    result = await gateway.call_tool(
        "gitea.get_issue", {"repo": "acme/widgets", "number": 1}, claims=claims_for(), token=""
    )

    assert result.is_error is True
    assert result.content[0].text == "forbid matched: forbid-comment"
    assert upstream.calls == []
    assert len(log.read("task-1")) == 1


async def test_an_escalated_call_returns_pending_and_is_logged(
    tmp_path: Path, graph_db: Graph
) -> None:
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(
        decision_log=log,
        verdict=Verdict.escalate,
        policy_ids=["forbid-read", "escalate-search"],
        reasons=["real action denied: read", "escalate permit matched: escalate-search"],
    )
    upstream = FakeUpstream()
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=upstream)

    result = await gateway.call_tool(
        "gitea.get_issue", {"repo": "acme/widgets", "number": 1}, claims=claims_for(), token=""
    )

    assert result.is_error is True
    assert result.content[0].text == "escalated: pending"
    assert upstream.calls == []
    decisions = log.read("task-1")
    assert len(decisions) == 1
    assert decisions[0].verdict is Verdict.escalate


async def test_an_unknown_agent_is_denied_by_name(tmp_path: Path, graph_db: Graph) -> None:
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=FakeUpstream())

    result = await gateway.call_tool(
        "gitea.get_issue",
        {"repo": "acme/widgets", "number": 1},
        claims=claims_for(act="agent-ghost"),
        token="",
    )

    assert result.is_error is True
    assert result.content[0].text == "unknown agent"
    assert engine.requests == [], "an unknown agent is refused before the engine"
    decisions = log.read("task-1")
    assert len(decisions) == 1
    assert decisions[0].reasons == ["unknown agent"]


async def test_an_unknown_tool_is_denied(tmp_path: Path, graph_db: Graph) -> None:
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log)
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=FakeUpstream())

    result = await gateway.call_tool(
        "gitea.delete_everything", {"repo": "acme/widgets"}, claims=claims_for(), token=""
    )

    assert result.is_error is True
    assert "unknown tool" in result.content[0].text
    assert log.read("task-1") == []


async def test_a_token_with_no_task_id_is_denied(tmp_path: Path, graph_db: Graph) -> None:
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=FakeUpstream())

    result = await gateway.call_tool(
        "gitea.get_issue",
        {"repo": "acme/widgets", "number": 1},
        claims=claims_for(task_id=None),
        token="",
    )

    assert result.is_error is True


# -- provenance comes only from the ledger ---------------------------------


async def test_agent_supplied_provenance_is_ignored_and_absent_from_the_record(
    tmp_path: Path, graph_db: Graph
) -> None:
    """The request body may carry provenance; the decision must not use it.

    The ledger holds one source for the task. The call's arguments carry a
    different, fabricated set. The engine must see the ledger's set, and the
    fabricated source must appear nowhere in the logged decision.
    """
    runs = tmp_path / "runs"
    log = DecisionLog(runs)
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=FakeUpstream(), runs_dir=runs)
    from warrant.models import Source, Tier

    real = Source(
        system="gitea",
        kind="file",
        id="acme/widgets:app.py@main",
        author="bob",
        author_tier=Tier.member,
        digest="sha256:real",
    )
    gateway.ledger.record("task-1", real)
    fabricated = {
        "task_id": "task-1",
        "sources": [
            {
                "system": "gitea",
                "kind": "file",
                "id": "fabricated-by-the-agent",
                "author": "alice",
                "author_tier": "owner",
                "digest": "sha256:fake",
            }
        ],
    }

    await gateway.call_tool(
        "gitea.get_issue",
        {"repo": "acme/widgets", "number": 1, "provenance": fabricated},
        claims=claims_for(),
        token="",
    )

    request = engine.requests[0]
    assert [source.id for source in request.provenance.sources] == [real.id]
    line = (runs / "task-1" / "decisions.jsonl").read_text(encoding="utf-8")
    assert "fabricated-by-the-agent" not in line
    assert "sha256:fake" not in line


async def test_the_request_provenance_is_the_ledgers_even_after_a_read(
    tmp_path: Path, graph_db: Graph
) -> None:
    runs = tmp_path / "runs"
    log = DecisionLog(runs)
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)
    payload = source_payload()
    upstream = FakeUpstream(
        result=CallToolResult(
            content=[TextContent(type="text", text=json.dumps(payload))], is_error=False
        )
    )
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=upstream, runs_dir=runs)

    await gateway.call_tool(
        "gitea.get_issue", {"repo": "acme/widgets", "number": 1}, claims=claims_for(), token=""
    )
    await gateway.call_tool(
        "gitea.get_issue", {"repo": "acme/widgets", "number": 1}, claims=claims_for(), token=""
    )

    # The second decision saw what the first read recorded.
    assert len(engine.requests[0].provenance.sources) == 0
    assert [source.id for source in engine.requests[1].provenance.sources] == ["acme/widgets#1"]


# -- the gateway's own log line --------------------------------------------


async def test_the_gateway_log_line_has_the_documented_shape(
    tmp_path: Path, graph_db: Graph
) -> None:
    runs = tmp_path / "runs"
    log = DecisionLog(runs)
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow, policy_ids=["permit-read"])
    upstream = FakeUpstream(
        result=CallToolResult(
            content=[TextContent(type="text", text=json.dumps(source_payload()))], is_error=False
        )
    )
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=upstream, runs_dir=runs)

    await gateway.call_tool(
        "gitea.get_issue", {"repo": "acme/widgets", "number": 1}, claims=claims_for(), token=""
    )

    lines = (runs / "task-1" / "gateway.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert set(record) == {
        "ts",
        "tool",
        "verdict",
        "policy_ids",
        "sub",
        "act",
        "task_id",
        "provenance_count",
        "upstream_ms",
    }
    assert record["tool"] == "gitea.get_issue"
    assert record["verdict"] == "allow"
    assert record["policy_ids"] == ["permit-read"]
    assert record["act"] == "triage-agent"
    assert record["task_id"] == "task-1"
    assert record["provenance_count"] == 0
    assert record["upstream_ms"] >= 0


def test_args_digest_is_stable_and_hides_the_values() -> None:
    assert args_digest({"b": 2, "a": 1}) == args_digest({"a": 1, "b": 2})
    assert "secret-body" not in args_digest({"body": "secret-body"})


# -- the tool surface ------------------------------------------------------


async def test_list_tools_prefixes_and_keeps_only_graph_known_tools(
    tmp_path: Path, graph_db: Graph
) -> None:
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log)
    upstream = FakeUpstream(
        tools=[
            Tool(name="get_issue", description="Read an issue.", input_schema={"type": "object"}),
            Tool(
                name="delete_everything",
                description="Not in the graph.",
                input_schema={"type": "object"},
            ),
        ]
    )
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=upstream)

    tools = await gateway.list_tools(claims=claims_for(), token="")

    assert [tool.name for tool in tools] == ["gitea.get_issue"]
    assert tools[0].description == "Read an issue."


# -- the HTTP boundary -----------------------------------------------------


def test_a_token_for_another_audience_gets_401(
    tmp_path: Path, graph_db: Graph, rsa_keypair: tuple[str, str], test_issuer: str, sign_token: Any
) -> None:
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log)
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=FakeUpstream())
    app = build_app(gateway, issuer=test_issuer, key=rsa_keypair[1])

    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            json=INITIALIZE_REQUEST,
            headers={**MCP_ACCEPT, "Authorization": f"Bearer {sign_token(audience='gitea-mcp')}"},
        )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_no_bearer_gets_401(
    tmp_path: Path, graph_db: Graph, rsa_keypair: tuple[str, str], test_issuer: str
) -> None:
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log)
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=FakeUpstream())
    app = build_app(gateway, issuer=test_issuer, key=rsa_keypair[1])

    with TestClient(app) as client:
        response = client.post("/mcp", json=INITIALIZE_REQUEST, headers=MCP_ACCEPT)

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_request"


# -- the real streamable-HTTP upstream client ------------------------------


def build_fake_upstream() -> MCPServer:
    """A real MCP server offering one graph-known read and one unknown tool."""
    server = MCPServer(name="fake-gitea-mcp", version="0.0.0")

    @server.tool(name="get_issue", description="Read one issue.")
    async def get_issue(repo: str, number: int) -> dict[str, Any]:
        return {**source_payload(f"{repo}#{number}"), "repo": repo}

    @server.tool(name="delete_everything", description="Not in the access graph.")
    async def delete_everything(repo: str) -> dict[str, Any]:
        return {"deleted": repo}

    return server


@contextmanager
def serve(app: Any) -> Iterator[str]:
    """Run an ASGI app on an ephemeral port in a thread and yield its base URL."""
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20.0
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("the fake upstream server did not start")
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10.0)


async def test_the_real_upstream_client_discovers_and_calls_a_fake_server(
    tmp_path: Path, graph_db: Graph
) -> None:
    app = build_fake_upstream().streamable_http_app(host="127.0.0.1")
    with serve(app) as base_url:
        server = UpstreamServer(
            name="gitea-mcp", prefix="gitea", url=f"{base_url}/mcp", audience="gitea-mcp"
        )
        log = DecisionLog(tmp_path / "runs")
        engine = FakeEngine(decision_log=log, verdict=Verdict.allow, policy_ids=["permit-read"])
        gateway = Gateway(
            graph=graph_db,
            engine=engine,
            ledger=Ledger(tmp_path / "runs"),
            decision_log=log,
            servers=[server],
            settings=GatewaySettings(warrant_agent_client_secret=""),
            upstream=StreamableHTTPUpstream(),
            runs_dir=tmp_path / "runs",
        )

        tools = await gateway.list_tools(claims=claims_for(), token="tok")
        assert [tool.name for tool in tools] == ["gitea.get_issue"]

        result = await gateway.call_tool(
            "gitea.get_issue",
            {"repo": "acme/widgets", "number": 1},
            claims=claims_for(),
            token="tok",
        )

    assert result.is_error is False
    assert [source.id for source in gateway.ledger.get("task-1").sources] == ["acme/widgets#1"]


# -- the second token hop --------------------------------------------------


async def test_a_successful_second_hop_uses_the_exchanged_token(
    tmp_path: Path, graph_db: Graph
) -> None:
    """The token the issuer returns is the one the upstream client presents."""
    import httpx

    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = request.content.decode()
        seen["authorization"] = request.headers.get("authorization", "")
        return httpx.Response(200, json={"access_token": "upstream-token"})

    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)
    upstream = FakeUpstream()
    gateway = make_gateway(
        tmp_path,
        graph_db,
        engine,
        upstream=upstream,
        exchange_transport=httpx.MockTransport(handler),
        client_secret="shh",
    )

    token = await gateway.upstream_token("incoming", "gitea-mcp", "task-1")

    assert token == "upstream-token"
    assert seen["path"].endswith("/protocol/openid-connect/token")
    assert "subject_token=incoming" in seen["body"]
    assert "audience=gitea-mcp" in seen["body"]
    assert "scope=task-id%3Atask-1" in seen["body"]
    assert seen["authorization"].startswith("Basic ")


async def test_a_refused_second_hop_forwards_the_incoming_token(
    tmp_path: Path, graph_db: Graph
) -> None:
    """A refusal falls back to the incoming token rather than failing the call."""
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "invalid_request"})

    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)
    gateway = make_gateway(
        tmp_path,
        graph_db,
        engine,
        upstream=FakeUpstream(),
        exchange_transport=httpx.MockTransport(handler),
        client_secret="shh",
    )

    assert await gateway.upstream_token("incoming", "gitea-mcp", "task-1") == "incoming"


async def test_a_call_without_a_client_secret_forwards_the_incoming_token(
    tmp_path: Path, graph_db: Graph
) -> None:
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=FakeUpstream())

    assert await gateway.upstream_token("incoming", "gitea-mcp", "task-1") == "incoming"


def test_the_settings_issuer_follows_the_keycloak_url() -> None:
    settings = GatewaySettings(keycloak_url="http://kc:8080", warrant_oidc_issuer=None)

    assert settings.issuer == "http://kc:8080/realms/warrant"
    assert settings.token_endpoint.endswith("/protocol/openid-connect/token")


async def test_the_request_timestamp_is_the_gateways_clock(tmp_path: Path, graph_db: Graph) -> None:
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=FakeUpstream())

    await gateway.call_tool(
        "gitea.get_issue", {"repo": "acme/widgets", "number": 1}, claims=claims_for(), token=""
    )

    assert engine.requests[0].ts.tzinfo is not None
    assert engine.requests[0].ts <= datetime.now(UTC)
