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

import asyncio
import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent, Tool
from starlette.testclient import TestClient

from warrant import oidc
from warrant.config import Mode
from warrant.engine import PolicyEngine
from warrant.gateway import (
    Gateway,
    GatewayError,
    GatewayServer,
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
MAIL = UpstreamServer(
    name="mail-mcp", prefix="mail", url="http://127.0.0.1:1/mcp", audience="mail-mcp"
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
        decision_log=engine.decision_log,
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
        ("gitea-mcp", "gitea", "gitea-mcp"),
        ("postgres-mcp", "db", "postgres-mcp"),
        ("mail-mcp", "mail", "mail-mcp"),
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
    name = extract_resource("mailbox", {"to": "support@acme.test", "body": "hi"})

    assert resolve_resource(graph_db, "mailbox", name) == "mailbox-support"


def test_a_mailbox_argument_becomes_the_mailbox() -> None:
    """The two mail reads name the mailbox they open, not a recipient.

    `list_inbox` and `get_message` take `mailbox`; only `send_reply` takes `to`.
    The extractor reads both spellings, so a read resolves to the same row a
    send to that address does.
    """
    assert extract_resource("mailbox", {"mailbox": "support@acme.test"}) == "support@acme.test"
    assert extract_resource("mailbox", {"to": "support@acme.test"}) == "support@acme.test"
    assert extract_resource("mailbox", {}) is None


def test_an_unknown_resource_name_is_passed_through() -> None:
    assert resolve_resource(None, "repo", "acme/unknown") == "acme/unknown"
    assert resolve_resource(None, "repo", None) == ""


def test_a_free_text_customer_search_resolves_only_to_exactly_one_row() -> None:
    """`search_customers` takes text, and a decision needs one subject.

    The query string is not an id, so it resolves only when it is the `name` of
    exactly one graph row. A query matching no row resolves to something the
    graph has no row for, so the engine's unknown-resource path applies instead
    of a decision against the row the query was not bounded by.
    """
    with Graph(":memory:") as graph:
        graph.seed(
            {
                "humans": [{"id": "h-alice", "login": "alice", "groups": []}],
                "resources": [
                    {
                        "id": "customer-acme-1",
                        "kind": "db_customer",
                        "name": "Acme",
                        "owner_human_id": "h-alice",
                        "sensitivity": "internal",
                    }
                ],
            }
        )

        assert resolve_resource(graph, "db_customer", "Acme") == "customer-acme-1"
        unmatched = resolve_resource(graph, "db_customer", "Globex")
        assert graph.resource(unmatched) is None, "an unmatched name names no row"


def test_a_customer_query_matching_several_rows_is_unresolved() -> None:
    """Two rows named the same are not a subject a read can be decided against."""
    with Graph(":memory:") as graph:
        graph.seed(
            {
                "humans": [{"id": "h-alice", "login": "alice", "groups": []}],
                "resources": [
                    {
                        "id": "customer-acme-1",
                        "kind": "db_customer",
                        "name": "Acme",
                        "owner_human_id": "h-alice",
                        "sensitivity": "internal",
                    },
                    {
                        "id": "customer-acme-2",
                        "kind": "db_customer",
                        "name": "Acme",
                        "owner_human_id": "h-alice",
                        "sensitivity": "confidential",
                    },
                ],
            }
        )

        resolved = resolve_resource(graph, "db_customer", "Acme")

        assert graph.resource(resolved) is None, "a tie must not become a known row"


def test_a_multi_table_statement_is_decided_against_its_first_table() -> None:
    """The current behavior, pinned so a change to it is visible.

    `select c.name, k.key_value from customers c join api_keys k ...` is a read
    of two tables, and the decision is made against the first one the extractor
    finds, `customers`. A policy that keys on `api_keys` never sees the call.
    One resource cannot name several tables, so the fix is a policy or resource
    model that can and belongs to W7 and W12; this test is the visible record
    that it is open.
    """
    sql = "select c.name, k.key_value from customers c join api_keys k on k.customer_id = c.id"

    name = extract_resource("db_table", {"sql": sql})

    assert name == "customers", "the first FROM wins, not the table that holds the key"
    assert "api_keys" in sql, "and the statement really does read the key table"


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
    sources = gateway.ledger.get("task-1", "triage-agent").sources
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
    gateway.ledger.record("task-1", "triage-agent", real)
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


async def test_list_tools_offers_only_the_tools_the_agent_holds(
    tmp_path: Path, graph_db: Graph
) -> None:
    """A graph-known tool the acting agent does not hold is not offered.

    The graph is the authority twice over: a tool with no row is not
    re-exported, and a tool with a row that the agent's allowlist lacks is not
    offered to that agent, because the baseline permit refuses it anyway.
    """
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log)
    upstream = FakeUpstream(
        tools=[
            Tool(name="get_issue", description="Read an issue.", input_schema={"type": "object"}),
            Tool(name="send_reply", description="Send a reply.", input_schema={"type": "object"}),
        ]
    )
    gateway = make_gateway(tmp_path, graph_db, engine, servers=[GITEA, MAIL], upstream=upstream)

    triage_tools = await gateway.list_tools(claims=claims_for(act="triage-agent"), token="")
    support_tools = await gateway.list_tools(claims=claims_for(act="support-agent"), token="")

    assert [tool.name for tool in triage_tools] == ["gitea.get_issue"]
    assert [tool.name for tool in support_tools] == ["mail.send_reply"]


async def test_prompt_only_offers_the_whole_graph_surface(tmp_path: Path, graph_db: Graph) -> None:
    """The ablation must not gain a graph-allowlist control it did not have.

    `orphan-agent` holds none of the discovered tools. Under prompt-only the
    engine evaluates no policy, so the discovered graph-known surface is offered
    whole; the same request in a deciding mode comes back empty.
    """
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log)
    upstream = FakeUpstream(
        tools=[
            Tool(name="get_issue", description="Read an issue.", input_schema={"type": "object"}),
            Tool(name="get_file", description="Read a file.", input_schema={"type": "object"}),
            Tool(name="send_reply", description="Send a reply.", input_schema={"type": "object"}),
        ]
    )
    gateway = make_gateway(tmp_path, graph_db, engine, servers=[GITEA, MAIL], upstream=upstream)
    gateway.mode = Mode.prompt_only

    tools = await gateway.list_tools(claims=claims_for(act="orphan-agent"), token="")

    assert [tool.name for tool in tools] == [
        "gitea.get_issue",
        "gitea.get_file",
        "mail.send_reply",
    ]


async def test_the_handler_lists_tools_from_headers_under_no_exchange(
    tmp_path: Path, graph_db: Graph
) -> None:
    """`tools/list` builds the same chain `tools/call` does, from the headers.

    The handler did not pass the request headers, so under the no-exchange
    ablation `list_tools` raised `ChainSourceError` at the first request an MCP
    client makes, and the whole ablation was unusable.
    """
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log)
    upstream = FakeUpstream(
        tools=[
            Tool(name="get_issue", description="Read an issue.", input_schema={"type": "object"})
        ]
    )
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=upstream)
    gateway.mode = Mode.no_exchange
    handler = GatewayServer(gateway)
    headers = {
        "X-Warrant-Sub": "h-alice",
        "X-Warrant-Act": "triage-agent",
        "X-Warrant-Task-Id": "task-1",
        "X-Warrant-Token-Exp": str(int(time.time()) + 300),
    }
    ctx = SimpleNamespace(request=SimpleNamespace(headers=headers))

    result = await handler.list_tools(ctx, None)

    assert [tool.name for tool in result.tools] == ["gitea.get_issue"]


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
    recorded = gateway.ledger.get("task-1", "triage-agent").sources
    assert [source.id for source in recorded] == ["acme/widgets#1"]


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


# -- the fixes the W6 review asked for ---------------------------------------


async def test_a_task_id_cannot_inherit_another_actors_provenance(
    tmp_path: Path, graph_db: Graph
) -> None:
    """The agent chooses its own task id, so the actor is part of the ledger key.

    `scope=task-id:<value>` is written by the caller of the exchange, so an agent
    can name a task id that belongs to someone else. With the ledger keyed on the
    id alone, that agent inherited the sources recorded under it and the engine
    computed `hasExternal` from another task's reads. Two actors, one task id:
    the second must see nothing.
    """
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)
    upstream = FakeUpstream(
        result=CallToolResult(
            content=[TextContent(type="text", text=json.dumps(source_payload()))],
            is_error=False,
        )
    )
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=upstream)

    await gateway.call_tool(
        "gitea.get_issue",
        {"repo": "acme/widgets", "number": 1},
        claims=claims_for(act="triage-agent", task_id="shared-task"),
        token="",
    )
    # Read before the second call: that call performs its own read of the same
    # issue, and its own read belongs in its own ledger. What the second call
    # must not do is start from the first actor's sources.
    before = list(gateway.ledger.get("shared-task", "support-agent").sources)
    await gateway.call_tool(
        "gitea.get_issue",
        {"repo": "acme/widgets", "number": 1},
        claims=claims_for(act="support-agent", task_id="shared-task"),
        token="",
    )

    assert before == [], "the second actor starts from nothing, under the same task id"
    assert engine.requests[1].provenance.sources == [], "and is decided with nothing"
    assert [source.id for source in gateway.ledger.get("shared-task", "triage-agent").sources] == [
        "acme/widgets#1"
    ]
    assert [source.id for source in gateway.ledger.get("shared-task", "support-agent").sources] == [
        "acme/widgets#1"
    ], "each actor's own read lands in its own file"


async def test_an_all_dots_task_id_is_refused_as_a_tool_error(
    tmp_path: Path, graph_db: Graph
) -> None:
    """A task id that cannot name a run is refused, not raised out of the log.

    `task_dir` rejects an all-dots name. The gateway used to pass that value to
    the decision log, which raised `ValueError` out of the request handler after
    the call had been accepted: an unlogged crash in place of a refusal.
    """
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=FakeUpstream())

    result = await gateway.call_tool(
        "gitea.get_issue",
        {"repo": "acme/widgets", "number": 1},
        claims=claims_for(task_id=".."),
        token="",
    )

    assert result.is_error is True
    assert "cannot name a run" in result.content[0].text
    assert engine.requests == [], "a refused call never reaches the engine"


async def test_an_unknown_tool_leaves_a_gateway_line_with_its_task(
    tmp_path: Path, graph_db: Graph
) -> None:
    """A refusal before the engine is still a call, and the record says so.

    The module docstring promises a line for every call including the ones the
    gateway refuses itself. An unknown tool is the easiest such call to make and
    it wrote nothing, because the refusal carried no task id.
    """
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=FakeUpstream())

    result = await gateway.call_tool("gitea.delete_everything", {}, claims=claims_for(), token="")

    assert result.is_error is True
    lines = [
        json.loads(line)
        for line in (tmp_path / "runs" / "task-1" / "gateway.jsonl").read_text().splitlines()
    ]
    assert len(lines) == 1
    assert lines[0]["tool"] == "gitea.delete_everything"
    assert lines[0]["verdict"] == "deny"
    assert lines[0]["task_id"] == "task-1"
    assert lines[0]["act"] == "triage-agent"
    assert "unknown tool" in lines[0]["error"]


async def test_an_upstream_failure_is_recorded_as_an_error_not_a_clean_allow(
    tmp_path: Path, graph_db: Graph
) -> None:
    """The verdict is the decision and the error is the outcome.

    The line for a failed upstream call used to be byte-identical in shape to a
    successful one: `allow`, no error, no way to tell a delivered call from a
    lost one.
    """
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)

    class Exploding(FakeUpstream):
        async def call_tool(
            self, server: UpstreamServer, name: str, arguments: dict[str, Any], bearer: str
        ) -> CallToolResult:
            raise RuntimeError("upstream exploded")

    gateway = make_gateway(tmp_path, graph_db, engine, upstream=Exploding())

    result = await gateway.call_tool(
        "gitea.get_issue", {"repo": "acme/widgets", "number": 1}, claims=claims_for(), token=""
    )

    assert result.is_error is True
    lines = [
        json.loads(line)
        for line in (tmp_path / "runs" / "task-1" / "gateway.jsonl").read_text().splitlines()
    ]
    assert lines[-1]["verdict"] == "allow", "the decision was allow; the call is what failed"
    assert "upstream gitea-mcp failed" in lines[-1]["error"]


async def test_listing_tools_for_an_unknown_agent_reaches_no_upstream(
    tmp_path: Path, graph_db: Graph
) -> None:
    """Tool inventory is the deployment's shape, and it is not for a ghost.

    `call_tool` refused an unknown actor before the engine; `list_tools` did an
    exchange and an upstream round trip for it and handed back the names.
    """
    log = DecisionLog(tmp_path / "runs")
    engine = FakeEngine(decision_log=log, verdict=Verdict.allow)
    upstream = FakeUpstream(tools=[Tool(name="get_issue", input_schema={"type": "object"})])
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=upstream)

    tools = await gateway.list_tools(claims=claims_for(act="agent-ghost"), token="")

    assert tools == []
    assert upstream.bearers == [], "no upstream was contacted for an actor with no row"


def test_a_resource_id_of_another_kind_does_not_become_that_resource(graph_db: Graph) -> None:
    """A mailbox that names a table id must not be decided as that table.

    Names and ids share one namespace, so `to="table-orders"` missed the
    kind-filtered name lookup and was passed through as an id, where the engine
    resolved alice's confidential table under a permit aimed at a mailbox.
    """
    resolved = resolve_resource(graph_db, "mailbox", "table-orders")

    assert graph_db.resource(resolved) is None, "it must not resolve to a known row"
    assert resolved != "table-orders", "and it must not be the id that does"


async def test_a_per_tool_forbid_refuses_under_the_graph_schema(
    tmp_path: Path, graph_db: Graph
) -> None:
    """The criterion's policy shape, through the real engine and the graph schema.

    Every other gateway test uses `FakeEngine`, so nothing here has run a policy
    through Cedar with the schema generated from the graph. This one does: the
    permit is a kind rule, the forbid names one tool, and the call is the
    gateway's own tool id.
    """
    from warrant.engine import CedarEngine

    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "00_test.cedar").write_text(
        '@id("permit-write")\npermit(principal, action in Action::"write", resource);\n'
        '@id("forbid-comment")\nforbid(principal, action == '
        'Action::"gitea.create_issue_comment", resource);\n'
    )
    log = DecisionLog(tmp_path / "runs")
    engine = CedarEngine(policies_dir=policies, graph=graph_db, decision_log=log)
    gateway = make_gateway(tmp_path, graph_db, engine, upstream=FakeUpstream())

    denied = await gateway.call_tool(
        "gitea.create_issue_comment",
        {"repo": "acme/widgets", "number": 1, "body": "hi"},
        claims=claims_for(),
        token="",
    )
    decided = log.read("task-1")

    assert denied.is_error is True
    assert decided[0].verdict is Verdict.deny
    assert decided[0].policy_ids == ["forbid-comment"], "the forbid fired, not the default deny"


def test_a_ticket_argument_becomes_the_ticket_row() -> None:
    """The postgres tools name a row by id, and the extractor reads that id.

    The schema declares `ticket_id` as an integer, so that is the spelling a real
    caller sends. The string form still resolves, because W12 seeds the resource
    with `name` set to the id as a string and both spellings become that string.
    """
    assert extract_resource("db_ticket", {"ticket_id": 10}) == "10"
    assert extract_resource("db_ticket", {"ticket_id": "10"}) == "10"
    assert extract_resource("db_ticket", {}) is None


def test_a_customer_argument_becomes_the_customer_row() -> None:
    """`search_customers` carries a query rather than an id, and both work."""
    assert extract_resource("db_customer", {"customer_id": 3}) == "3"
    assert extract_resource("db_customer", {"customer_id": "3"}) == "3"
    assert extract_resource("db_customer", {"query": "acme"}) == "acme"
    assert extract_resource("db_customer", {}) is None


def test_the_shipped_graph_holds_the_postgres_tools(tmp_path: Path) -> None:
    """Every tool the W8 server offers has a row, or the gateway drops it.

    `list_tools` re-exports only tools the graph knows, so a missing row is a
    tool the agent is never shown, which is how W8 arrived unreachable.
    """
    with load_graph(SEED, tmp_path / "warrant.db") as graph:
        tools = {tool.id for tool in graph.tools()}

    assert {
        "db.search_customers",
        "db.get_ticket",
        "db.get_customer",
        "db.run_readonly_sql",
        "db.update_ticket",
        "db.rotate_api_key",
    } <= tools
    assert not {"db.query", "db.execute"} & tools, "the placeholders are gone"


def test_the_shipped_graph_holds_the_mail_tools(tmp_path: Path) -> None:
    """Every tool the W9 server offers has a row, or the gateway drops it.

    `mail.search` and `mail.send` were the placeholders W5 wrote before the
    server existed. The three real rows replace them, and the old names are gone
    so a policy or an allowlist that still names one is a deny rather than a
    quiet pass.
    """
    with load_graph(SEED, tmp_path / "warrant.db") as graph:
        tools = {tool.id for tool in graph.tools()}

    assert {
        "mail.list_inbox",
        "mail.get_message",
        "mail.send_reply",
    } <= tools
    assert not {"mail.search", "mail.send"} & tools, "the placeholders are gone"


def test_the_shipped_graph_names_the_mailbox_the_server_uses(tmp_path: Path) -> None:
    """The mailbox resource name has to be the address the mail tools carry.

    The graph held `support@acme.example` while the server sends from and reads
    `support@acme.test`, so a live honest `list_inbox` resolved to no resource and
    the subject rule refused it. The two spellings are two trees that have to
    agree, and this is the check that keeps them agreeing.
    """
    from servers.mail_mcp.mail import MailSettings

    desk = MailSettings().mail_from
    with load_graph(SEED, tmp_path / "warrant.db") as graph:
        row = graph.resource_named(desk, "mailbox")

    assert row is not None, f"no mailbox resource named {desk}"
    assert row.owner_human_id, "the row needs an owner for the subject rule"


def test_the_mail_tool_surface_matches_the_graph_rows(tmp_path: Path) -> None:
    """The server's names and arguments and the graph's rows cannot drift apart.

    The gateway re-exports only tools the graph knows, and the graph decides the
    resource kind each tool is authorized against, so the two trees have to
    agree. A rename on either side fails here, the way
    `test_the_shipped_graph_names_the_mailbox_the_server_uses` holds the mailbox
    name. Each tool's declared arguments are fed to the extractor for its row's
    resource kind, so a read that stops naming its mailbox is a failure and not a
    quiet unknown resource at decision time.
    """
    from servers.mail_mcp.server import TOOL_NAMES, ServerSettings, build_server

    server = build_server(mail=object(), settings=ServerSettings())
    declared = {
        tool.name: set(tool.input_schema.get("properties") or {})
        for tool in asyncio.run(server.list_tools())
    }
    with load_graph(SEED, tmp_path / "warrant.db") as graph:
        rows = {tool.name: tool for tool in graph.tools() if tool.server == "mail"}

    assert set(declared) == set(TOOL_NAMES)
    assert set(declared) == set(rows), "a server tool has no graph row, or the reverse"
    for name, arguments in declared.items():
        row = rows[name]
        probe = dict.fromkeys(arguments, "probe@acme.test")
        assert extract_resource(row.resource_kind, probe) is not None, (
            f"{name} declares no argument the {row.resource_kind} extractor reads"
        )


async def test_an_honest_get_message_by_the_desk_owners_agent_is_allowed(
    tmp_path: Path, graph_db: Graph
) -> None:
    """The mailbox is the resource `get_message` names, so the desk owner passes.

    With only a `message_id` argument the extractor resolved nothing, the mailbox
    was unknown, and the subject rule refused the honest read. This runs the
    shipped policy set through the real engine, so the verdict is the rule's.
    """
    from warrant.engine import CedarEngine

    log = DecisionLog(tmp_path / "runs")
    engine = CedarEngine(policies_dir=REPO / "policies", graph=graph_db, decision_log=log)
    gateway = make_gateway(tmp_path, graph_db, engine, servers=[MAIL], upstream=FakeUpstream())

    result = await gateway.call_tool(
        "mail.get_message",
        {"mailbox": "support@acme.test", "message_id": "prior@acme.test"},
        claims=claims_for(sub="h-bob", act="support-agent"),
        token="",
    )

    assert result.is_error is False
    assert log.read("task-1")[-1].verdict is Verdict.allow
