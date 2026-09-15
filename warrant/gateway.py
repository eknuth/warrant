"""Warrant as the MCP gateway every agent call passes through.

An agent no longer holds a token for a resource server. It holds an on-behalf-of
token for `warrant`, connects to this server, and calls the re-exported tools
(`gitea.get_issue`, `db.get_ticket`, `mail.send_reply`). For each call the gateway:

1. Verifies the bearer for the `warrant` audience. A token minted for an
   upstream resource server is refused here, which is what stops an agent from
   skipping the gateway.
2. Builds a `Chain` from the verified claims, and looks the acting agent up in
   the access graph by `chain.act`, which is the token's `act.sub`. An actor the
   graph does not know is a deny.
3. Builds an `AuthzRequest` from the graph's row for the tool: its action kind,
   the resource named by the call's arguments, and the provenance ledger's set
   for the task. The ledger is the only source of provenance; nothing the agent
   sends in the call body reaches the request.
4. Calls `engine.decide()`. An allow forwards the call upstream with a bearer
   Warrant exchanges for that upstream's audience, a deny returns the policy
   reasons as a tool error, and an escalate returns `escalated: pending`.
5. On an allowed read, records each provenance block the upstream returned in
   the ledger, so the next call in the task is decided with it.

Two JSONL records are written per call. `decisions.jsonl` is the
`warrant.engine` decision log, one line per evaluated call. `gateway.jsonl` is
this module's own line, written for every call including the ones the gateway
refuses before the engine: `ts`, `tool`, `verdict`, `policy_ids`, `sub`, `act`,
`task_id`, `provenance_count`, and `upstream_ms`.

Upstream tokens
---------------
The verified token names `warrant`, so it is not valid at an upstream resource
server. The gateway exchanges it again at the issuer, acting as its own
confidential client and using the incoming token as the subject token. When the
issuer refuses that second hop the gateway forwards the incoming token, records
the refusal, and the upstream refuses it; see
`docs/decisions/004-gateway-hop.md` for what the running realm does.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import httpx
import yaml
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.lowlevel import Server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.applications import Starlette

from servers.common.auth import BearerAuthMiddleware
from warrant import config, oidc
from warrant.config import RUNS_DIR, Mode, bad_task_id, task_dir
from warrant.engine import PolicyEngine
from warrant.graph import Graph
from warrant.log import DecisionLog
from warrant.models import (
    ActionKind,
    AuthzRequest,
    Chain,
    Decision,
    Source,
    Tier,
    Verdict,
)
from warrant.provenance import Ledger
from warrant.resources import extract_resource, resolve_resource

logger = logging.getLogger(__name__)

GATEWAY_LOG_NAME = "gateway.jsonl"

DEFAULT_SERVERS_FILE = Path("infra/servers.yml")
DEFAULT_POLICIES_DIR = Path("policies")
DEFAULT_DB = Path("warrant.db")
DEFAULT_SEED = Path("infra/graph.yml")

# The resource kind of a read, from `ActionKind`. A read is the only kind whose
# result is recorded as provenance.
READ = ActionKind.read

# The upstream provenance block's keys. A dict carrying all of them is a
# `warrant.models.Source`; anything else is walked through looking for one.
SOURCE_KEYS = frozenset({"system", "kind", "id", "author", "author_tier"})

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


class GatewayError(RuntimeError):
    """The gateway could not carry a call: a missing bearer, an unreachable upstream."""


@dataclass(frozen=True)
class UpstreamServer:
    """One resource server behind the gateway."""

    name: str
    prefix: str
    url: str
    audience: str


def load_servers(path: Path | str = DEFAULT_SERVERS_FILE) -> list[UpstreamServer]:
    """Read the upstream list from `servers.yml`.

    The file is separate from the code so the compose network's hostnames
    (`gitea-mcp:9101`) are a deployment value and a host-side run can point at a
    file with `127.0.0.1` URLs instead.
    """
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping) or "servers" not in data:
        raise GatewayError(f"{path} does not hold a `servers:` list")
    servers: list[UpstreamServer] = []
    for index, entry in enumerate(data["servers"]):
        if not isinstance(entry, Mapping):
            raise GatewayError(f"servers[{index}] is not a mapping: {entry!r}")
        missing = [key for key in ("name", "prefix", "url", "audience") if key not in entry]
        if missing:
            raise GatewayError(f"servers[{index}] is missing {', '.join(missing)}")
        servers.append(
            UpstreamServer(
                name=str(entry["name"]),
                prefix=str(entry["prefix"]),
                url=str(entry["url"]),
                audience=str(entry["audience"]),
            )
        )
    prefixes = [server.prefix for server in servers]
    if len(set(prefixes)) != len(prefixes):
        raise GatewayError(f"{path} repeats a tool prefix: {prefixes}")
    return servers


class GatewaySettings(BaseSettings):
    """What the gateway reads from `.env` and the environment."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    keycloak_url: str = "http://localhost:8080"
    # The gateway's own confidential client at the issuer. Its secret is the
    # dev secret the agent clients share; see docs/decisions/002-token-exchange.md.
    warrant_client_id: str = "warrant"
    warrant_agent_client_secret: str = ""
    # None means `warrant.oidc`'s own default, which reads WARRANT_OIDC_ISSUER.
    warrant_oidc_issuer: str | None = None
    warrant_audience: str = "warrant"
    warrant_servers_file: str = str(DEFAULT_SERVERS_FILE)
    warrant_graph_db: str = str(DEFAULT_DB)
    warrant_graph_seed: str = str(DEFAULT_SEED)
    warrant_policies_dir: str = str(DEFAULT_POLICIES_DIR)
    warrant_runs_dir: str = str(RUNS_DIR)
    warrant_gateway_host: str = "127.0.0.1"
    warrant_gateway_port: int = 9100
    warrant_gateway_path: str = "/mcp"

    @property
    def issuer(self) -> str:
        if self.warrant_oidc_issuer:
            return self.warrant_oidc_issuer
        return f"{self.keycloak_url.rstrip('/')}/realms/warrant"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/token"


def args_digest(args: Mapping[str, Any]) -> str:
    """A stable sha256 over a tool call's arguments.

    The arguments can carry issue bodies and file contents, so the decision
    records a digest and not the values. The digest also means an agent-supplied
    provenance set in the arguments cannot appear in the decision; only this
    digest of the whole argument mapping does.
    """
    canonical = json.dumps(dict(args), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def digest(value: Any) -> str:
    """A stable sha256 over any JSON-shaped value."""
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def extract_sources(payload: Any) -> list[tuple[dict[str, Any], Any]]:
    """Every provenance block in a tool result, with the record that carried it.

    A block already found is not walked again, and two blocks with the same
    system, kind, and id are one entry, so a repeated read does not duplicate
    the ledger. The second element is the record the block sat in, which is what
    its digest is taken over.
    """
    found: list[tuple[dict[str, Any], Any]] = []
    seen: set[tuple[Any, Any, Any]] = set()

    def walk(value: Any, parent: Any) -> None:
        if isinstance(value, dict):
            if SOURCE_KEYS <= set(value):
                key = (value.get("system"), value.get("kind"), value.get("id"))
                if key not in seen:
                    seen.add(key)
                    found.append((dict(value), parent if parent is not None else value))
                return
            for item in value.values():
                walk(item, value)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item, parent)

    walk(payload, None)
    return found


def payload_of(result: CallToolResult) -> Any:
    """The structured payload of a tool result, or its text parsed as JSON."""
    payload = getattr(result, "structured_content", None)
    if payload is not None:
        return payload
    text = "".join(
        block.text
        for block in (getattr(result, "content", None) or [])
        if getattr(block, "type", None) == "text" and getattr(block, "text", None)
    )
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def as_source(block: Mapping[str, Any], record: Any) -> Source:
    """A `Source` from an upstream provenance block, with a digest of the record.

    The resource server's block carries the identity of what was read but not a
    digest of it, so the digest is taken here over the record the block sat in.
    """
    tier = block.get("author_tier")
    try:
        author_tier = Tier(tier)
    except ValueError:
        author_tier = Tier.unknown
    return Source(
        system=str(block.get("system", "")),
        kind=str(block.get("kind", "")),
        id=str(block.get("id", "")),
        author=str(block.get("author", "")),
        author_tier=author_tier,
        digest=digest(record),
    )


def tool_result_error(text: str) -> CallToolResult:
    """A tool error carrying `text` verbatim."""
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)


class UpstreamClient(Protocol):
    """What the gateway needs from an upstream MCP server."""

    async def list_tools(self, server: UpstreamServer, bearer: str) -> Sequence[Tool]: ...

    async def call_tool(
        self, server: UpstreamServer, name: str, arguments: dict[str, Any], bearer: str
    ) -> CallToolResult: ...


class StreamableHTTPUpstream:
    """Upstream MCP servers over streamable HTTP, one short session per call.

    A session carries one bearer, and the bearer is per task, so a session
    cannot be reused across tasks. Opening one per call keeps that honest and
    costs one handshake, which is small next to the work the call does.
    """

    def __init__(
        self, *, transport: httpx.AsyncBaseTransport | None = None, timeout: float = 60.0
    ) -> None:
        self._transport = transport
        self._timeout = timeout

    @asynccontextmanager
    async def _session(self, server: UpstreamServer, bearer: str) -> AsyncIterator[ClientSession]:
        headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
        async with httpx.AsyncClient(
            headers=headers, timeout=self._timeout, transport=self._transport
        ) as http:
            async with streamable_http_client(server.url, http_client=http) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    yield session

    async def list_tools(self, server: UpstreamServer, bearer: str) -> Sequence[Tool]:
        async with self._session(server, bearer) as session:
            result = await session.list_tools()
        return list(result.tools)

    async def call_tool(
        self, server: UpstreamServer, name: str, arguments: dict[str, Any], bearer: str
    ) -> CallToolResult:
        async with self._session(server, bearer) as session:
            return await session.call_tool(name, arguments=arguments)


def describe_failure(error: Exception) -> str:
    """One line naming what an upstream failure was, for a log or a reason."""
    return f"{type(error).__name__}: {error}"


class Gateway:
    """The request path: verify, decide, forward, record."""

    def __init__(
        self,
        *,
        graph: Graph,
        engine: PolicyEngine,
        ledger: Ledger,
        decision_log: DecisionLog,
        servers: Sequence[UpstreamServer],
        settings: GatewaySettings | None = None,
        upstream: UpstreamClient | None = None,
        issuer: str | None = None,
        key: object | None = None,
        exchange_transport: httpx.AsyncBaseTransport | None = None,
        runs_dir: Path | str | None = None,
        mode: Mode | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings or GatewaySettings()
        self.graph = graph
        self.engine = engine
        self.ledger = ledger
        self.decision_log = decision_log
        self.servers = list(servers)
        self.upstream = upstream or StreamableHTTPUpstream()
        self._by_prefix = {server.prefix: server for server in self.servers}
        self._issuer = issuer if issuer is not None else self.settings.issuer
        self._key = key
        self._exchange_transport = exchange_transport
        self.runs_dir = (
            Path(runs_dir) if runs_dir is not None else Path(self.settings.warrant_runs_dir)
        )
        self.mode = Mode(mode) if mode is not None else config.current_mode()
        self._now = now or (lambda: datetime.now(UTC))
        self._tools: dict[str, list[Tool]] = {}

    # Bearer verification ---------------------------------------------------

    def verify(self, token: str) -> oidc.Claims:
        """Verify an incoming token for the gateway's audience."""
        return oidc.verify(
            token, self.settings.warrant_audience, key=self._key, issuer=self._issuer
        )

    # Tool surface ----------------------------------------------------------

    async def list_tools(
        self,
        *,
        claims: oidc.Claims | None = None,
        token: str = "",
        headers: Mapping[str, str] | None = None,
    ) -> list[Tool]:
        """The tools the acting agent holds, with the upstream name prefixed.

        The graph is the authority on what may be called twice over. A tool the
        upstream offers but the graph has no row for is not re-exported, because
        the gateway would have no action kind to decide it with; and a tool the
        graph knows but the acting agent's allowlist does not hold is not
        offered, because the baseline permit refuses it anyway and the model
        should not be handed a call it cannot make. `_discover` caches the full
        per-server list, so the per-actor narrowing is a filter over that cache
        on every request.

        `claims` is None under the `no-exchange` ablation, where the chain comes
        from headers and there is no token at all. `tools/list` is the first
        thing an MCP client asks for after `initialize`, so reading
        `claims.task_id` unconditionally made the whole ablation unusable.
        """
        chain, _ = self._chain_for(claims=claims, headers=headers)
        if chain is None:
            return []
        # An actor the graph does not know gets no tool inventory. `call_tool`
        # already refuses it before the engine; listing is not a decision, but
        # it is a round trip to every upstream and a description of what this
        # deployment can do, and neither belongs to an actor with no row.
        agent = self.graph.agent(chain.act)
        if agent is None:
            logger.info("not listing tools for unknown agent %s", chain.act)
            return []
        allowed = set(agent.allowed_tools)

        tools: list[Tool] = []
        for server in self.servers:
            tools.extend(await self._discover(server, task_id=chain.task_id, token=token))
        return [tool for tool in tools if tool.name in allowed]

    async def _discover(self, server: UpstreamServer, *, task_id: str, token: str) -> list[Tool]:
        if server.name in self._tools:
            return self._tools[server.name]
        upstream_token = await self.upstream_token(token, server.audience, task_id)
        try:
            offered = await self.upstream.list_tools(server, upstream_token)
        except Exception as error:  # noqa: BLE001 - an upstream that will not list is reported
            logger.warning("could not list tools from %s: %s", server.name, describe_failure(error))
            return []
        registered: list[Tool] = []
        for tool in offered:
            name = f"{server.prefix}.{tool.name}"
            if self.graph.tool(name) is None:
                logger.info("not re-exporting %s: no row in the access graph", name)
                continue
            registered.append(
                Tool(
                    name=name,
                    description=tool.description or "",
                    input_schema=tool.input_schema or {"type": "object", "properties": {}},
                )
            )
        self._tools[server.name] = registered
        return registered

    # Token exchange --------------------------------------------------------

    async def upstream_token(self, subject_token: str, audience: str, task_id: str | None) -> str:
        """A bearer for an upstream audience, or the incoming token on refusal.

        The second hop is the design risk this module documents: the verified
        token names `warrant`, so an upstream will not accept it. The exchange
        is attempted and its outcome logged; a refusal falls back to the
        incoming token, which the upstream will refuse in turn.
        """
        if self.mode is Mode.no_exchange or not subject_token:
            return subject_token
        secret = self.settings.warrant_agent_client_secret
        if not secret:
            logger.warning(
                "no client secret for the upstream exchange; forwarding the incoming token"
            )
            return subject_token
        data = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": ACCESS_TOKEN_TYPE,
            "audience": audience,
        }
        if task_id:
            data["scope"] = f"task-id:{task_id}"
        try:
            async with httpx.AsyncClient(
                timeout=20.0, transport=self._exchange_transport
            ) as client:
                response = await client.post(
                    self.settings.token_endpoint,
                    auth=(self.settings.warrant_client_id, secret),
                    data=data,
                )
        except httpx.HTTPError as error:
            logger.warning("upstream exchange for %s failed: %s", audience, error)
            return subject_token
        if response.status_code != 200:
            logger.warning(
                "upstream exchange for %s refused: HTTP %d %s",
                audience,
                response.status_code,
                response.text[:300],
            )
            return subject_token
        return str(response.json()["access_token"])

    # The request path ------------------------------------------------------

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        claims: oidc.Claims | None = None,
        token: str = "",
        headers: Mapping[str, str] | None = None,
    ) -> CallToolResult:
        """Decide one tool call and, on an allow, forward it upstream."""
        chain, refusal = self._chain_for(claims=claims, headers=headers)
        if chain is None:
            return self._refuse(name, refusal)
        if not chain.task_id:
            return self._refuse(name, "token carries no task id", chain)
        if bad_task_id(chain.task_id):
            # The task id names the run directory and the ledger file. A value
            # the path sanitizer refuses would raise out of the decision log
            # after the call had already been processed, turning a refusal into
            # an unlogged crash.
            return self._refuse(name, f"task id {chain.task_id!r} cannot name a run", chain)

        row = self.graph.tool(name)
        if row is None:
            return self._refuse(name, f"unknown tool {name!r}", chain)

        provenance = self.ledger.get(chain.task_id, chain.act)
        resource_name = extract_resource(row.resource_kind, arguments)
        request = AuthzRequest(
            chain=chain,
            tool=name,
            action_kind=ActionKind(row.action_kind),
            resource=resolve_resource(self.graph, row.resource_kind, resource_name),
            args_digest=args_digest(arguments),
            provenance=provenance,
            ts=self._now(),
        )

        if self.graph.agent(chain.act) is None:
            return self._log_and_refuse(request, ["unknown agent"])

        decision = self.engine.decide(request)
        if decision.verdict is Verdict.deny:
            return self._denied(name, decision)
        if decision.verdict is Verdict.escalate:
            self._write_log(
                name, decision, provenance_count=len(provenance.sources), upstream_ms=0.0
            )
            logger.info("escalated: pending tool=%s act=%s", name, chain.act)
            return tool_result_error("escalated: pending")

        server = self._by_prefix.get(row.server)
        if server is None:
            # The graph names a server the deployment does not list. Fail closed
            # rather than guess an upstream.
            return self._log_and_refuse(
                request, [f"no upstream configured for server {row.server!r}"]
            )
        upstream_token = await self.upstream_token(token, server.audience, chain.task_id)
        # Started after the exchange, so the number is the upstream's latency. A
        # slow issuer and a slow upstream are different problems and the record
        # has to be able to tell them apart.
        upstream_started = time.monotonic()
        upstream_name = row.name
        try:
            result = await self.upstream.call_tool(server, upstream_name, arguments, upstream_token)
        except Exception as error:  # noqa: BLE001 - any upstream failure is answered as a tool error
            self._write_log(
                name,
                decision,
                provenance_count=len(provenance.sources),
                upstream_ms=(time.monotonic() - upstream_started) * 1000,
                error=f"upstream {server.name} failed: {describe_failure(error)}",
            )
            logger.warning(
                "upstream %s failed for %s: %s", server.name, name, describe_failure(error)
            )
            return tool_result_error(f"upstream {server.name} failed: {describe_failure(error)}")

        if request.action_kind is READ:
            self._record_sources(chain.task_id, chain.act, result)
        self._write_log(
            name,
            decision,
            provenance_count=len(provenance.sources),
            upstream_ms=(time.monotonic() - upstream_started) * 1000,
        )
        return result

    def _chain_for(
        self, *, claims: oidc.Claims | None, headers: Mapping[str, str] | None
    ) -> tuple[Chain | None, str]:
        """The chain for this call, or the reason there is none.

        `no-exchange` builds it from the headers the agent sends, which is the
        ablation's dishonesty made explicit. Every other mode takes it from the
        verified token. Both `tools/list` and `tools/call` come through here so
        the two cannot disagree about whose call this is.
        """
        if self.mode is Mode.no_exchange:
            return config.chain_from_headers(headers or {}, mode=self.mode), ""
        if claims is None:
            return None, "no verified token reached the gateway"
        try:
            chain = Chain(
                sub=claims.sub,
                act=claims.act.sub,
                task_id=claims.task_id or "",
                scopes=list(claims.scope),
                groups=list(claims.groups),
                token_exp=datetime.fromtimestamp(claims.exp, tz=UTC),
            )
        except ValueError as error:
            # A token whose claims cannot build a chain is a malformed token, not
            # a crash: `Chain` refuses an id that cannot name a run directory,
            # and a refusal the caller can read beats a traceback.
            return None, f"the token's claims cannot build a chain: {error}"
        return chain, ""

    def _record_sources(self, task_id: str, actor: str, result: CallToolResult) -> None:
        payload = payload_of(result)
        for block, record in extract_sources(payload):
            self.ledger.record(task_id, actor, as_source(block, record))

    # Decisions the gateway makes itself, and logging -----------------------

    def _refuse(self, tool: str, reason: str, chain: Chain | None = None) -> CallToolResult:
        """Refuse a call the gateway itself rejects, and record that it did.

        This runs before the engine, so there is no `Decision`. The line still
        goes to the task's `gateway.jsonl` when the call named a task, because
        the spec asks for one line per call and "the gateway refused this" is
        the outcome a reader most needs to see. A refusal that names no task
        (no token at all) can only go to the process log.
        """
        self._write_line(
            tool=tool,
            verdict=Verdict.deny.value,
            policy_ids=[],
            sub=chain.sub if chain else "",
            act=chain.act if chain else "",
            task_id=chain.task_id if chain else "",
            provenance_count=0,
            upstream_ms=0.0,
            error=reason,
        )
        logger.info("refused %s before evaluation: %s", tool, reason)
        return tool_result_error(reason)

    def _log_and_refuse(self, request: AuthzRequest, reasons: list[str]) -> CallToolResult:
        decision = Decision(
            verdict=Verdict.deny,
            policy_ids=[],
            reasons=reasons,
            request=request,
            mode=self.mode.value,
        )
        self.decision_log.append(decision)
        return self._denied(request.tool, decision)

    def _denied(self, tool: str, decision: Decision) -> CallToolResult:
        self._write_log(
            tool,
            decision,
            provenance_count=len(decision.request.provenance.sources),
            upstream_ms=0.0,
        )
        text = "\n".join(decision.reasons) or "denied"
        logger.info("denied %s: %s", tool, decision.reasons)
        return tool_result_error(text)

    def _write_log(
        self,
        tool: str,
        decision: Decision,
        *,
        provenance_count: int,
        upstream_ms: float,
        error: str = "",
    ) -> None:
        request = decision.request
        self._write_line(
            tool=tool,
            verdict=decision.verdict.value,
            policy_ids=list(decision.policy_ids),
            sub=request.chain.sub,
            act=request.chain.act,
            task_id=request.chain.task_id,
            provenance_count=provenance_count,
            upstream_ms=upstream_ms,
            error=error,
        )

    def _write_line(
        self,
        *,
        tool: str,
        verdict: str,
        policy_ids: list[str],
        sub: str,
        act: str,
        task_id: str,
        provenance_count: int,
        upstream_ms: float,
        error: str = "",
    ) -> None:
        """One line per call. `error` is what went wrong after the verdict.

        The verdict is the decision and the error is the outcome, so an allowed
        call whose upstream failed is `allow` with an error rather than a second
        verdict. `error` is absent from a line that has none, so the nine keys
        the spec names are the ones a clean call carries.
        """
        record = {
            "ts": self._now().isoformat().replace("+00:00", "Z"),
            "tool": tool,
            "verdict": verdict,
            "policy_ids": policy_ids,
            "sub": sub,
            "act": act,
            "task_id": task_id,
            "provenance_count": provenance_count,
            "upstream_ms": round(upstream_ms, 3),
        }
        if error:
            record["error"] = error
        if not task_id:
            logger.info(json.dumps(record, sort_keys=True))
            return
        path = task_dir(self.runs_dir, task_id) / GATEWAY_LOG_NAME
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def authorization_header(headers: Mapping[str, Any] | None) -> str | None:
    """The first `Authorization` header value, case-insensitively."""
    if not headers:
        return None
    for key, value in headers.items():
        text = key.decode("latin-1") if isinstance(key, bytes) else str(key)
        if text.lower() == "authorization":
            raw = value.decode("latin-1") if isinstance(value, bytes) else str(value)
            return raw
    return None


def parse_bearer(authorization: str | None) -> str | None:
    """The token from an `Authorization: Bearer <token>` value."""
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def request_headers(ctx: Any) -> Mapping[str, Any] | None:
    """The headers the transport attached to a request context, when it did."""
    request = getattr(ctx, "request", None)
    return getattr(request, "headers", None)


class GatewayServer:
    """Holds the low-level MCP server so the handlers can see request headers.

    The high-level tool manager builds a schema from a function signature, which
    a proxy with a schema it learned at runtime does not have. Registering the
    two handlers directly keeps the upstream's schema and gives each handler the
    request context, which is where the bearer is.
    """

    def __init__(self, gateway: Gateway) -> None:
        self.gateway = gateway

    async def list_tools(self, ctx: Any, params: Any) -> ListToolsResult:
        claims, token = self._identity(ctx)
        return ListToolsResult(tools=await self.gateway.list_tools(claims=claims, token=token))

    async def call_tool(self, ctx: Any, params: Any) -> CallToolResult:
        claims, token = self._identity(ctx)
        return await self.gateway.call_tool(
            params.name,
            dict(params.arguments or {}),
            claims=claims,
            token=token,
            headers=request_headers(ctx),
        )

    def _identity(self, ctx: Any) -> tuple[oidc.Claims | None, str]:
        if self.gateway.mode is Mode.no_exchange:
            return None, ""
        token = parse_bearer(authorization_header(request_headers(ctx)))
        if token is None:
            raise GatewayError("no bearer token on the request")
        return self.gateway.verify(token), token


def build_server(gateway: Gateway) -> Server:
    """The low-level MCP server with the two handlers bound to `gateway`."""
    handlers = GatewayServer(gateway)
    return Server(
        name="warrant",
        version="0.0.0",
        instructions=(
            "Warrant is the gateway to the underlying resource servers. It verifies the "
            "on-behalf-of token for the warrant audience, decides each call, and forwards "
            "the allowed ones. Tool names are prefixed with the server they belong to."
        ),
        on_list_tools=handlers.list_tools,
        on_call_tool=handlers.call_tool,
    )


def build_app(
    gateway: Gateway,
    *,
    issuer: str | None = None,
    key: object | None = None,
    transport_security: Any | None = None,
) -> Starlette:
    """The streamable-HTTP ASGI app with bearer verification around it.

    The middleware refuses a token that does not name the `warrant` audience
    with `401` before a handler runs, which is the boundary an agent cannot
    skip. The handler verifies again from the same header, so the decision path
    does not depend on the middleware's context reaching its task.
    """
    server = build_server(gateway)
    app = server.streamable_http_app(
        streamable_http_path=gateway.settings.warrant_gateway_path,
        host=gateway.settings.warrant_gateway_host,
        transport_security=transport_security,
    )
    if gateway.mode is not Mode.no_exchange:
        app.add_middleware(
            BearerAuthMiddleware,
            audience=gateway.settings.warrant_audience,
            issuer=issuer if issuer is not None else gateway._issuer,
            key=key if key is not None else gateway._key,
        )
    return app
