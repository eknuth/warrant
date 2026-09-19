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
   sends in the call body reaches the request. W11 then fills the taint and
   target fields from the task's `TaskState`: the sources its reads recorded,
   the secrets they carried, and the target the first call named.
4. Calls `engine.evaluate()`. An allow forwards the call upstream with a bearer
   Warrant exchanges for that upstream's audience, a deny returns the policy
   reasons as a tool error, and an escalate goes to the adjudicator. An approved
   escalation mints a time-boxed grant, logs the call as allowed by that grant,
   and forwards it. A refused escalation returns the adjudicator's reason. A
   deferred or discarded verdict returns `escalated: pending human review` and
   records the call in `runs/queue.jsonl` for a person. A grant minted earlier,
   by the adjudicator or by the queue CLI, is checked before the engine and
   turns the call into an allow on its own.
5. On an allowed read, records each provenance block the upstream returned in
   the ledger and in the task state, so the next call in the task is decided
   with it. The ledger is the evidence on disk; the task state is the text the
   content taint matches against, and it is in memory only.

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
from starlette.responses import JSONResponse
from starlette.routing import Route

from servers.common.auth import BearerAuthMiddleware
from warrant import config, oidc
from warrant.adjudicator import (
    Adjudication,
    AdjudicatorClient,
    AdjudicatorSettings,
    EscalationAdjudicator,
    record_verdict,
)
from warrant.config import RUNS_DIR, Mode, Taint, bad_task_id, task_dir
from warrant.engine import PolicyEngine
from warrant.grants import SOURCE_ADJUDICATOR, Grant, GrantStore, grant_policy_id
from warrant.graph import Graph
from warrant.jev import JevClient
from warrant.log import DecisionLog
from warrant.models import (
    ActionKind,
    AdjudicationDecision,
    AdjudicatorVerdict,
    AuthzRequest,
    Chain,
    Decision,
    Source,
    Tier,
    Verdict,
)
from warrant.provenance import Ledger, classify
from warrant.queue import Queue
from warrant.resources import extract_resource, resolve_resource
from warrant.subjects import SubjectFetcher, fetch_subject, subject_ref
from warrant.taint import TaskState

logger = logging.getLogger(__name__)

GATEWAY_LOG_NAME = "gateway.jsonl"

# The one path the runner polls before it spends anything. It is open by
# design: the mode it reports is not a secret, and a runner that needed a token
# to ask whether the process it just restarted is ready would be checking the
# wrong thing.
HEALTH_PATH = "/healthz"

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

# What a call whose escalation no verdict answered returns. The eval runner
# reads it as a block rather than a failure: the call did not run, and a person
# still has to answer it.
PENDING_TEXT = "escalated: pending human review"


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
    # The URL base the gateway fetches the realm's signing keys from when it
    # differs from the issuer a token must name. The compose gateway sets this
    # to the internal `keycloak` name while the expected issuer is the host's
    # `localhost`, so a host-minted token verifies in the container.
    warrant_oidc_discovery_issuer: str | None = None
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
    def key_source(self) -> str:
        """The URL base the signing keys are fetched from."""
        return self.warrant_oidc_discovery_issuer or self.issuer

    @property
    def token_endpoint(self) -> str:
        return f"{self.key_source}/protocol/openid-connect/token"


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


def extract_sources(payload: Any, *, dedupe: bool = True) -> list[tuple[dict[str, Any], Any]]:
    """Every provenance block in a tool result, with the record that carried it.

    The record is the mapping that directly holds the block, so a code-search
    match's record is the match and its `snippet` is available to the harvest.
    A block already found is not walked again.

    With `dedupe`, two blocks with the same system, kind, and id are one entry,
    which is what the ledger wants. The harvest passes false: a code search can
    return several matches in one file, each with its own snippet, and a key in
    the second match is still a secret.
    """
    found: list[tuple[dict[str, Any], Any]] = []
    seen: set[tuple[Any, Any, Any]] = set()

    def walk(value: Any, parent: Any) -> None:
        if isinstance(value, dict):
            if SOURCE_KEYS <= set(value):
                key = (value.get("system"), value.get("kind"), value.get("id"))
                if dedupe and key in seen:
                    return
                seen.add(key)
                found.append((dict(value), parent if parent is not None else value))
                return
            for item in value.values():
                walk(item, value)
        elif isinstance(value, (list, tuple)):
            for item in value:
                # The item is its own container, so a block inside a list
                # element belongs to that element rather than to the list's
                # parent.
                walk(item, None)

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

    The tier is the one `warrant.provenance.classify` gives, not the upstream's
    word alone. The forge knows its own membership and the database knows its
    record kinds, but only Warrant knows that a `.github/` file is an
    instruction surface and that a raw SQL read has no author to grade.
    """
    tier = block.get("author_tier")
    try:
        author_tier = Tier(tier)
    except ValueError:
        author_tier = Tier.unknown
    source = Source(
        system=str(block.get("system", "")),
        kind=str(block.get("kind", "")),
        id=str(block.get("id", "")),
        author=str(block.get("author", "")),
        author_tier=author_tier,
        digest=digest(record),
    )
    return source.model_copy(update={"author_tier": classify(source)})


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
        taint: Taint | None = None,
        now: Callable[[], datetime] | None = None,
        adjudicator: AdjudicatorClient | None = None,
        adjudicator_settings: AdjudicatorSettings | None = None,
        subject_fetcher: SubjectFetcher | None = None,
        queue: Queue | None = None,
        grants: GrantStore | None = None,
        jev: JevClient | None = None,
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
        # `Taint(...)` rather than the value as given, the same rule `mode`
        # follows: a bare string that happens to match would compare unequal
        # against `is` and quietly run the wrong taint set.
        self.taint = Taint(taint) if taint is not None else config.current_taint()
        self._now = now or (lambda: datetime.now(UTC))
        self.adjudicator_settings = adjudicator_settings or AdjudicatorSettings()
        # The default adjudicator builds its provider on the first escalation,
        # so a process that never escalates needs no adjudicator credential.
        self.adjudicator = adjudicator or EscalationAdjudicator(settings=self.adjudicator_settings)
        self.subject_fetcher = subject_fetcher or fetch_subject
        self.queue = queue or Queue(self.runs_dir)
        self.grants = grants or GrantStore(self.runs_dir)
        # Constructed always so a caller has one object to fake; it reads no key
        # until a question is asked, so a process that never runs a Jev ablation
        # never needs the credential.
        self.jev = jev or JevClient()
        self._tools: dict[str, list[Tool]] = {}
        # The no-exchange ablation has no subject token, so the gateway reaches
        # the upstreams as itself. The client-credentials token is minted once
        # per process and reused; the process is recreated per eval cell.
        self._service_token: str | None = None
        # One `TaskState` per task and actor. The actor is part of the key for the
        # same reason the ledger keys on it: an agent writes its own task id, so
        # keying on the id alone would let one agent fill another agent's taint.
        self._tasks: dict[tuple[str, str], TaskState] = {}

    # Bearer verification ---------------------------------------------------

    def verify(self, token: str) -> oidc.Claims:
        """Verify an incoming token for the gateway's audience."""
        return oidc.verify(
            token,
            self.settings.warrant_audience,
            key=self._key,
            issuer=self._issuer,
            discovery_issuer=self.settings.key_source,
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
        the gateway would have no action kind to decide it with; and, in the
        modes where the engine decides, a tool the graph knows but the acting
        agent's allowlist does not hold is not offered, because the baseline
        permit refuses it anyway and the model should not be handed a call it
        cannot make. `_discover` caches the full per-server list, so the
        per-actor narrowing is a filter over that cache on every request.

        `prompt-only` is the exception. That mode makes every decision allow
        without evaluating a policy, and it is the ablation column the matrix is
        measured against. Filtering by the graph's allowlist there would add a
        control the other ablations do not have, so the discovered surface is
        returned whole and the ablation stays policy-free.

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
        if self.mode is Mode.prompt_only:
            return tools
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

        `no-exchange` has no subject token at all, so it takes the service
        credential path below: the ablation is about the chain the gateway
        decides on, not about the credential the upstreams see.
        """
        if self.mode is Mode.no_exchange:
            return await self.service_token()
        if not subject_token:
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

    async def service_token(self) -> str:
        """A client-credentials bearer for the upstreams, for `no-exchange`.

        The ablation has no subject token to exchange, so the gateway reaches
        the upstreams as itself with the broad service credential. The warrant
        client's service account carries `warrant-obo`, whose mappers give the
        token the upstream audiences and an `act` equal to `azp`, which is what
        the resource servers verify. The token is minted once per process: the
        gateway is recreated per eval cell, and a mint per call would double
        every upstream round trip.
        """
        if self._service_token is not None:
            return self._service_token
        secret = self.settings.warrant_agent_client_secret
        if not secret:
            logger.warning("no client secret for the no-exchange service token")
            return ""
        try:
            async with httpx.AsyncClient(
                timeout=20.0, transport=self._exchange_transport
            ) as client:
                response = await client.post(
                    self.settings.token_endpoint,
                    auth=(self.settings.warrant_client_id, secret),
                    data={"grant_type": "client_credentials"},
                )
        except httpx.HTTPError as error:
            logger.warning("no-exchange service token request failed: %s", error)
            return ""
        if response.status_code != 200:
            logger.warning(
                "no-exchange service token refused: HTTP %d %s",
                response.status_code,
                response.text[:300],
            )
            return ""
        self._service_token = str(response.json()["access_token"])
        return self._service_token

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
        if self.taint in (Taint.content, Taint.jev):
            # `TAINT=content` runs the content rule alone, and `TAINT=jev` runs
            # the Jev rule alone. The sources stay in the request so the decision
            # line records what was read; the flag is what keeps
            # `provenance.hasExternal` from firing the task rule.
            provenance = provenance.model_copy(update={"task_taint": False})
        resource_name = extract_resource(row.resource_kind, arguments)
        # The resolved name, before redaction. The task's named target and the
        # `targetOutsideTask` comparison both use it, so a target named before a
        # value was harvested as a secret still matches after.
        resolved = resolve_resource(self.graph, row.resource_kind, resource_name)

        # The task's named target comes from its first exchange, which here is
        # the first call whose arguments resolve to a resource. `docs/provenance.md`
        # records why the call's arguments name it rather than a token claim.
        state = self._task_state(chain.task_id, chain.act)
        if not state.targets_named:
            state.name_target(row.resource_kind, resolved)
        # A resource that is a secret is replaced with its digest before it
        # enters the request, so the decision line carries the digest and a value
        # that names no row in the graph. The replacement is whole-value or
        # key-shaped rather than a substring: `repo-acme-widgets` stays what it
        # is even when `acme-widgets` is a known secret.
        request = AuthzRequest(
            chain=chain,
            tool=name,
            action_kind=ActionKind(row.action_kind),
            resource=state.redact_resource(resolved),
            args_digest=args_digest(arguments),
            provenance=provenance,
            ts=self._now(),
        )

        context = state.context_for(
            request,
            arguments,
            exclude=[resource_name or ""],
            resource_kind=row.resource_kind,
            resource=resolved,
        )
        request.overlap_sources = context["overlap_sources"]
        request.overlap_external = context["overlap_external"]
        request.args_touch_secret = context["args_touch_secret"]
        request.target_outside_task = context["target_outside_task"]
        request.overlap_details = context["overlap_details"]

        # An unknown agent is refused before the classifier is asked, so a call
        # the harness would not run never spends a Jev request.
        if self.graph.agent(chain.act) is None:
            return self._log_and_refuse(request, ["unknown agent"])

        # W24. The two Jev ablations ask the classifier here, after the read set
        # and the pending call are known and before the engine decides. The
        # answer is recorded on the request, so the decision line carries the
        # latency and token cost of every call. A failed call fails closed in
        # `JevClient`, so a classifier that did not answer never allows a call.
        if self.mode is Mode.jev_only:
            agent_row = self.graph.agent(chain.act)
            resource_row = self.graph.resource(request.resource)
            owner_row = (
                self.graph.human(agent_row.owner_human_id)
                if agent_row is not None and agent_row.owner_human_id
                else None
            )
            choice, call = await self.jev.disposition(
                state=state,
                request=request,
                arguments=arguments,
                resolved_resource=resolved,
                agent_row=agent_row,
                owner_row=owner_row,
                resource_row=resource_row,
            )
            request.jev_choice = choice
            request.jev_calls.append(call)
        elif self.taint is Taint.jev and request.action_kind in (
            ActionKind.write,
            ActionKind.send,
        ):
            derived, call = await self.jev.derived(
                state=state,
                request=request,
                arguments=arguments,
                resolved_resource=resolved,
            )
            request.derived = derived
            request.jev_calls.append(call)

        # A grant is checked before the engine. An approval answered this exact
        # tool and resource for this task, so the policy set is not consulted and
        # the line names the grant that allowed it.
        grant = self.grants.find(
            task_id=chain.task_id, tool=name, resource=request.resource, now=self._now()
        )
        if grant is not None:
            decision = self._granted(request, grant)
            self._append_decision(decision)
        else:
            decision = self.engine.evaluate(request)
            if decision.verdict is Verdict.escalate:
                adjudication = await self._review(request, decision)
                decision.adjudication = adjudication.verdict
                self._append_decision(decision)
                if adjudication.verdict is None or (
                    adjudication.verdict.decision is AdjudicationDecision.defer
                ):
                    return self._deferred(name, request, decision, adjudication)
                if adjudication.verdict.decision is AdjudicationDecision.deny:
                    return self._adjudicated_deny(name, request, decision, adjudication)
                box = adjudication.verdict.time_box_minutes
                if box is None:
                    # `AdjudicatorVerdict` refuses an approval without a box, so
                    # this guards a verdict built outside the model.
                    return self._deferred(
                        name,
                        request,
                        decision,
                        Adjudication(reason="the approval carried no time box"),
                    )
                self._record_adjudication(request, adjudication.verdict)
                grant = self.grants.mint(
                    task_id=chain.task_id,
                    tool=name,
                    resource=request.resource,
                    minutes=box,
                    source=SOURCE_ADJUDICATOR,
                    now=self._now(),
                )
                decision = self._granted(request, grant)
                self._append_decision(decision)
                logger.info(
                    "adjudicator approved %s for task %s: grant %s for %d minutes",
                    name,
                    chain.task_id,
                    grant.id,
                    box,
                )
            else:
                self._append_decision(decision)
        if decision.verdict is Verdict.deny:
            return self._denied(name, decision)

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
                incident_id=claims.incident_id,
            )
        except ValueError as error:
            # A token whose claims cannot build a chain is a malformed token, not
            # a crash: `Chain` refuses an id that cannot name a run directory,
            # and a refusal the caller can read beats a traceback.
            return None, f"the token's claims cannot build a chain: {error}"
        return chain, ""

    def _task_state(self, task_id: str, actor: str) -> TaskState:
        """The taint state for one task and actor, created on first use."""
        key = (task_id, actor)
        state = self._tasks.get(key)
        if state is None:
            state = TaskState(task_id=task_id, taint=self.taint)
            self._tasks[key] = state
        return state

    def _record_sources(self, task_id: str, actor: str, result: CallToolResult) -> None:
        """Record a read's sources in the ledger and its taint in the task state.

        The ledger is the evidence and the task state is the working memory. The
        state is not updated under `no-provenance`, because that ablation drops
        everything that depends on what was read, and a content taint computed
        from a state the ledger refuses to hold would be a check the ablation did
        not remove.
        """
        payload = payload_of(result)
        # Every occurrence for the harvest, the deduped set for the ledger. A
        # code search returns several matches in one file, and the second
        # match's snippet is a source of secrets too.
        occurrences = [
            (as_source(block, record), record)
            for block, record in extract_sources(payload, dedupe=False)
        ]
        recorded: set[tuple[str, str, str]] = set()
        sources = []
        for source, _ in occurrences:
            key = (source.system, source.kind, source.id)
            if key in recorded:
                continue
            recorded.add(key)
            sources.append(source)
            self.ledger.record(task_id, actor, source)
        if self.mode is Mode.no_provenance:
            return
        self._task_state(task_id, actor).on_read(
            payload=payload,
            sources=sources,
            records=occurrences,
        )

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
            chain_source=request.chain.source,
        )
        self.decision_log.append(decision)
        return self._denied(request.tool, decision)

    # Escalation: the adjudicator, the queue, and grants ---------------------

    async def _review(self, request: AuthzRequest, decision: Decision) -> Adjudication:
        """Fetch the subject and ask the adjudicator, deferring on any failure.

        The subject comes from the ledger, and the fetch uses Warrant's own
        credential. Nothing here raises: a call that cannot be adjudicated is a
        call for a person, not a failed call.
        """
        ref = subject_ref(request.provenance)
        if ref is None:
            return Adjudication(
                reason=(
                    f"the ledger for task {request.chain.task_id} names no ticket or issue "
                    "to cite as the subject"
                )
            )
        try:
            subject = await self.subject_fetcher(ref)
        except Exception as error:  # noqa: BLE001 - a failed fetch defers the call
            return Adjudication(reason=f"the subject fetch failed: {describe_failure(error)}")
        if subject is None:
            return Adjudication(reason=f"the subject {ref.id} could not be fetched")
        try:
            return await self.adjudicator.review(
                request, request.provenance, subject, reasons=decision.reasons
            )
        except Exception as error:  # noqa: BLE001 - a failed adjudicator defers the call
            return Adjudication(reason=f"the adjudicator failed: {describe_failure(error)}")

    def _granted(self, request: AuthzRequest, grant: Grant) -> Decision:
        """The allow a grant produces, with the grant named as its policy."""
        return Decision(
            verdict=Verdict.allow,
            policy_ids=[grant_policy_id(grant)],
            reasons=[
                f"grant {grant.id} allows {grant.tool} on {grant.resource} "
                f"until {grant.expires_at.isoformat()}"
            ],
            request=request,
            mode=self.mode.value,
            chain_source=request.chain.source,
        )

    def _deferred(
        self,
        name: str,
        request: AuthzRequest,
        decision: Decision,
        adjudication: Adjudication,
    ) -> CallToolResult:
        """Queue a call no verdict answered and tell the agent it is pending."""
        reason = adjudication.reason
        if not reason and adjudication.verdict is not None:
            # A deferral with a rationale has said why it could not decide; the
            # person reading the queue should see that rather than a generic
            # sentence.
            reason = adjudication.verdict.rationale
        item = self.queue.add(
            request,
            reason=reason or "the adjudicator deferred the call",
            verdict=adjudication.verdict,
            raw=adjudication.raw,
            now=self._now(),
        )
        self._write_log(
            name,
            decision,
            provenance_count=len(request.provenance.sources),
            upstream_ms=0.0,
            error=PENDING_TEXT,
        )
        logger.info("escalation queued as %s: %s", item.id, adjudication.reason)
        return tool_result_error(PENDING_TEXT)

    def _adjudicated_deny(
        self,
        name: str,
        request: AuthzRequest,
        decision: Decision,
        adjudication: Adjudication,
    ) -> CallToolResult:
        """Record a refusal the adjudicator gave and return its reason."""
        verdict = adjudication.verdict
        if verdict is None:
            return self._deferred(name, request, decision, adjudication)
        self._record_adjudication(request, verdict)
        refusal = Decision(
            verdict=Verdict.deny,
            policy_ids=[],
            reasons=[verdict.rationale or "the adjudicator refused the call"],
            request=request,
            mode=self.mode.value,
            chain_source=request.chain.source,
        )
        self._append_decision(refusal)
        self._write_log(
            name,
            refusal,
            provenance_count=len(request.provenance.sources),
            upstream_ms=0.0,
        )
        text = verdict.rationale or "the adjudicator refused the call"
        logger.info("adjudicator refused %s: %s", name, text)
        return tool_result_error(text)

    def _record_adjudication(self, request: AuthzRequest, verdict: AdjudicatorVerdict) -> None:
        """Append one accepted verdict to the task's `adjudications.jsonl`."""
        record_verdict(self.runs_dir, request.chain.task_id, verdict)

    def _append_decision(self, decision: Decision) -> None:
        """Write one decision line. The engine evaluates; the gateway appends.

        The gateway appends because an escalated call's line has to carry the
        verdict the adjudicator answered with, and that answer is only known
        after the evaluation.
        """
        self.decision_log.append(decision)

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
        return ListToolsResult(
            tools=await self.gateway.list_tools(
                claims=claims, token=token, headers=request_headers(ctx)
            )
        )

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


def health_payload() -> dict[str, Any]:
    """The mode and taint this process imported, for the runner's health check.

    The values come from `warrant.config`, which reads `WARRANT_MODE` and
    `TAINT` once at import, so the payload is what this process is actually
    running and not what a caller asked for. The runner restarts the process,
    polls this, and records the mode it confirmed.
    """
    return {
        "status": "ok",
        "mode": config.current_mode().value,
        "taint": config.current_taint().value,
    }


async def _healthz(_request: Any) -> JSONResponse:
    """`GET /healthz`: the process is up and running the named ablation."""
    return JSONResponse(health_payload())


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

    `/healthz` is exempt from the bearer check in every mode, so the runner can
    confirm a restarted process without holding a token for it.
    """
    server = build_server(gateway)
    app = server.streamable_http_app(
        streamable_http_path=gateway.settings.warrant_gateway_path,
        host=gateway.settings.warrant_gateway_host,
        transport_security=transport_security,
        custom_starlette_routes=[Route(HEALTH_PATH, _healthz, methods=["GET"])],
    )
    if gateway.mode is not Mode.no_exchange:
        # No bearer middleware in `no-exchange`: that ablation's whole point is
        # that the agent sends headers instead of a token. `/healthz` is exempt
        # so the runner can poll a restarted process in every mode.
        app.add_middleware(
            BearerAuthMiddleware,
            audience=gateway.settings.warrant_audience,
            issuer=issuer if issuer is not None else gateway._issuer,
            key=key if key is not None else gateway._key,
            discovery_issuer=gateway.settings.key_source,
            open_paths={HEALTH_PATH},
        )
    return app
