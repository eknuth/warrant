"""A client for one or more MCP endpoints over streamable HTTP.

The triage agent reaches the Gitea MCP server through this, and W10 reaches the
postgres and mail servers through the same class with more endpoints. Each
endpoint carries its own bearer, because each is its own OAuth resource server
with its own audience in the token.

Every call is logged as one JSON line to `runs/<task_id>/calls.jsonl`. The line
carries the chain `{sub, act, task_id}`, the tool, a digest of the arguments and
a digest of the result, and the provenance block the tool returned when it
returned one. The values themselves are not logged: an issue body or a file's
contents are what the digests stand for. `sub` is the human's login and
`sub_id` is the token's own subject claim, so a line points at the signed token
without repeating an opaque identifier as the chain's subject.

Nothing here reads a credential or starts a server at import time.
"""

from __future__ import annotations

import hashlib
import json
import logging
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from pydantic_settings import BaseSettings, SettingsConfigDict

from agents.providers.base import ToolSchema
from agents.task import Chain

logger = logging.getLogger(__name__)

# The keys a forge provenance block carries. A dict with all of them is a
# `Source`; anything else is walked through looking for one.
SOURCE_KEYS = frozenset({"system", "kind", "id", "author", "author_tier"})

DEFAULT_TIMEOUT = 60.0

# The gateway every agent reaches. `WARRANT_URL` in `.env` overrides it.
DEFAULT_WARRANT_URL = "http://localhost:9100/mcp"


class MCPError(RuntimeError):
    """A call this client could not make or answer."""


@dataclass(frozen=True)
class Endpoint:
    """One MCP server, its streamable-HTTP URL, and the headers it carries.

    `bearer` is the verified token in every mode but `no-exchange`, where it is
    empty and `headers` carries the self-reported `X-Warrant-*` chain instead.
    """

    url: str
    bearer: str
    name: str = "mcp"
    headers: dict[str, str] = field(default_factory=dict)


class GatewaySettings(BaseSettings):
    """The gateway URL, read from `.env` the way every other setting is."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    warrant_url: str = DEFAULT_WARRANT_URL


def warrant_endpoint(
    bearer: str,
    *,
    url: str | None = None,
    name: str = "warrant",
    headers: dict[str, str] | None = None,
) -> Endpoint:
    """The one endpoint an agent is configured to reach.

    An agent holds an on-behalf-of token for `warrant` and nothing else; the
    per-upstream tokens are the gateway's to mint. `url` overrides the
    environment, which is what a test or the CLI flag uses. `headers` is the
    `no-exchange` ablation's self-reported chain, sent with an empty bearer.
    """
    return Endpoint(
        url=url or GatewaySettings().warrant_url,
        bearer=bearer,
        name=name,
        headers=dict(headers or {}),
    )


@dataclass
class CallResult:
    """What one tool call returned, in the shapes the loop needs."""

    tool: str
    endpoint: str
    payload: Any
    text: str
    is_error: bool
    sources: list[dict[str, Any]] = field(default_factory=list)

    @property
    def content(self) -> str:
        """The string handed back to the model as the tool's answer.

        The MCP text block is the server's own rendering of the result for a
        model to read, and the structured payload is the machine-readable copy
        beside it. The postgres server keeps `secrets` out of the text and puts
        it in the structured payload, so handing the payload to the model would
        put every key value in the model's input a second time. The text block
        wins whenever there is one; the payload is the fallback for a server
        that returns structured content and no text.
        """
        if self.text:
            return self.text
        if self.payload is not None:
            return json.dumps(self.payload, sort_keys=True, default=str)
        return self.text


def digest(value: Any) -> str:
    """A stable sha256 over any JSON-shaped value.

    Canonical JSON (sorted keys, no extra whitespace) is what makes the digest
    the same across runs for the same value. The digest stands in for the value
    in a log line, so an issue body or a file's contents never lands in one.
    """
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def extract_sources(payload: Any) -> list[dict[str, Any]]:
    """Every provenance block in a tool result, in the order it appears.

    A list result carries one per element, and a search result buries them one
    level down. A block already found is not walked again, and two blocks with
    the same system, kind, and id are one entry, so a repeated read does not
    duplicate it.
    """
    found: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any, Any]] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if SOURCE_KEYS <= set(value):
                key = (value.get("system"), value.get("kind"), value.get("id"))
                if key not in seen:
                    seen.add(key)
                    found.append(dict(value))
                return
            for item in value.values():
                walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item)

    walk(payload)
    return found


def call_record(
    *,
    chain: Chain,
    tool: str,
    endpoint: str,
    args: dict[str, Any],
    result_value: Any,
    is_error: bool,
    sources: list[dict[str, Any]],
    now: datetime | None = None,
) -> dict[str, Any]:
    """One tool call's log line as a dict, before it is serialized.

    The keys are fixed and the chain is on every one: `ts`, `task_id`, `sub`,
    `sub_id`, `act`, `tool`, `endpoint`, `args_digest`, `result_digest`,
    `is_error`, and `source` when the result carried exactly one provenance
    block. A read that returned several carries them in `sources` instead.
    """
    moment = now or datetime.now(UTC)
    record: dict[str, Any] = {
        "ts": moment.isoformat().replace("+00:00", "Z"),
        "task_id": chain.task_id,
        "sub": chain.sub,
        "sub_id": chain.sub_id,
        "act": chain.act,
        "tool": tool,
        "endpoint": endpoint,
        "args_digest": digest(args),
        "result_digest": digest(result_value),
        "is_error": is_error,
    }
    if len(sources) == 1:
        record["source"] = sources[0]
    elif sources:
        record["sources"] = sources
    return record


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    """Append one JSON object as a line, creating the directory if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")


class MCPClient:
    """One session per endpoint, opened for the length of a task.

    Use it as an async context manager. `list_tools` collects the tool surface
    across every endpoint and remembers which session serves each name; `call`
    routes by name and logs the call.
    """

    def __init__(
        self,
        endpoints: Endpoint | list[Endpoint],
        *,
        chain: Chain,
        runs_dir: Path | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._endpoints = list(endpoints) if isinstance(endpoints, (list, tuple)) else [endpoints]
        if not self._endpoints:
            raise MCPError("at least one endpoint is required")
        self.chain = chain
        self._timeout = timeout
        self._log_path = (
            Path(runs_dir) / chain.task_id / "calls.jsonl" if runs_dir is not None else None
        )
        self._stack = AsyncExitStack()
        self._sessions: dict[str, ClientSession] = {}
        self._tools: dict[str, tuple[str, ClientSession]] = {}
        # The per-endpoint HTTP client, kept so the bearer a session carries can
        # be read back without a call. It is also what makes the per-task token
        # test assert the header the request uses rather than the endpoint the
        # client was built from.
        self._http: dict[str, httpx.AsyncClient] = {}

    async def __aenter__(self) -> MCPClient:
        try:
            for endpoint in self._endpoints:
                request_headers = dict(endpoint.headers)
                if endpoint.bearer:
                    request_headers["Authorization"] = f"Bearer {endpoint.bearer}"
                http = await self._stack.enter_async_context(
                    httpx.AsyncClient(headers=request_headers, timeout=self._timeout)
                )
                self._http[endpoint.name] = http
                streams = await self._stack.enter_async_context(
                    streamable_http_client(endpoint.url, http_client=http)
                )
                read, write = streams[0], streams[1]
                session = await self._stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                self._sessions[endpoint.name] = session
        except BaseException:
            await self._stack.aclose()
            raise
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self._stack.aclose()

    async def list_tools(self) -> list[ToolSchema]:
        """Every tool on every endpoint, in endpoint order.

        Two endpoints offering the same tool name is a configuration mistake;
        the first one wins and the collision is logged, rather than a later
        endpoint silently shadowing an earlier one.
        """
        schemas: list[ToolSchema] = []
        for endpoint in self._endpoints:
            session = self._sessions[endpoint.name]
            result = await session.list_tools()
            for tool in result.tools:
                if tool.name in self._tools:
                    logger.warning(
                        "tool %s is offered by more than one endpoint; keeping %s",
                        tool.name,
                        self._tools[tool.name][0],
                    )
                    continue
                self._tools[tool.name] = (endpoint.name, session)
                schemas.append(
                    ToolSchema(
                        name=tool.name,
                        description=tool.description or "",
                        input_schema=tool.input_schema or {"type": "object", "properties": {}},
                    )
                )
        return schemas

    async def call(self, name: str, args: dict[str, Any]) -> CallResult:
        """Call one tool and log the call, whatever the result.

        The log line is written for a call that raises too, because a failed call
        is exactly what an audit reader wants to see. It used to be written only
        after a successful return, so a bad tool name or a transport error killed
        the run and left the run directory with no record of the attempt.
        """
        if name not in self._tools:
            await self._log_failure(name, args, endpoint="", error=f"unknown tool {name!r}")
            raise MCPError(f"unknown tool {name!r}; call list_tools first")
        endpoint_name, session = self._tools[name]
        try:
            result = await session.call_tool(name, arguments=args)
        except Exception as error:
            reason = f"{type(error).__name__}: {error}"
            await self._log_failure(name, args, endpoint=endpoint_name, error=reason)
            raise
        call = self._result_from(name, endpoint_name, result)
        if self._log_path is not None:
            append_jsonl(
                self._log_path,
                call_record(
                    chain=self.chain,
                    tool=name,
                    endpoint=endpoint_name,
                    args=args,
                    result_value=call.payload if call.payload is not None else call.text,
                    is_error=call.is_error,
                    sources=call.sources,
                ),
            )
        return call

    async def _log_failure(
        self, name: str, args: dict[str, Any], *, endpoint: str, error: str
    ) -> None:
        """Record a call that raised, so a failed attempt is in the run record.

        The line carries `is_error` and the error text in place of a result
        digest, which is the difference between "this call returned an error"
        and "this call never completed".
        """
        if self._log_path is None:
            return
        record = call_record(
            chain=self.chain,
            tool=name,
            endpoint=endpoint,
            args=args,
            result_value={"error": error},
            is_error=True,
            sources=[],
        )
        record["raised"] = True
        append_jsonl(self._log_path, record)

    def _result_from(self, name: str, endpoint_name: str, result: Any) -> CallResult:
        content = getattr(result, "content", None) or []
        text = "".join(
            block.text
            for block in content
            if getattr(block, "type", None) == "text" and getattr(block, "text", None)
        )
        payload = getattr(result, "structured_content", None)
        if payload is None and text:
            try:
                payload = json.loads(text)
            except ValueError:
                payload = None
        return CallResult(
            tool=name,
            endpoint=endpoint_name,
            payload=payload,
            text=text,
            is_error=bool(getattr(result, "is_error", False)),
            sources=extract_sources(payload),
        )
