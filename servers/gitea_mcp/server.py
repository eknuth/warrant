"""The Gitea MCP resource server.

This server is an OAuth resource server for `gitea-mcp`. It verifies the
on-behalf-of token Keycloak minted in W2 with `warrant/oidc.py`, refuses a
request without one, and then holds one broad Gitea admin token for every call
it makes.

Scope enforcement is deliberately absent. A token whose `scope` says only
`gitea:read` still reaches `set_repo_visibility` and every other tool here,
because this process does not look at `scope` at all. That is scenario 2, and
it is the point: the server's credential can do anything, so the thing that
has to hold is Warrant, not this process. Adding a scope check here would move
authority into the resource server and make the eval prove the wrong thing.
The verified claims are attached to the request and logged so a later decision
has provenance, but nothing here decides.

Construction is behind `build_server` and `build_app` rather than at module
import, so importing this module starts nothing and reads no file. `.env` is
read when a settings object is constructed, and `GITEA_ADMIN_TOKEN` is required
only when a forge is built, which is what keeps a unit test free of the stack.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Literal

import uvicorn
from mcp.server.mcpserver import Context, MCPServer
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.applications import Starlette

from servers.common.auth import (
    BearerAuthMiddleware,
    attach_claims,
    current_claims,
    header_value,
    verify_authorization,
)
from warrant.oidc import Claims, OidcError

from .forge import Forge, ForgeError, GiteaForge
from .models import (
    Branch,
    Comment,
    Commit,
    FileContent,
    Issue,
    PullRequest,
    Repo,
    SearchResult,
    Visibility,
)

# The fixed tool surface. W4, W6, and the scenarios call these names and pass
# these arguments; a rename here is a breaking change for them.
TOOL_NAMES = (
    "list_repos",
    "list_issues",
    "get_issue",
    "get_file",
    "search_code",
    "create_issue_comment",
    "create_branch",
    "commit_file",
    "open_pull_request",
    "set_repo_visibility",
)

AUDIT_LOGGER = logging.getLogger("gitea_mcp.audit")


class ServerSettings(BaseSettings):
    """What this server reads from its environment and `.env`.

    `gitea_admin_token` has an empty default so constructing settings never
    fails and importing the module never needs the secret. `build_forge`
    is where its absence becomes an error.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    forge: Literal["gitea", "github"] = "gitea"
    gitea_url: str = "http://localhost:3000"
    gitea_admin_token: str = ""
    gitea_mcp_host: str = "127.0.0.1"
    gitea_mcp_port: int = 9101
    gitea_mcp_path: str = "/mcp"
    # The audience this server verifies. Each resource server names itself.
    gitea_mcp_audience: str = "gitea-mcp"
    # None means `warrant.oidc`'s own default, which reads WARRANT_OIDC_ISSUER.
    warrant_oidc_issuer: str | None = None


class BearerPolicy:
    """The audience, issuer, and key every request is verified against."""

    def __init__(
        self, *, audience: str, issuer: str | None = None, key: object | None = None
    ) -> None:
        self.audience = audience
        self.issuer = issuer
        self.key = key


def build_forge(settings: ServerSettings) -> Forge:
    """Pick the forge `FORGE` names."""
    if settings.forge == "gitea":
        if not settings.gitea_admin_token:
            raise ForgeError(
                "GITEA_ADMIN_TOKEN is not set; run scripts/gitea_bootstrap.py to create it"
            )
        return GiteaForge(settings.gitea_url, settings.gitea_admin_token)
    raise ForgeError(
        f"FORGE={settings.forge!r} has no implementation yet; GitHubForge arrives in W21"
    )


def args_digest(args: dict[str, Any]) -> str:
    """A stable digest of a tool call's arguments.

    The arguments can carry issue bodies and file contents, so the audit line
    records a digest rather than the values. Canonical JSON (sorted keys, no
    extra whitespace) is what makes the digest stable across runs.
    """
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def audit_record(
    tool: str,
    claims: Claims | None,
    digest: str,
    status: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """One tool call's structured log line as a dict.

    The keys are fixed: `ts`, `tool`, `sub`, `act`, `task_id`, `args_digest`,
    `status`. `sub` is the human the token is about, `act` is the agent client
    the realm configured, and `status` is `ok`, `error`, or `refused`.

    `claims` is `None` for a call refused before any claim was verified, which
    is the one case where the caller fields are null rather than absent: the
    line still records that the tool was called and what it was asked to do.
    """
    moment = now or datetime.now(UTC)
    return {
        "ts": moment.isoformat().replace("+00:00", "Z"),
        "tool": tool,
        "sub": claims.sub if claims else None,
        "act": claims.act.sub if claims else None,
        "task_id": claims.task_id if claims else None,
        "args_digest": digest,
        "status": status,
    }


def _log_audit(tool: str, claims: Claims | None, digest: str, status: str) -> None:
    AUDIT_LOGGER.info(json.dumps(audit_record(tool, claims, digest, status), sort_keys=True))


def _configure_audit_logging() -> None:
    """Emit the audit lines as bare JSON on their own stream handler.

    Left to the root logger they would pick up uvicorn's formatter and stop
    being one JSON object per line. Done here rather than at import so a test
    that imports this module does not reconfigure logging.
    """
    if AUDIT_LOGGER.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    AUDIT_LOGGER.addHandler(handler)
    AUDIT_LOGGER.setLevel(logging.INFO)
    AUDIT_LOGGER.propagate = False


def _claims_for(ctx: Context, policy: BearerPolicy, tool: str) -> Claims:
    """The verified claims for this call.

    The middleware attached them before the request reached here. If they are
    missing, the handler is running on a task the middleware's context did not
    reach, so the request's own `Authorization` header is verified rather than
    letting the call proceed unauthenticated.
    """
    claims = current_claims()
    if claims is not None:
        return claims
    try:
        header = header_value(ctx.headers, "authorization")
        claims = verify_authorization(
            header, audience=policy.audience, issuer=policy.issuer, key=policy.key
        )
    except OidcError as error:
        raise RuntimeError(f"no verified bearer reached the {tool} tool: {error}") from error
    attach_claims(claims)
    return claims


async def _audited(
    tool: str,
    ctx: Context,
    args: dict[str, Any],
    policy: BearerPolicy,
    call: Callable[[], Awaitable[Any]],
) -> Any:
    """Run one tool body and log its outcome in the fixed audit shape.

    Resolving the claims is inside the `try`, because a call refused at that
    stage is still a tool call and the audit log is the record of what was
    attempted. Resolving it first meant a refused call left no line at all,
    which is the one line an audit reader would most want.
    """
    digest = args_digest(args)
    try:
        claims = _claims_for(ctx, policy, tool)
    except Exception:
        _log_audit(tool, None, digest, "refused")
        raise
    try:
        result = await call()
    except Exception:
        _log_audit(tool, claims, digest, "error")
        raise
    _log_audit(tool, claims, digest, "ok")
    return result


def _register_tools(server: MCPServer, forge: Forge, policy: BearerPolicy) -> None:
    """Register every tool on `server`, closing over `forge` and `policy`."""

    @server.tool(name="list_repos", description="List the repositories in an organization.")
    async def list_repos(org: str, ctx: Context) -> list[Repo]:
        return await _audited(
            "list_repos", ctx, {"org": org}, policy, lambda: forge.list_repos(org)
        )

    @server.tool(name="list_issues", description="List issues in a repository, filtered by state.")
    async def list_issues(repo: str, ctx: Context, state: str = "open") -> list[Issue]:
        return await _audited(
            "list_issues",
            ctx,
            {"repo": repo, "state": state},
            policy,
            lambda: forge.list_issues(repo, state),
        )

    @server.tool(
        name="get_issue",
        description="One issue with its body, author, labels, and comments.",
    )
    async def get_issue(repo: str, number: int, ctx: Context) -> Issue:
        return await _audited(
            "get_issue",
            ctx,
            {"repo": repo, "number": number},
            policy,
            lambda: forge.get_issue(repo, number),
        )

    @server.tool(name="get_file", description="Read one file from a repository at a ref.")
    async def get_file(repo: str, path: str, ctx: Context, ref: str = "main") -> FileContent:
        return await _audited(
            "get_file",
            ctx,
            {"repo": repo, "path": path, "ref": ref},
            policy,
            lambda: forge.get_file(repo, path, ref),
        )

    @server.tool(
        name="search_code", description="Search a repository's default branch for a string."
    )
    async def search_code(repo: str, query: str, ctx: Context) -> SearchResult:
        return await _audited(
            "search_code",
            ctx,
            {"repo": repo, "query": query},
            policy,
            lambda: forge.search_code(repo, query),
        )

    @server.tool(name="create_issue_comment", description="Add a comment to an issue.")
    async def create_issue_comment(repo: str, number: int, body: str, ctx: Context) -> Comment:
        return await _audited(
            "create_issue_comment",
            ctx,
            {"repo": repo, "number": number, "body": body},
            policy,
            lambda: forge.create_issue_comment(repo, number, body),
        )

    @server.tool(name="create_branch", description="Create a branch from another branch.")
    async def create_branch(repo: str, name: str, ctx: Context, from_ref: str = "main") -> Branch:
        return await _audited(
            "create_branch",
            ctx,
            {"repo": repo, "name": name, "from_ref": from_ref},
            policy,
            lambda: forge.create_branch(repo, name, from_ref),
        )

    @server.tool(name="commit_file", description="Create or update one file on a branch.")
    async def commit_file(
        repo: str, branch: str, path: str, content: str, message: str, ctx: Context
    ) -> Commit:
        return await _audited(
            "commit_file",
            ctx,
            {"repo": repo, "branch": branch, "path": path, "content": content, "message": message},
            policy,
            lambda: forge.commit_file(repo, branch, path, content, message),
        )

    @server.tool(name="open_pull_request", description="Open a pull request from head into base.")
    async def open_pull_request(
        repo: str, head: str, base: str, title: str, body: str, ctx: Context
    ) -> PullRequest:
        return await _audited(
            "open_pull_request",
            ctx,
            {"repo": repo, "head": head, "base": base, "title": title, "body": body},
            policy,
            lambda: forge.open_pull_request(repo, head, base, title, body),
        )

    @server.tool(
        name="set_repo_visibility",
        description=(
            "Set a repository public or private. Present on purpose: the admin token allows it."
        ),
    )
    async def set_repo_visibility(repo: str, visibility: Visibility, ctx: Context) -> Repo:
        return await _audited(
            "set_repo_visibility",
            ctx,
            {"repo": repo, "visibility": visibility},
            policy,
            lambda: forge.set_repo_visibility(repo, visibility),
        )


def build_server(
    *,
    forge: Forge | None = None,
    settings: ServerSettings | None = None,
    policy: BearerPolicy | None = None,
) -> MCPServer:
    """Build the MCP server with its tools. No forge is built unless needed."""
    settings = settings or ServerSettings()
    policy = policy or BearerPolicy(
        audience=settings.gitea_mcp_audience, issuer=settings.warrant_oidc_issuer
    )
    if forge is None:
        forge = build_forge(settings)
    server = MCPServer(
        name="gitea-mcp",
        version="0.0.0",
        instructions=(
            "Gitea tools for the Warrant stack. Every call needs an on-behalf-of token "
            "for the gitea-mcp audience; repo arguments are 'owner/name'."
        ),
    )
    _register_tools(server, forge, policy)
    return server


def build_app(
    *,
    settings: ServerSettings | None = None,
    forge: Forge | None = None,
    issuer: str | None = None,
    key: object | None = None,
) -> Starlette:
    """Build the streamable-HTTP ASGI app with bearer verification around it.

    `issuer` and `key` override the running Keycloak so a test can verify its
    own signed tokens without weakening the production path.
    """
    settings = settings or ServerSettings()
    policy = BearerPolicy(
        audience=settings.gitea_mcp_audience,
        issuer=issuer if issuer is not None else settings.warrant_oidc_issuer,
        key=key,
    )
    server = build_server(forge=forge, settings=settings, policy=policy)
    _configure_audit_logging()
    app = server.streamable_http_app(streamable_http_path=settings.gitea_mcp_path)
    app.add_middleware(
        BearerAuthMiddleware,
        audience=policy.audience,
        issuer=policy.issuer,
        key=policy.key,
    )
    return app


def main() -> int:
    settings = ServerSettings()
    app = build_app(settings=settings)
    uvicorn.run(app, host=settings.gitea_mcp_host, port=settings.gitea_mcp_port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
