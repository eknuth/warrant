"""Bearer-token verification shared by Warrant's MCP resource servers.

Every resource server in this stack is an OAuth resource server: the only
credential a caller presents is an on-behalf-of token Keycloak minted for it,
and the server refuses anything it cannot verify. This module is that check,
written once so gitea-mcp, postgres-mcp, and mail-mcp enforce the same rules.

The check itself lives in `warrant.oidc.verify`: signature against the issuer's
JWKS, expiry, the audience naming this server, and an `act` claim that agrees
with `azp`. This module adds the HTTP layer around it. It reads the
`Authorization` header, refuses a missing or malformed one with its own error,
and turns any refusal into `401` with a `WWW-Authenticate` header. An issuer
that cannot be reached is a `503` rather than a `401`, because "I could not
check" and "your token is bad" are different answers and `warrant.oidc` keeps
them apart on purpose.

The verified claims are attached in two places. They go into a `ContextVar`,
which is what a tool handler in the same task reads, and into the ASGI
`scope["state"]`, which is there for anything that holds the scope. A caller
inside a handler should use `current_claims()`; if that returns `None` the
handler is on a task the middleware's context did not reach, and it should
verify the request's own `Authorization` header with `verify_authorization`
rather than proceed unauthenticated.

Nothing here reads a secret or starts a server at import time, and the app
construction lives with each server, so importing this module in a test is
free.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from contextvars import ContextVar
from typing import Any

import httpx
from starlette.responses import JSONResponse

from warrant.oidc import Claims, OidcError, verify

logger = logging.getLogger(__name__)

_CLAIMS: ContextVar[Claims | None] = ContextVar("warrant_verified_claims", default=None)

BEARER_SCHEME = "bearer"


class MissingBearer(OidcError):
    """No bearer token was presented, or the header was not a bearer token."""


def current_claims() -> Claims | None:
    """The claims the middleware verified for the request in this context."""
    return _CLAIMS.get()


def attach_claims(claims: Claims) -> None:
    """Attach verified claims to the current context."""
    _CLAIMS.set(claims)


def parse_bearer(authorization: str | None) -> str:
    """Return the token from an `Authorization: Bearer <token>` header.

    A missing header, a different scheme, or an empty token is a
    `MissingBearer`. The scheme is compared case-insensitively, which RFC 7235
    requires.
    """
    if not authorization:
        raise MissingBearer("no Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != BEARER_SCHEME or not token.strip():
        raise MissingBearer("Authorization header is not a Bearer token")
    return token.strip()


def verify_authorization(
    authorization: str | None,
    *,
    audience: str,
    issuer: str | None = None,
    key: object | None = None,
) -> Claims:
    """Verify an `Authorization` header value for `audience` and return claims.

    `issuer` and `key` default to the running stack; a test passes its own so
    no server is needed. Every refusal is an `OidcError` subclass, and a dead
    issuer is an `httpx.HTTPError`, exactly as `warrant.oidc.verify` raises.
    """
    return verify(parse_bearer(authorization), audience, key=key, issuer=issuer)


class BearerAuthMiddleware:
    """ASGI middleware that refuses a request without a verifiable bearer.

    Every HTTP request, including the ones that only open or close a
    streamable-HTTP session, has to carry the token. Non-HTTP scopes (lifespan)
    pass through untouched.
    """

    def __init__(
        self,
        app: Any,
        *,
        audience: str,
        issuer: str | None = None,
        key: object | None = None,
    ) -> None:
        self.app = app
        self.audience = audience
        self.issuer = issuer
        self.key = key

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            name.decode("latin-1").lower(): value.decode("latin-1")
            for name, value in scope.get("headers", [])
        }
        try:
            claims = verify_authorization(
                headers.get("authorization"),
                audience=self.audience,
                issuer=self.issuer,
                key=self.key,
            )
        except MissingBearer as error:
            await self._reject(scope, receive, send, "invalid_request", str(error))
            return
        except OidcError as error:
            logger.warning("refused a bearer token: %s", error)
            await self._reject(scope, receive, send, "invalid_token", str(error))
            return
        except httpx.HTTPError as error:
            # The issuer is unreachable. The token may be fine, so this is not a
            # 401: a caller that retries a 401 with a fresh token would loop.
            logger.warning("could not reach the token issuer: %s", error)
            await self._reject(
                scope,
                receive,
                send,
                "temporarily_unavailable",
                "could not reach the token issuer",
                status_code=503,
            )
            return

        attach_claims(claims)
        state = scope.setdefault("state", {})
        state["claims"] = claims
        await self.app(scope, receive, send)

    async def _reject(
        self,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
        error: str,
        description: str,
        *,
        status_code: int = 401,
    ) -> None:
        response = JSONResponse(
            {"error": error, "error_description": description},
            status_code=status_code,
            headers={"WWW-Authenticate": f'Bearer error="{error}"'},
        )
        await response(scope, receive, send)


def header_value(headers: Mapping[str, str] | None, name: str) -> str | None:
    """Case-insensitive header lookup that also accepts a plain mapping.

    The MCP transport hands handlers a `Mapping[str, str]` whose key case is
    not guaranteed, so a handler that verifies from the request's own headers
    uses this rather than `headers.get`.
    """
    if not headers:
        return None
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None
