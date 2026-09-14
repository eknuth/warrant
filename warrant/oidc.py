"""Verify the on-behalf-of tokens Keycloak issues for the local stack.

Every resource server and Warrant itself decide from a token this module
verified. Verification is not just a signature check. A token is accepted only
when the signature matches the issuer's JWKS, it has not expired, the audience
names this resource server, and the delegation chain in it is internally
consistent.

The delegation chain is a pair of signed claims that must agree. `azp` names
the client the token was issued to. The `act` claim names the actor the token
claims to speak for. Keycloak's token exchange has no actor concept, so the
realm synthesizes `act` with a per-client mapper; see
docs/decisions/002-token-exchange.md. `verify()` refuses any token where
`act.sub` differs from `azp`, which is what stops another client's hardcoded
`act` from being read as this one's.

Tokens come from the running stack, so `verify()` reaches the issuer's
discovery and JWKS endpoints once per issuer and caches them for the process.
Tests pass their own key and issuer, so none of that is needed to test the
claim rules.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import Any

import httpx
from jose import ExpiredSignatureError, JWTError, jwt
from jose.exceptions import JWTClaimsError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

# The local stack's realm. A deployment points this elsewhere with
# WARRANT_OIDC_ISSUER.
DEFAULT_ISSUER = os.environ.get("WARRANT_OIDC_ISSUER", "http://localhost:8080/realms/warrant")

# Keycloak signs with RS256. Listing one algorithm is the point: a token that
# asks to be checked with "none" or an HMAC over the public key is refused.
ALGORITHMS = ("RS256",)

_DISCOVERY: dict[str, Discovery] = {}
_JWKS: dict[str, dict[str, Any]] = {}


class OidcError(Exception):
    """Base class for every way a token can fail verification."""


class InvalidToken(OidcError):
    """The token is malformed, signed by the wrong key, or shaped unexpectedly."""


class TokenExpired(OidcError):
    """The token's `exp` is in the past."""


class AudienceMismatch(OidcError):
    """The token's `aud` does not name the resource server that asked."""


class MissingActClaim(OidcError):
    """The token carries no `act` claim, so it does not describe a delegation."""


class ActorMismatch(OidcError):
    """`act.sub` and `azp` disagree, so the token's actor is not its holder."""


class Act(BaseModel):
    """The RFC 8693 actor claim. `sub` is the client id of the acting agent."""

    model_config = ConfigDict(extra="allow")

    sub: str


class Claims(BaseModel):
    """The claims Warrant and every resource server decide from.

    The model is a normalized view, not the raw JSON. Keycloak writes a single
    audience as a string and the realm's parameterized scope mapper writes
    `task_id` as a one-element array; both are normalized here so callers see
    one shape. The raw values are still in the signed token.
    """

    model_config = ConfigDict(extra="ignore")

    sub: str
    act: Act
    aud: list[str]
    azp: str
    scope: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    task_id: str | None = None
    exp: int
    iss: str | None = None

    @field_validator("aud", mode="before")
    @classmethod
    def _audience_as_list(cls, value: object) -> object:
        return [value] if isinstance(value, str) else value

    @field_validator("scope", mode="before")
    @classmethod
    def _scope_as_list(cls, value: object) -> object:
        if value is None:
            return []
        return value.split() if isinstance(value, str) else value

    @field_validator("groups", mode="before")
    @classmethod
    def _groups_as_list(cls, value: object) -> object:
        if value is None:
            return []
        return [value] if isinstance(value, str) else value

    @field_validator("task_id", mode="before")
    @classmethod
    def _single_task_id(cls, value: object) -> object:
        # The parameterized scope mapper emits a list. An exchanged token has
        # one task, so a one-element list is the value and an empty list is no
        # task at all.
        if isinstance(value, list):
            return value[0] if value else None
        return value


class Discovery(BaseModel):
    """The subset of the issuer's discovery document this module reads."""

    model_config = ConfigDict(extra="ignore")

    issuer: str
    jwks_uri: str
    token_endpoint: str
    authorization_endpoint: str | None = None


def discover(issuer: str | None = None) -> Discovery:
    """Fetch and cache the issuer's discovery document."""
    issuer = issuer or DEFAULT_ISSUER
    if issuer not in _DISCOVERY:
        url = issuer.rstrip("/") + "/.well-known/openid-configuration"
        response = httpx.get(url, timeout=10.0)
        response.raise_for_status()
        _DISCOVERY[issuer] = Discovery.model_validate(response.json())
    return _DISCOVERY[issuer]


def jwks(issuer: str | None = None) -> dict[str, Any]:
    """Fetch and cache the issuer's JSON Web Key Set."""
    issuer = issuer or DEFAULT_ISSUER
    if issuer not in _JWKS:
        response = httpx.get(discover(issuer).jwks_uri, timeout=10.0)
        response.raise_for_status()
        _JWKS[issuer] = response.json()
    return _JWKS[issuer]


def verify(
    token: str,
    audience: str,
    *,
    key: object | None = None,
    issuer: str | None = None,
    algorithms: Sequence[str] = ALGORITHMS,
) -> Claims:
    """Verify `token` for `audience` and return its normalized claims.

    Raises a subclass of `OidcError` for every refusal: `TokenExpired` for an
    expired token, `AudienceMismatch` for a token minted for another resource
    server, `MissingActClaim` for a token with no delegation, `ActorMismatch`
    when `act.sub` and `azp` disagree, and `InvalidToken` for a bad signature,
    a bad issuer, or a claim of the wrong shape.

    `key` and `issuer` default to the running stack. A test passes its own
    public key and issuer so it needs no server.
    """
    issuer = issuer or DEFAULT_ISSUER
    signing_key = jwks(issuer) if key is None else key

    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            signing_key,
            algorithms=list(algorithms),
            audience=audience,
            issuer=issuer,
            options={"verify_aud": True, "verify_iss": True, "verify_exp": True},
        )
    except ExpiredSignatureError as error:
        raise TokenExpired(f"token expired: {error}") from error
    except JWTClaimsError as error:
        if "audience" in str(error).lower():
            raise AudienceMismatch(f"token does not name audience {audience!r}: {error}") from error
        raise InvalidToken(f"token claims failed validation: {error}") from error
    except JWTError as error:
        raise InvalidToken(f"token is not valid: {error}") from error

    act = payload.get("act")
    if act is None:
        raise MissingActClaim("token carries no act claim, so it is not a delegation")

    azp = payload.get("azp")
    if not isinstance(azp, str):
        raise InvalidToken("token carries no azp claim naming the client it was issued to")
    if not isinstance(act, dict) or not isinstance(act.get("sub"), str):
        raise InvalidToken(f"token's act claim is not an object with a sub: {act!r}")
    if act["sub"] != azp:
        raise ActorMismatch(
            f"act.sub {act['sub']!r} is not azp {azp!r}: the token names an actor "
            "that does not hold it"
        )

    try:
        return Claims.model_validate(payload)
    except ValidationError as error:
        raise InvalidToken(f"token claims are not the expected shape: {error}") from error
