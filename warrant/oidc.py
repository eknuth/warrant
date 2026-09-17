"""Verify the on-behalf-of tokens Keycloak issues for the local stack.

Every resource server and Warrant itself decide from a token this module
verified. Verification is not just a signature check. A token is accepted only
when the signature matches the issuer's JWKS, it has not expired, the audience
names this resource server, and the delegation chain in it is internally
consistent.

The delegation chain is a pair of signed claims that must agree. `azp` names
the client the token was issued to. The `act` claim names the actor the token
claims to speak for. Keycloak's token exchange has no actor concept, so the
realm synthesizes `act` with a mapper on each agent client's own scope; see
docs/decisions/002-token-exchange.md. `verify()` refuses any token where
`act.sub` differs from `azp`.

That equality is a consistency check, not the guard against a foreign actor. It
holds by construction for any token carrying an `act` at all, because the mapper
hardcodes the client's own id and Keycloak sets `azp` to the client that
requested the token. What stops one agent from holding another's token is the
realm's audience and scope assignment: a client that is not in the subject
token's audience is refused `403` by Keycloak before any mapper runs. `verify()`
has no actor allowlist, so it accepts any self-consistent actor the realm ever
mints, and a client later given an `act` mapper would verify too.

What a verified token establishes: the subject is real, because Keycloak
validated the subject token; the audience and lifetime are Keycloak's; the actor
was written by the realm rather than supplied by the caller; and the token is
signed. What it does not establish: that a human asked for this action, that the
subject is a human rather than a service account, or that `task_id` names a task
the human chose rather than one the agent named.

Tokens come from the running stack, so `verify()` reaches the issuer's
discovery and JWKS endpoints once per issuer and caches them for the process.
Tests pass their own key and issuer, so none of that is needed to test the
claim rules.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from jose import ExpiredSignatureError, JWTError, jwt
from jose.exceptions import JWTClaimsError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

# The local stack's realm. A deployment points this elsewhere with
# WARRANT_OIDC_ISSUER. The issuer a token must name and the URL its keys come
# from can differ: a host login reaches Keycloak at `localhost`, and a container
# fetches the same realm's keys at the compose service name. A deployment whose
# realm is reachable under one name sets only the issuer.
DEFAULT_ISSUER = os.environ.get("WARRANT_OIDC_ISSUER", "http://localhost:8080/realms/warrant")
DEFAULT_DISCOVERY_ISSUER = os.environ.get("WARRANT_OIDC_DISCOVERY_ISSUER") or DEFAULT_ISSUER

# Keycloak signs with RS256. Listing one algorithm is the point: a token that
# asks to be checked with "none" or an HMAC over the public key is refused.
ALGORITHMS = ("RS256",)

_DISCOVERY: dict[str, Discovery] = {}
_JWKS: dict[str, dict[str, Any]] = {}


class OidcError(Exception):
    """Base class for the refusals this module raises about a token.

    A failure to reach the issuer is not one of these: a dead discovery or JWKS
    endpoint raises `httpx.HTTPError`, and a key that cannot be read raises a
    `jose` error. Those escape as themselves rather than as an `OidcError`,
    which is deliberate: a caller can tell "this token is bad" apart from
    "I could not reach the issuer", and neither one is an accept.
    """


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
    # The realm's `incident_id` parameterized scope writes a separate claim and
    # does not put a bare `incident_id` in `scope`; see
    # docs/decisions/w15-eval-runner.md. The escalation rule reads this claim.
    incident_id: str | None = None
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

    @field_validator("incident_id", mode="before")
    @classmethod
    def _single_incident_id(cls, value: object) -> object:
        # The same parameterized-scope mapper that writes `task_id` writes
        # `incident_id`, so it arrives as a one-element list. More than one is
        # refused for the same reason `task_id` refuses it: the caller chooses
        # how many values to ask for, and keeping the first would pick an
        # arbitrary incident.
        if isinstance(value, list):
            if len(value) > 1:
                message = (
                    f"incident_id carries {len(value)} values, at most one is expected: {value!r}"
                )
                raise ValueError(message)
            return value[0] if value else None
        return value

    @field_validator("task_id", mode="before")
    @classmethod
    def _single_task_id(cls, value: object) -> object:
        # The parameterized scope mapper emits a list. An exchanged token has
        # one task, so a one-element list is the value and an empty list is no
        # task at all. More than one is refused rather than truncated: the
        # caller chooses how many `task-id:<value>` scopes to ask for, and
        # keeping the first would key provenance to an arbitrary one of them in
        # an order the mapper does not guarantee.
        if isinstance(value, list):
            if len(value) > 1:
                message = f"task_id carries {len(value)} values, at most one is expected: {value!r}"
                raise ValueError(message)
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
    discovery_issuer: str | None = None,
) -> Claims:
    """Verify `token` for `audience` and return its normalized claims.

    Raises a subclass of `OidcError` for every refusal: `TokenExpired` for an
    expired token, `AudienceMismatch` for a token minted for another resource
    server, `MissingActClaim` for a token with no delegation, `ActorMismatch`
    when `act.sub` and `azp` disagree, and `InvalidToken` for a bad signature,
    a bad issuer, or a claim of the wrong shape.

    `issuer` is the value the token's `iss` claim must equal. `discovery_issuer`
    is the URL base the signing keys are fetched from, and it defaults to
    `issuer`. The two differ on the local stack: a host-side login reaches
    Keycloak at `localhost:8080`, so the token carries that issuer, while the
    gateway container reaches the same realm at `keycloak:8080` to fetch its
    keys. Splitting the check from the fetch keeps the identity provider's
    public issuer ordinary and lets one deployment run both. A test passes its
    own public key and issuer so it needs no server.

    `key` and `issuer` default to the running stack.

    The signing algorithms are not a parameter. They are pinned above so no
    caller can widen them, which matters here: the pinned python-jose has an
    open DER-key HMAC confusion that a symmetric algorithm in the accepted list
    would expose. A token whose header names an algorithm outside the pinned
    set is a `InvalidToken`.
    """
    issuer = issuer or DEFAULT_ISSUER
    key_source = discovery_issuer or DEFAULT_DISCOVERY_ISSUER or issuer
    signing_key = jwks(key_source) if key is None else key

    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            signing_key,
            algorithms=list(ALGORITHMS),
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
