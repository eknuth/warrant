"""The dev-only auth path: a human's token, and the exchange for an agent's.

This module holds what `scripts/token_exchange.py` used to hold, moved here so
the triage agent can call it. The script imports these functions back out, so
its CLI and the W3 test fixture that reads it keep working.

The flow is two steps:

1. The human logs in. Dev-only shortcut: this uses the resource owner password
   grant, which OAuth 2.1 deprecates and which exists here only because there is
   no browser in a terminal. The realm's real human client is the public
   `console` client, and a deployment runs authorization code with PKCE there.
   The token this returns is issued to `console` and names triage-agent as its
   audience, which is what lets triage-agent exchange it.
2. triage-agent, a confidential client, exchanges that token for one addressed
   to a resource server. The exchanged token keeps the human as `sub`, records
   triage-agent as `act.sub` and `azp`, and carries the caller's `task_id`.

`task_id` travels as the parameterized scope `task-id:<value>`; see
`docs/decisions/002-token-exchange.md`. The decoded token this module returns
never includes the signature: `decode_claims` reads the header and the payload,
which is what a run record can carry without carrying a usable credential.

Credentials come from `.env` through a settings object, the same way the rest of
the repository reads them, so nothing here needs an exported shell variable.
"""

from __future__ import annotations

from typing import Any

import httpx
from jose import jwt
from pydantic_settings import BaseSettings, SettingsConfigDict

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

# The agent client every triage exchange is issued to. It is also the value the
# realm's `act` mapper hardcodes, and `warrant.oidc.verify` refuses a token
# where `act.sub` and `azp` disagree with it.
TRIAGE_AGENT = "triage-agent"


class AuthError(RuntimeError):
    """A login or exchange the realm refused."""


class DevSettings(BaseSettings):
    """The values the dev auth path needs, read from `.env` like compose does."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    keycloak_url: str = "http://localhost:8080"
    warrant_user_password: str = ""
    warrant_agent_client_secret: str = ""

    @property
    def issuer(self) -> str:
        return f"{self.keycloak_url.rstrip('/')}/realms/warrant"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/token"


def login_user(settings: DevSettings, client: httpx.Client, username: str, password: str) -> str:
    """The named human's token, issued to `console`. Password grant."""
    response = client.post(
        settings.token_endpoint,
        data={
            "grant_type": "password",
            "client_id": "console",
            "username": username,
            "password": password,
            "scope": "openid",
        },
    )
    if response.status_code != 200:
        raise AuthError(f"login for {username!r} failed: HTTP {response.status_code}")
    return response.json()["access_token"]


def login_as_alice(settings: DevSettings, client: httpx.Client) -> str:
    """alice's token. Kept because the W3 integration fixture imports it."""
    return login_user(settings, client, "alice", settings.warrant_user_password)


def exchange_for_obo(
    settings: DevSettings,
    client: httpx.Client,
    subject_token: str,
    audience: str,
    task_id: str,
    *,
    client_id: str = TRIAGE_AGENT,
) -> str:
    """The agent's on-behalf-of token for one audience, keyed to one task."""
    response = client.post(
        settings.token_endpoint,
        auth=(client_id, settings.warrant_agent_client_secret),
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": ACCESS_TOKEN_TYPE,
            "audience": audience,
            "scope": f"task-id:{task_id}",
        },
    )
    if response.status_code != 200:
        raise AuthError(f"exchange for audience {audience!r} failed: HTTP {response.status_code}")
    return response.json()["access_token"]


def decode_claims(token: str) -> dict[str, Any]:
    """The token's header and claims, without the signature.

    A JWT is three base64url parts. This returns the first two decoded and drops
    the third, so the result describes a token without being one.
    """
    return {
        "header": jwt.get_unverified_header(token),
        "claims": jwt.get_unverified_claims(token),
    }


def audience_list(claims: dict[str, Any]) -> list[str]:
    """The `aud` claim as a list, which the raw token does not guarantee."""
    value = claims.get("aud")
    if isinstance(value, str):
        return [value]
    return list(value or [])


def claim_task_id(claims: dict[str, Any]) -> str | None:
    """The `task_id` claim as one string.

    The parameterized scope mapper writes a one-element array, and `warrant.oidc`
    refuses more than one value, so this is the same normalization at the raw
    claim level.
    """
    value = claims.get("task_id")
    if isinstance(value, list):
        return value[0] if value else None
    if value is None:
        return None
    return str(value)


def lifetime_seconds(claims: dict[str, Any]) -> int | None:
    """`exp - iat`, or None when either claim is missing or not an int."""
    issued, expires = claims.get("iat"), claims.get("exp")
    if not isinstance(issued, int) or not isinstance(expires, int):
        return None
    return expires - issued
