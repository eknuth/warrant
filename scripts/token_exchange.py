"""Exchange a human's token for an on-behalf-of token, and print the claims.

The flow:

1. The human logs in as alice. Dev-only shortcut: this uses the resource owner
   password grant, which OAuth 2.1 deprecates and which exists here only
   because there is no browser in a terminal. The realm's real human client is
   the public `console` client, and a deployment runs authorization code with
   PKCE there. The subject token this step returns is issued to `console` and
   names triage-agent as its audience, which is what lets triage-agent exchange
   it.
2. triage-agent, a confidential client, exchanges that token for one addressed
   to gitea-mcp. The exchanged token keeps alice as `sub`, records
   triage-agent as `act.sub` and `azp`, and carries the caller's `task_id`.
3. `warrant.oidc.verify` checks the signature, audience, expiry, and that
   `act.sub` equals `azp`, then prints the normalized claims.

The task id travels as a parameterized scope, `scope=task-id:<value>`. That is
the one built-in way in this version for a caller to get a value into an
exchanged access token; see docs/decisions/002-token-exchange.md.

Usage: uv run python scripts/token_exchange.py [task_id] [--audience AUD]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx
from jose import jwt
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[1]
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


class DevSettings(BaseSettings):
    """The values this dev script needs, read from `.env` like compose does."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    keycloak_url: str = "http://localhost:8080"
    warrant_user_password: str
    warrant_agent_client_secret: str

    @property
    def issuer(self) -> str:
        return f"{self.keycloak_url.rstrip('/')}/realms/warrant"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/token"


def login_as_alice(settings: DevSettings, client: httpx.Client) -> str:
    """The human's token, issued to `console`. Resource owner password grant."""
    response = client.post(
        settings.token_endpoint,
        data={
            "grant_type": "password",
            "client_id": "console",
            "username": "alice",
            "password": settings.warrant_user_password,
            "scope": "openid",
        },
    )
    if response.status_code != 200:
        raise SystemExit(f"login failed: {response.status_code} {response.text}")
    return response.json()["access_token"]


def exchange_for_obo(
    settings: DevSettings, client: httpx.Client, subject_token: str, audience: str, task_id: str
) -> str:
    """triage-agent's on-behalf-of token for one audience, keyed to one task."""
    response = client.post(
        settings.token_endpoint,
        auth=("triage-agent", settings.warrant_agent_client_secret),
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
        raise SystemExit(f"exchange failed: {response.status_code} {response.text}")
    return response.json()["access_token"]


def main() -> int:
    # `python scripts/token_exchange.py` does not put the repository root on
    # sys.path the way pytest's `pythonpath` setting does.
    sys.path.insert(0, str(REPO_ROOT))
    from warrant.oidc import verify

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task_id", nargs="?", default="task-1", help="task id to bind to the token")
    parser.add_argument("--audience", default="gitea-mcp", help="resource server client id")
    args = parser.parse_args()

    settings = DevSettings()
    with httpx.Client(timeout=20.0) as client:
        subject_token = login_as_alice(settings, client)
        obo_token = exchange_for_obo(settings, client, subject_token, args.audience, args.task_id)

    print("subject token claims (issued to console):")
    print(json.dumps(jwt.get_unverified_claims(subject_token), indent=2, sort_keys=True))
    print()
    print("on-behalf-of token claims (as decoded from the JWT):")
    print(json.dumps(jwt.get_unverified_claims(obo_token), indent=2, sort_keys=True))
    print()
    print("on-behalf-of token claims (after warrant.oidc.verify):")
    claims = verify(obo_token, args.audience, issuer=settings.issuer)
    print(claims.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
