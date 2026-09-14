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

The flow itself lives in `agents/auth.py` now, because the triage agent needs
the same two steps. This file keeps the CLI and imports those functions back
out, so `from scripts.token_exchange import DevSettings` still works for the
integration fixture.

Usage: uv run python scripts/token_exchange.py [task_id] [--audience AUD]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx
from jose import jwt

# `python scripts/token_exchange.py` does not put the repository root on
# sys.path the way pytest's `pythonpath` setting does, so `agents` is not
# importable until this runs. It has to happen before the import below.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.auth import (  # noqa: E402
    ACCESS_TOKEN_TYPE,
    TOKEN_EXCHANGE_GRANT,
    AuthError,
    DevSettings,
    exchange_for_obo,
    login_as_alice,
)

__all__ = [
    "ACCESS_TOKEN_TYPE",
    "TOKEN_EXCHANGE_GRANT",
    "DevSettings",
    "exchange_for_obo",
    "login_as_alice",
    "main",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task_id", nargs="?", default="task-1", help="task id to bind to the token")
    parser.add_argument("--audience", default="gitea-mcp", help="resource server client id")
    args = parser.parse_args()

    settings = DevSettings()
    try:
        with httpx.Client(timeout=20.0) as client:
            subject_token = login_as_alice(settings, client)
            obo_token = exchange_for_obo(
                settings, client, subject_token, args.audience, args.task_id
            )
    except AuthError as error:
        print(f"token exchange failed: {error}", file=sys.stderr)
        return 1

    print("subject token claims (issued to console):")
    print(json.dumps(jwt.get_unverified_claims(subject_token), indent=2, sort_keys=True))
    print()
    print("on-behalf-of token claims (as decoded from the JWT):")
    print(json.dumps(jwt.get_unverified_claims(obo_token), indent=2, sort_keys=True))
    print()
    print("on-behalf-of token claims (after warrant.oidc.verify):")
    from warrant.oidc import verify

    claims = verify(obo_token, args.audience, issuer=settings.issuer)
    print(claims.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
