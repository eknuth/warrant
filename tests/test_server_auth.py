"""Bearer middleware unit tests, with tokens this suite signs itself.

No server and no Keycloak: the middleware is handed a test public key and a
test issuer, and the tokens are signed with the matching private key. The three
refusals the ticket names live here (no bearer, an expired bearer, a bearer
minted for another audience) plus the accept case that attaches claims, and the
audit record's shape.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from servers.common.audit import args_digest, audit_record
from servers.common.auth import BearerAuthMiddleware, MissingBearer, current_claims, parse_bearer
from warrant.oidc import verify

REPO_ROOT = Path(__file__).resolve().parents[1]

TEST_ISSUER = "https://issuer.test/realms/warrant"
AUDIENCE = "gitea-mcp"


def build_client(
    public_pem: str, issuer: str = TEST_ISSUER, audience: str = AUDIENCE
) -> TestClient:
    """A one-route app behind the middleware, reporting what it saw."""

    async def home(request: Any) -> JSONResponse:
        claims = current_claims()
        state_claims = request.scope.get("state", {}).get("claims")
        return JSONResponse(
            {
                "sub": claims.sub if claims else None,
                "scope": claims.scope if claims else None,
                "task_id": claims.task_id if claims else None,
                "state_sub": state_claims.sub if state_claims else None,
            }
        )

    app = Starlette(routes=[Route("/", home)])
    app.add_middleware(BearerAuthMiddleware, audience=audience, issuer=issuer, key=public_pem)
    return TestClient(app)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_a_request_with_no_bearer_is_refused(rsa_keypair: tuple[str, str]) -> None:
    client = build_client(rsa_keypair[1])

    response = client.get("/")

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_request"
    assert response.headers["www-authenticate"] == 'Bearer error="invalid_request"'


def test_a_non_bearer_scheme_is_refused(rsa_keypair: tuple[str, str]) -> None:
    client = build_client(rsa_keypair[1])

    response = client.get("/", headers={"Authorization": "Basic dXNlcjpwYXNz"})

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_request"


def test_an_expired_bearer_is_refused(rsa_keypair: tuple[str, str], sign_token: Any) -> None:
    client = build_client(rsa_keypair[1])

    response = client.get("/", headers=bearer(sign_token(exp_offset=-30)))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_a_bearer_for_another_audience_is_refused(
    rsa_keypair: tuple[str, str], sign_token: Any
) -> None:
    client = build_client(rsa_keypair[1])

    response = client.get("/", headers=bearer(sign_token(audience="postgres-mcp")))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_a_bearer_signed_by_another_key_is_refused(
    rsa_keypair: tuple[str, str], other_keypair: tuple[str, str]
) -> None:
    client = build_client(rsa_keypair[1])

    # The signature is over the other key, so the test public key refuses it
    # before any claim is read.
    forged = _sign_with(other_keypair[0])
    response = client.get("/", headers=bearer(forged))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_a_bearer_with_no_act_claim_is_refused(
    rsa_keypair: tuple[str, str], sign_token: Any
) -> None:
    client = build_client(rsa_keypair[1])

    response = client.get("/", headers=bearer(sign_token(act=None)))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_a_valid_bearer_attaches_its_claims(rsa_keypair: tuple[str, str], sign_token: Any) -> None:
    client = build_client(rsa_keypair[1])
    token = sign_token(scope=["gitea:read"], task_id="task-9")

    response = client.get("/", headers=bearer(token))

    assert response.status_code == 200
    body = response.json()
    assert body["sub"] == "alice-id"
    assert body["scope"] == ["gitea:read"]
    assert body["task_id"] == "task-9"
    # Attached to both the task's context and the ASGI scope.
    assert body["state_sub"] == "alice-id"


def test_the_claims_do_not_leak_between_requests(
    rsa_keypair: tuple[str, str], sign_token: Any
) -> None:
    client = build_client(rsa_keypair[1])

    refused = client.get("/")
    accepted = client.get("/", headers=bearer(sign_token(sub="bob-id")))

    assert refused.status_code == 401
    assert accepted.json()["sub"] == "bob-id"


@pytest.mark.parametrize(
    ("header", "reason"),
    [
        (None, "no Authorization header"),
        ("", "no Authorization header"),
        ("Bearer", "not a Bearer token"),
        ("Bearer   ", "not a Bearer token"),
        ("Token abc", "not a Bearer token"),
    ],
)
def test_parse_bearer_refusals(header: str | None, reason: str) -> None:
    with pytest.raises(MissingBearer) as caught:
        parse_bearer(header)

    assert reason in str(caught.value)


def test_parse_bearer_accepts_a_folded_scheme() -> None:
    assert parse_bearer("bearer abc.def") == "abc.def"
    assert parse_bearer("Bearer abc.def") == "abc.def"


def test_args_digest_is_canonical_and_sensitive() -> None:
    assert args_digest({"b": [1, 2], "a": "x"}) == args_digest({"a": "x", "b": [1, 2]})
    assert args_digest({"a": 1}) != args_digest({"a": 2})


def test_the_audit_record_has_exactly_the_named_keys(
    rsa_keypair: tuple[str, str], sign_token: Any
) -> None:
    claims = verify(sign_token(task_id="task-7"), AUDIENCE, key=rsa_keypair[1], issuer=TEST_ISSUER)

    record = audit_record(
        "get_issue",
        claims,
        args_digest({"repo": "acme/demo", "number": 1}),
        "ok",
        now=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
    )

    assert list(record) == ["ts", "tool", "sub", "act", "task_id", "args_digest", "status"]
    assert record["ts"] == "2026-01-02T03:04:05Z"
    assert record["tool"] == "get_issue"
    assert record["sub"] == "alice-id"
    assert record["act"] == "triage-agent"
    assert record["task_id"] == "task-7"
    assert record["status"] == "ok"
    assert record["args_digest"] == args_digest({"repo": "acme/demo", "number": 1})


def test_a_refused_call_still_records_an_audit_line() -> None:
    """A call refused before any claim was verified is still a tool call.

    The line exists so the log answers "what was attempted", and the caller
    fields are null rather than absent because there was no verified caller.
    """
    record = audit_record(
        "set_repo_visibility",
        None,
        args_digest({"repo": "acme/demo", "visibility": "private"}),
        "refused",
        now=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
    )

    assert list(record) == ["ts", "tool", "sub", "act", "task_id", "args_digest", "status"]
    assert record["status"] == "refused"
    assert record["sub"] is None
    assert record["act"] is None
    assert record["task_id"] is None
    assert record["args_digest"] == args_digest({"repo": "acme/demo", "visibility": "private"})


def test_importing_the_shared_middleware_needs_no_secret_or_server() -> None:
    """`import servers.common.auth` must not read a token or start anything.

    Run in a child process with the credential names removed, because the
    session's own environment has them loaded.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("GITEA_ADMIN_TOKEN", "WARRANT_OIDC_ISSUER")
    }
    result = subprocess.run(
        [sys.executable, "-c", "import servers.common.auth"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def _sign_with(private_pem: str) -> str:
    """A valid-looking token signed by a key the middleware does not trust."""
    import time

    from jose import jwt

    now = int(time.time())
    return jwt.encode(
        {
            "iss": TEST_ISSUER,
            "sub": "alice-id",
            "azp": "triage-agent",
            "aud": [AUDIENCE],
            "act": {"sub": "triage-agent"},
            "scope": "gitea:read",
            "iat": now,
            "exp": now + 300,
        },
        private_pem,
        algorithm="RS256",
    )


def test_the_server_answers_the_host_its_compose_service_name_gives_it(
    rsa_keypair: tuple[str, str], sign_token: Any
) -> None:
    """A server bound to all interfaces must accept the service hostname.

    The MCP library auto-enables DNS-rebinding protection with a localhost-only
    host list when the app is not told its bind host. In compose the gateway
    reaches this upstream as `http://gitea-mcp:9101/mcp`, so the Host header is
    the service name and every request was refused with 421 before this was
    wired: the tool list came back empty and the agent had nothing to call.

    The control is the localhost bind: the same request is refused there, which
    is the protection doing its job and what makes the first assertion mean the
    host was passed through rather than the protection switched off. A valid
    bearer is sent because the auth middleware answers 401 before the transport
    check runs.
    """
    from servers.gitea_mcp.server import ServerSettings, build_app

    headers = {"Authorization": f"Bearer {sign_token()}"}
    body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    compose_settings = ServerSettings(gitea_mcp_host="0.0.0.0")
    localhost_settings = ServerSettings(gitea_mcp_host="127.0.0.1")

    with TestClient(
        build_app(settings=compose_settings, issuer=TEST_ISSUER, key=rsa_keypair[1]),
        base_url="http://gitea-mcp:9101",
    ) as compose:
        answered = compose.post("/mcp", json=body, headers=headers)
    with TestClient(
        build_app(settings=localhost_settings, issuer=TEST_ISSUER, key=rsa_keypair[1]),
        base_url="http://gitea-mcp:9101",
    ) as localhost:
        refused = localhost.post("/mcp", json=body, headers=headers)

    assert answered.status_code != 421
    assert refused.status_code == 421
