"""The postgres MCP server's bearer boundary and result shaping, with no stack.

No database and no Keycloak: the app is handed a test public key and a test
issuer, and the tokens are signed with the matching private key. The audience
refusals the ticket names live here, plus the rule that a result's `secrets`
list rides in the structured result rather than in the text the model reads.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from starlette.testclient import TestClient

from servers.postgres_mcp.db import query_source, secrets_in
from servers.postgres_mcp.models import ApiKey, CustomerDetail, Source
from servers.postgres_mcp.server import (
    TOOL_NAMES,
    ServerSettings,
    build_app,
    tool_result,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

TEST_ISSUER = "https://issuer.test/realms/warrant"
MCP_ACCEPT = {"Accept": "application/json, text/event-stream"}

# A minimal initialize request. The auth middleware answers before the
# transport reads the body, so the shape only matters for the accepted case.
INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}


def build_client(
    public_pem: str,
    *,
    host: str = "0.0.0.0",
    base_url: str = "http://postgres-mcp:9102",
) -> TestClient:
    settings = ServerSettings(postgres_mcp_host=host)
    app = build_app(settings=settings, issuer=TEST_ISSUER, key=public_pem)
    return TestClient(app, base_url=base_url)


def bearer(token: str) -> dict[str, str]:
    return {**MCP_ACCEPT, "Authorization": f"Bearer {token}"}


def customer_payload() -> CustomerDetail:
    source = Source(kind="customer", id="1", author="bob", author_tier="member")
    return CustomerDetail(
        id=1,
        name="Acme",
        email="ops@acme.example",
        owner_login="bob",
        api_keys=[
            ApiKey(
                id=9,
                customer_id=1,
                key_value="fixture-key-value-alpha",
                label="prod",
                revoked=False,
            )
        ],
        secrets=["fixture-key-value-alpha"],
        source=source,
    )


def test_the_tool_surface_is_the_named_set() -> None:
    assert set(TOOL_NAMES) == {
        "search_customers",
        "get_ticket",
        "get_customer",
        "run_readonly_sql",
        "update_ticket",
        "rotate_api_key",
    }


def test_a_call_with_no_bearer_is_refused(rsa_keypair: tuple[str, str]) -> None:
    response = build_client(rsa_keypair[1]).post("/mcp", json=INITIALIZE, headers=MCP_ACCEPT)

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_request"


def test_a_gitea_audience_token_is_refused(rsa_keypair: tuple[str, str], sign_token: Any) -> None:
    """A triage on-behalf-of token names gitea-mcp, so postgres-mcp refuses it."""
    token = sign_token(audience="gitea-mcp", scope=("gitea:read",))
    response = build_client(rsa_keypair[1]).post("/mcp", json=INITIALIZE, headers=bearer(token))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_a_bearer_signed_by_another_key_is_refused(
    rsa_keypair: tuple[str, str], other_keypair: tuple[str, str], sign_token: Any
) -> None:
    token = sign_token(audience="postgres-mcp", scope=("db:read",))
    response = build_client(other_keypair[1]).post("/mcp", json=INITIALIZE, headers=bearer(token))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_a_postgres_audience_token_is_accepted(
    rsa_keypair: tuple[str, str], sign_token: Any
) -> None:
    token = sign_token(audience="postgres-mcp", scope=("db:read",))
    with build_client(rsa_keypair[1]) as client:
        response = client.post("/mcp", json=INITIALIZE, headers=bearer(token))

    assert response.status_code != 401


def test_tool_result_keeps_secrets_out_of_the_model_text() -> None:
    """The key value is in the text once, on the record, not again in `secrets`."""
    result = tool_result(customer_payload())

    assert result.structured_content["secrets"] == ["fixture-key-value-alpha"]
    assert result.structured_content["api_keys"][0]["key_value"] == "fixture-key-value-alpha"
    text = result.content[0].text
    assert text.count("fixture-key-value-alpha") == 1
    assert "secrets" not in text


def test_tool_result_carries_a_payload_with_no_secrets_whole() -> None:
    from servers.postgres_mcp.models import CustomerSearch

    result = tool_result(CustomerSearch(query="acme"))

    assert result.structured_content == {"query": "acme", "customers": []}
    assert "acme" in result.content[0].text


def test_secrets_in_collects_every_known_key_value_in_row_order() -> None:
    rows = [
        {"id": 1, "key_value": "alpha"},
        {"id": 2, "key_value": "beta"},
        {"id": 3, "key_value": None},
    ]

    assert secrets_in(["id", "key_value"], rows, ["alpha", "beta", "gamma"]) == [
        "alpha",
        "beta",
    ]
    assert secrets_in(["id"], rows, ["alpha"]) == []
    assert secrets_in(["id", "key_value"], rows, []) == [], "no known keys, nothing listed"


def test_secrets_in_finds_a_key_under_an_alias_or_inside_a_json_object() -> None:
    """The key value reaches the model under any name, so the check is on values.

    A column-name match found nothing for `select key_value as kv`, for
    `select key_value || '' as kv`, or for `select row_to_json(k) from api_keys
    k`, so W11 saw an empty `secrets` for a read that leaked a key.
    """
    aliased = [{"kv": "alpha"}]
    concatenated = [{"kv": "alpha"}]
    as_json = [{"row_to_json": '{"id": 1, "key_value": "alpha"}'}]

    assert secrets_in(["kv"], aliased, ["alpha", "beta"]) == ["alpha"]
    assert secrets_in(["kv"], concatenated, ["alpha", "beta"]) == ["alpha"]
    assert secrets_in(["row_to_json"], as_json, ["alpha", "beta"]) == ["alpha"]


def test_secrets_in_does_not_list_a_key_the_result_does_not_carry() -> None:
    rows = [{"id": 1, "name": "Acme"}]

    assert secrets_in(["id", "name"], rows, ["alpha"]) == []


def test_query_source_ids_the_statement_by_digest() -> None:
    source = query_source("select 1")

    assert source.system == "db"
    assert source.kind == "query"
    assert source.id == hashlib.sha256(b"select 1").hexdigest()[:12]
    assert source.author == ""
    assert source.author_tier == "unknown"


def test_the_server_answers_the_host_its_compose_service_name_gives_it(
    rsa_keypair: tuple[str, str], sign_token: Any
) -> None:
    """A server bound to all interfaces must accept the service hostname.

    The MCP library auto-enables DNS-rebinding protection with a localhost-only
    host list when the app is not told its bind host. In compose the gateway
    reaches this upstream as `http://postgres-mcp:9102/mcp`, so the Host header
    is the service name and the request would be refused with 421 without this.
    The localhost bind is the control that keeps the first assertion honest.
    """
    headers = bearer(sign_token(audience="postgres-mcp", scope=("db:read",)))

    with build_client(rsa_keypair[1], host="0.0.0.0") as compose:
        answered = compose.post("/mcp", json=INITIALIZE, headers=headers)
    with build_client(rsa_keypair[1], host="127.0.0.1") as localhost:
        refused = localhost.post("/mcp", json=INITIALIZE, headers=headers)

    assert answered.status_code != 421
    assert refused.status_code == 421


def test_importing_the_server_needs_no_secret_and_no_database() -> None:
    """`import servers.postgres_mcp.server` must not read a password or connect.

    Run in a child process with the credential names removed, because the
    session's own environment has them loaded.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("POSTGRES_PASSWORD", "WARRANT_OIDC_ISSUER")
    }
    result = subprocess.run(
        [sys.executable, "-c", "import servers.postgres_mcp.server"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
