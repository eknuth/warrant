"""The second token hop against the running realm.

The hop is the one design risk in W6: the token an agent holds names `warrant`,
and the upstream needs one that names it. This is the live check that the pinned
realm allows Warrant to exchange the agent's token again, and that the token
that comes back is one the upstream will verify. It skips when the stack is
absent, the way the other integration tests do, and fails when the realm is up
but refuses, because a realm regression here is the thing the test exists for.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from agents.auth import ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT, DevSettings
from warrant import oidc

pytestmark = pytest.mark.integration

GITEA_AUDIENCE = "gitea-mcp"
GATEWAY_AUDIENCE = "warrant"


@pytest.fixture(scope="module")
def dev_settings() -> DevSettings:
    try:
        settings = DevSettings()
    except Exception as error:  # noqa: BLE001 - a missing .env value is a skip
        pytest.skip(f"dev token settings are unavailable: {error}")
    if not settings.warrant_agent_client_secret:
        pytest.skip("WARRANT_AGENT_CLIENT_SECRET is not set")
    return settings


def test_warrant_may_exchange_the_agents_token_for_an_upstream(
    dev_settings: DevSettings, mint_obo: Any
) -> None:
    incoming = mint_obo(audience=GATEWAY_AUDIENCE, scope="task-id:task-w6-hop")

    try:
        with httpx.Client(timeout=20.0) as client:
            response = client.post(
                dev_settings.token_endpoint,
                auth=("warrant", dev_settings.warrant_agent_client_secret),
                data={
                    "grant_type": TOKEN_EXCHANGE_GRANT,
                    "subject_token": incoming,
                    "subject_token_type": ACCESS_TOKEN_TYPE,
                    "requested_token_type": ACCESS_TOKEN_TYPE,
                    "audience": GITEA_AUDIENCE,
                    "scope": "task-id:task-w6-hop",
                },
            )
    except httpx.HTTPError as error:
        pytest.skip(f"no Keycloak at {dev_settings.keycloak_url}: {error}")

    assert response.status_code == 200, response.text
    upstream = response.json()["access_token"]

    claims = oidc.verify(upstream, GITEA_AUDIENCE, issuer=dev_settings.issuer)
    assert claims.aud == [GITEA_AUDIENCE]
    assert claims.act.sub == "warrant"
    assert claims.azp == "warrant"
    assert claims.task_id == "task-w6-hop"


def test_an_upstream_audience_is_refused_at_the_gateway(
    dev_settings: DevSettings, mint_obo: Any
) -> None:
    """A token for the upstream does not name the gateway, so it cannot skip it."""
    upstream_token = mint_obo(audience=GITEA_AUDIENCE)

    with pytest.raises(oidc.AudienceMismatch):
        oidc.verify(upstream_token, GATEWAY_AUDIENCE, issuer=dev_settings.issuer)


def test_a_refused_second_hop_is_an_error_not_a_token(
    dev_settings: DevSettings, mint_obo: Any
) -> None:
    """An audience the gateway client does not hold is refused by the realm.

    The realm's audience parameter filters what the client's scopes already add,
    so asking for an audience no scope of `warrant` carries is a refusal. This
    is how the fallback path in `Gateway.upstream_token` is exercised live.
    """
    incoming = mint_obo(audience=GATEWAY_AUDIENCE, scope="task-id:task-w6-refused")

    try:
        with httpx.Client(timeout=20.0) as client:
            response = client.post(
                dev_settings.token_endpoint,
                auth=("warrant", dev_settings.warrant_agent_client_secret),
                data={
                    "grant_type": TOKEN_EXCHANGE_GRANT,
                    "subject_token": incoming,
                    "subject_token_type": ACCESS_TOKEN_TYPE,
                    "requested_token_type": ACCESS_TOKEN_TYPE,
                    "audience": "no-such-resource-server",
                },
            )
    except httpx.HTTPError as error:
        pytest.skip(f"no Keycloak at {dev_settings.keycloak_url}: {error}")

    assert response.status_code != 200
    assert "error" in response.text.lower() or response.status_code == 403
