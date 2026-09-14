"""Fixtures for the resource servers under `servers/` and the live stack.

`rsa_keypair`, `sign_token`, `test_issuer`, and `other_keypair` mint tokens this
suite signs itself, so a request test needs no Keycloak. `settings`, `gitea`, and
`mint_obo` reach the running compose stack and skip when it is absent, so `make
test` is green on a clean checkout and still exercises the live paths when the
stack is up. They live here rather than in `tests/conftest.py` so that
everything that talks to a server sits together.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

from servers.gitea_mcp.server import ServerSettings

# A test issuer and audience. Nothing here talks to this issuer; `verify` is
# handed the matching public key directly.
TEST_ISSUER = "https://issuer.test/realms/warrant"
TEST_AUDIENCE = "gitea-mcp"


def _generate_keypair() -> tuple[str, str]:
    """(private PEM, public PEM) for one RSA key."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture(scope="session")
def rsa_keypair() -> tuple[str, str]:
    return _generate_keypair()


@pytest.fixture(scope="session")
def test_issuer() -> str:
    """The issuer the test keypair's tokens claim."""
    return TEST_ISSUER


@pytest.fixture(scope="session")
def other_keypair() -> tuple[str, str]:
    """A second keypair, for a token signed by the wrong key."""
    return _generate_keypair()


@pytest.fixture(scope="session")
def sign_token(rsa_keypair: tuple[str, str]) -> Any:
    """Return a factory that signs a realistic on-behalf-of token.

    The shape mirrors what the realm mints: `sub` is the human, `act.sub` and
    `azp` are the agent client, `aud` names one resource server, `scope` is a
    space-delimited string, and `task_id` is the parameterized scope's single
    value.
    """
    private_pem, _ = rsa_keypair

    def sign(
        *,
        issuer: str = TEST_ISSUER,
        audience: str = TEST_AUDIENCE,
        sub: str = "alice-id",
        act: str = "triage-agent",
        azp: str | None = None,
        scope: Any = ("gitea:read",),
        task_id: str | None = "task-1",
        groups: Any = ("owners",),
        exp_offset: int = 300,
        **overrides: Any,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": issuer,
            "sub": sub,
            "azp": azp or act,
            "aud": [audience],
            "act": {"sub": act},
            "scope": scope if isinstance(scope, str) else " ".join(scope),
            "groups": list(groups) if groups is not None else None,
            "task_id": [task_id] if task_id is not None else None,
            "iat": now,
            "exp": now + exp_offset,
        }
        claims.update(overrides)
        for name in [name for name, value in claims.items() if value is None]:
            del claims[name]
        return jwt.encode(claims, private_pem, algorithm="RS256")

    return sign


@pytest.fixture(scope="session")
def settings() -> ServerSettings:
    """The server's own settings, read from `.env` the way the server reads them."""
    return ServerSettings()


def _health_ok(base_url: str, timeout: float = 2.0) -> bool:
    try:
        return httpx.get(f"{base_url}/api/healthz", timeout=timeout).status_code == 200
    except httpx.HTTPError:
        return False


@pytest.fixture(scope="session")
def gitea(settings: ServerSettings) -> ServerSettings:
    """Skip unless a bootstrapped Gitea is reachable.

    Only an absent stack skips. A Gitea that answers and refuses the token is a
    failure, not a skip: a set-but-wrong `GITEA_ADMIN_TOKEN` used to be reported
    as a missing org, which deleted every integration test silently while
    `make test` stayed green.
    """
    if not settings.gitea_admin_token:
        pytest.skip("GITEA_ADMIN_TOKEN is not set; run scripts/gitea_bootstrap.py")
    if not _health_ok(settings.gitea_url):
        pytest.skip(f"no Gitea at {settings.gitea_url}; run `make up`")
    headers = {"Authorization": f"token {settings.gitea_admin_token}"}
    response = httpx.get(f"{settings.gitea_url}/api/v1/orgs/acme", headers=headers, timeout=5.0)
    if response.status_code in (401, 403):
        pytest.fail(
            f"Gitea at {settings.gitea_url} refused GITEA_ADMIN_TOKEN with "
            f"HTTP {response.status_code}; run scripts/gitea_bootstrap.py"
        )
    if response.status_code == 404:
        pytest.fail("org acme is missing; run scripts/gitea_bootstrap.py")
    if response.status_code != 200:
        pytest.fail(f"Gitea answered HTTP {response.status_code} for org acme")
    return settings


@pytest.fixture(scope="session")
def mint_obo() -> Any:
    """Return a factory that mints a real on-behalf-of token from Keycloak.

    This is the same flow `scripts/token_exchange.py` runs, so no human is
    needed: alice's dev password and the triage-agent secret come from `.env`.
    A missing stack skips rather than fails.
    """
    try:
        from scripts.token_exchange import (
            ACCESS_TOKEN_TYPE,
            TOKEN_EXCHANGE_GRANT,
            DevSettings,
            login_as_alice,
        )

        dev = DevSettings()
    except Exception as error:  # noqa: BLE001 - a missing .env value is a skip, not a failure
        pytest.skip(f"dev token settings are unavailable: {error}")

    def mint(*, scope: str = "task-id:task-1", audience: str = "gitea-mcp") -> str:
        try:
            with httpx.Client(timeout=20.0) as client:
                subject_token = login_as_alice(dev, client)
                response = client.post(
                    dev.token_endpoint,
                    auth=("triage-agent", dev.warrant_agent_client_secret),
                    data={
                        "grant_type": TOKEN_EXCHANGE_GRANT,
                        "subject_token": subject_token,
                        "subject_token_type": ACCESS_TOKEN_TYPE,
                        "requested_token_type": ACCESS_TOKEN_TYPE,
                        "audience": audience,
                        "scope": scope,
                    },
                )
        except httpx.HTTPError as error:
            pytest.skip(f"no Keycloak at {dev.keycloak_url}: {error}")
        # A reachable Keycloak that refuses the exchange is a failure. Skipping
        # here meant a wrong or rotated WARRANT_AGENT_CLIENT_SECRET, or a realm
        # regression, left the suite green with the real-token criteria never
        # exercised.
        if response.status_code != 200:
            pytest.fail(
                f"Keycloak at {dev.keycloak_url} refused the token exchange with "
                f"HTTP {response.status_code}: {response.text[:300]}"
            )
        return response.json()["access_token"]

    return mint
