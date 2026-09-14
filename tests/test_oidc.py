"""The claim rules every resource server depends on, tested without a server.

Each token is signed by a key this test generates, so the suite needs no
Keycloak. The claims mirror what the realm's exchange mints: `sub` is the
human, `act.sub` is the agent client, `azp` is the client the token was issued
to, and `aud` names one resource server.
"""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

from warrant.oidc import (
    ActorMismatch,
    AudienceMismatch,
    Claims,
    InvalidToken,
    MissingActClaim,
    OidcError,
    TokenExpired,
    verify,
)

ISSUER = "https://issuer.test/realms/warrant"
AUDIENCE = "gitea-mcp"


@pytest.fixture(scope="module")
def keys() -> tuple[str, str]:
    """(private PEM, public PEM) for one test key."""
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


def token_for(private_pem: str, **overrides: object) -> str:
    """A valid token, with any claim replaced or, for None, removed."""
    now = int(time.time())
    claims: dict[str, object] = {
        "iss": ISSUER,
        "sub": "alice-id",
        "azp": "triage-agent",
        "aud": [AUDIENCE],
        "act": {"sub": "triage-agent"},
        "scope": "gitea:read gitea:write",
        "groups": ["owners"],
        "task_id": ["task-1"],
        "iat": now,
        "exp": now + 300,
    }
    claims.update(overrides)
    for name, value in list(claims.items()):
        if value is None:
            del claims[name]
    return jwt.encode(claims, private_pem, algorithm="RS256")


def test_a_valid_token_returns_normalized_claims(keys: tuple[str, str]) -> None:
    private_pem, public_pem = keys

    claims = verify(token_for(private_pem), AUDIENCE, key=public_pem, issuer=ISSUER)

    assert isinstance(claims, Claims)
    assert claims.sub == "alice-id"
    assert claims.act.sub == "triage-agent"
    assert claims.azp == "triage-agent"
    # Keycloak writes one audience as a string; the model normalizes it.
    assert claims.aud == [AUDIENCE]
    assert claims.scope == ["gitea:read", "gitea:write"]
    assert claims.groups == ["owners"]
    # The parameterized scope mapper writes a one-element array.
    assert claims.task_id == "task-1"


def test_a_string_audience_and_missing_groups_still_validate(keys: tuple[str, str]) -> None:
    private_pem, public_pem = keys

    claims = verify(
        token_for(private_pem, aud=AUDIENCE, groups=None),
        AUDIENCE,
        key=public_pem,
        issuer=ISSUER,
    )

    assert claims.aud == [AUDIENCE]
    assert claims.groups == []


def test_an_expired_token_is_refused(keys: tuple[str, str]) -> None:
    private_pem, public_pem = keys

    with pytest.raises(TokenExpired):
        verify(
            token_for(private_pem, exp=int(time.time()) - 30),
            AUDIENCE,
            key=public_pem,
            issuer=ISSUER,
        )


def test_a_wrong_audience_is_refused(keys: tuple[str, str]) -> None:
    private_pem, public_pem = keys

    with pytest.raises(AudienceMismatch):
        verify(
            token_for(private_pem, aud=["postgres-mcp"]),
            AUDIENCE,
            key=public_pem,
            issuer=ISSUER,
        )


def test_a_token_with_no_act_claim_is_refused(keys: tuple[str, str]) -> None:
    private_pem, public_pem = keys

    with pytest.raises(MissingActClaim):
        verify(token_for(private_pem, act=None), AUDIENCE, key=public_pem, issuer=ISSUER)


def test_an_act_that_is_not_an_object_is_refused(keys: tuple[str, str]) -> None:
    private_pem, public_pem = keys

    with pytest.raises(InvalidToken):
        verify(token_for(private_pem, act="triage-agent"), AUDIENCE, key=public_pem, issuer=ISSUER)


def test_an_act_that_disagrees_with_azp_is_refused(keys: tuple[str, str]) -> None:
    """The point of the mapper: two signed claims that must agree."""
    private_pem, public_pem = keys

    with pytest.raises(ActorMismatch):
        verify(
            token_for(private_pem, act={"sub": "support-agent"}),
            AUDIENCE,
            key=public_pem,
            issuer=ISSUER,
        )


def test_a_token_with_no_azp_is_refused(keys: tuple[str, str]) -> None:
    private_pem, public_pem = keys

    with pytest.raises(InvalidToken):
        verify(token_for(private_pem, azp=None), AUDIENCE, key=public_pem, issuer=ISSUER)


def test_a_token_signed_by_another_key_is_refused(keys: tuple[str, str]) -> None:
    _, public_pem = keys
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    with pytest.raises(InvalidToken):
        verify(token_for(other_pem), AUDIENCE, key=public_pem, issuer=ISSUER)


def test_the_refusal_classes_are_distinct() -> None:
    """Each refusal is its own class, so a caller can tell them apart.

    The test this replaces asserted `len(set_of_five) == 5`, which is a set
    literal and cannot fail. What is worth pinning is that the classes a caller
    catches are siblings rather than a hierarchy, so catching one never
    swallows another, and that all of them are `OidcError`.
    """
    classes = (TokenExpired, AudienceMismatch, MissingActClaim, InvalidToken, ActorMismatch)

    for one in classes:
        assert issubclass(one, OidcError), one
        assert one is not OidcError, one
        for other in classes:
            if one is not other:
                assert not issubclass(one, other), (one, other)
