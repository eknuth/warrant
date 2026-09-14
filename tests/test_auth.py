"""The auth helpers, and the re-export the W3 integration fixture depends on."""

from __future__ import annotations

from jose import jwt

import agents.auth as auth
import scripts.token_exchange as token_exchange


def test_the_script_reexports_the_moved_helpers() -> None:
    """`tests/conftest.py` imports these names from the script.

    The helpers moved into `agents.auth`; the script has to keep exporting them
    or the W3 integration fixture stops importing.
    """
    assert token_exchange.DevSettings is auth.DevSettings
    assert token_exchange.login_as_alice is auth.login_as_alice
    assert token_exchange.exchange_for_obo is auth.exchange_for_obo
    assert token_exchange.TOKEN_EXCHANGE_GRANT == auth.TOKEN_EXCHANGE_GRANT
    assert token_exchange.ACCESS_TOKEN_TYPE == auth.ACCESS_TOKEN_TYPE


def test_decode_claims_drops_the_signature() -> None:
    token = jwt.encode({"sub": "alice", "aud": "gitea-mcp"}, "a-signing-key", algorithm="HS256")

    decoded = auth.decode_claims(token)

    assert decoded["claims"]["sub"] == "alice"
    assert decoded["header"]["alg"] == "HS256"
    assert "signature" not in decoded
    assert token.split(".")[2] not in repr(decoded)


def test_audience_list_normalizes_the_two_shapes() -> None:
    assert auth.audience_list({"aud": "gitea-mcp"}) == ["gitea-mcp"]
    assert auth.audience_list({"aud": ["gitea-mcp", "postgres-mcp"]}) == [
        "gitea-mcp",
        "postgres-mcp",
    ]
    assert auth.audience_list({}) == []


def test_claim_task_id_reads_a_parameterized_scope_value() -> None:
    assert auth.claim_task_id({"task_id": ["task-1"]}) == "task-1"
    assert auth.claim_task_id({"task_id": "task-1"}) == "task-1"
    assert auth.claim_task_id({"task_id": []}) is None
    assert auth.claim_task_id({}) is None


def test_lifetime_seconds_needs_both_claims() -> None:
    assert auth.lifetime_seconds({"iat": 100, "exp": 400}) == 300
    assert auth.lifetime_seconds({"iat": 100}) is None
    assert auth.lifetime_seconds({"iat": "100", "exp": 400}) is None
