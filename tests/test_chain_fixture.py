"""The chain invariants, checked over a committed recording of a real run.

`runs/` is gitignored, so nothing here reads a live run. The fixture under
`tests/fixtures/recorded_run/` is a copy of one run's `calls.jsonl` and
`token.json` with the signature stripped. The token record carries claims only,
and the call log carries digests rather than tool arguments and results, so the
fixture is evidence of a run rather than a credential from one.

Every check in this file is one the ticket's acceptance criteria name.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "recorded_run"
CALLS = FIXTURE / "calls.jsonl"
TOKEN = FIXTURE / "token.json"

REQUIRED_CALL_KEYS = ("ts", "task_id", "sub", "act", "tool", "args_digest", "result_digest")


def call_lines() -> list[dict[str, Any]]:
    text = CALLS.read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def token_record() -> dict[str, Any]:
    return json.loads(TOKEN.read_text(encoding="utf-8"))


def test_the_recording_has_calls() -> None:
    lines = call_lines()

    assert lines, "a recorded run with no calls proves nothing"


def test_every_call_line_carries_the_same_chain() -> None:
    lines = call_lines()

    assert {line["sub"] for line in lines} == {"alice"}
    assert {line["act"] for line in lines} == {"triage-agent"}
    assert len({line["task_id"] for line in lines}) == 1
    for line in lines:
        for key in REQUIRED_CALL_KEYS:
            assert key in line, key


def test_the_call_chain_matches_the_token_the_run_used() -> None:
    record = token_record()

    assert call_lines()[0]["task_id"] == record["task_id"]


def test_the_obo_token_names_only_the_gitea_mcp_audience() -> None:
    claims = token_record()["claims"]

    audience = claims["aud"]
    audience = [audience] if isinstance(audience, str) else audience
    assert audience == ["gitea-mcp"]
    assert claims["act"]["sub"] == "triage-agent"
    assert claims["azp"] == "triage-agent"


def test_the_obo_token_lifetime_is_five_minutes_or_less() -> None:
    record = token_record()

    assert record["lifetime_seconds"] == record["claims"]["exp"] - record["claims"]["iat"]
    assert 0 < record["lifetime_seconds"] <= 300


def test_the_call_chain_points_at_the_token_subject() -> None:
    record = token_record()

    assert call_lines()[0]["sub_id"] == record["claims"]["sub"]


def test_the_token_record_is_the_decoded_token_with_the_signature_stripped() -> None:
    record = token_record()

    assert record["signature"] is None
    assert "signature" not in record["claims"]
    assert record["header"]["alg"]
    # Session identifiers for a session that ended are not committed either.
    assert "jti" not in record["claims"]
    assert "sid" not in record["claims"]


def test_neither_fixture_carries_a_signature_or_a_credential() -> None:
    for path in (CALLS, TOKEN):
        text = path.read_text(encoding="utf-8")
        assert "eyJ" not in text, f"{path.name} looks like it carries a JWT"
        assert "sk-" not in text, f"{path.name} looks like it carries an API key"
        assert "BEGIN" not in text, f"{path.name} looks like it carries a PEM key"
        assert not re.search(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}", text), path.name
