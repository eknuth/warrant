"""`WARRANT_MODE` and the run-directory rules.

The mode behavior that needs the real environment (prompt-only) runs in a
subprocess, because `WARRANT_MODE` is read once at import and reloading the
module would hand the engine a second `Mode` class.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from warrant import config
from warrant.config import ChainSourceError, Mode

REPO = Path(__file__).resolve().parents[1]

PROMPT_ONLY_SNIPPET = """
import json
import sys
from datetime import UTC, datetime

from warrant.engine import CedarEngine
from warrant.log import DecisionLog
from warrant.models import ActionKind, AuthzRequest, Chain, Provenance

policies, runs = sys.argv[1], sys.argv[2]
chain = Chain(
    sub="h-alice",
    act="agent-triage",
    task_id="task-1",
    scopes=["read"],
    groups=["engineering"],
    token_exp=datetime(2030, 1, 1, tzinfo=UTC),
)
request = AuthzRequest(
    chain=chain,
    tool="gitea.search",
    action_kind=ActionKind.read,
    resource="repo-acme-api",
    args_digest="sha256:args",
    provenance=Provenance(task_id="task-1"),
    ts=datetime.now(UTC),
)
engine = CedarEngine(policies_dir=policies, schema_path=None, decision_log=DecisionLog(runs))
decision = engine.decide(request)
print(json.dumps({"verdict": decision.verdict.value, "policy_ids": decision.policy_ids}))
"""


def run_python(
    code: str, extra_env: dict[str, str], *args: str
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **extra_env}
    return subprocess.run(
        [sys.executable, "-c", code, *args],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )


def test_parse_mode_defaults_to_full_and_rejects_typos() -> None:
    assert config.parse_mode(None) is Mode.full
    assert config.parse_mode("") is Mode.full
    assert config.parse_mode("no-provenance") is Mode.no_provenance
    with pytest.raises(ValueError, match="WARRANT_MODE"):
        config.parse_mode("no-provenence")


def test_warrant_mode_is_read_from_the_environment_once() -> None:
    snippet = "import warrant.config as c;print(c.current_mode().value);print(c.DEFAULT_MODE.value)"

    result = run_python(snippet, {"WARRANT_MODE": "prompt-only"})

    assert result.stdout.split() == ["prompt-only", "prompt-only"]


def test_prompt_only_makes_every_decision_allow_and_logs_it(tmp_path: Path) -> None:
    policies = tmp_path / "policies"
    policies.mkdir()
    runs = tmp_path / "runs"

    result = run_python(
        PROMPT_ONLY_SNIPPET, {"WARRANT_MODE": "prompt-only"}, str(policies), str(runs)
    )
    decision = json.loads(result.stdout)

    assert decision["verdict"] == "allow"
    assert decision["policy_ids"] == ["ablation:prompt-only"]
    lines = (runs / "task-1" / "decisions.jsonl").read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["verdict"] == "allow"


def test_no_exchange_builds_the_chain_from_headers() -> None:
    headers = {
        "X-Warrant-Sub": "h-alice",
        "X-Warrant-Act": "agent-triage",
        "X-Warrant-Task-Id": "task-1",
        "X-Warrant-Scopes": "read write",
        "X-Warrant-Groups": "engineering,reviewers",
        "X-Warrant-Token-Exp": "1893456000",
    }

    chain = config.chain_from_headers(headers, mode=Mode.no_exchange)

    assert chain.sub == "h-alice"
    assert chain.act == "agent-triage"
    assert chain.task_id == "task-1"
    assert chain.scopes == ["read", "write"]
    assert chain.groups == ["engineering", "reviewers"]
    assert chain.token_exp.year == 2030


def test_no_exchange_is_case_insensitive_about_header_names() -> None:
    headers = {
        "x-warrant-sub": "h-alice",
        "X-WARRANT-ACT": "agent-triage",
        "X-Warrant-Task-Id": "task-1",
        "X-Warrant-Token-Exp": "1893456000",
    }

    chain = config.chain_from_headers(headers, mode=Mode.no_exchange)

    assert chain.sub == "h-alice"
    assert chain.scopes == []
    assert chain.groups == []


def test_the_verified_path_refuses_a_header_chain() -> None:
    """Every mode but no-exchange has to get the chain from the token."""
    headers = {
        "X-Warrant-Sub": "h-alice",
        "X-Warrant-Act": "agent-triage",
        "X-Warrant-Task-Id": "task-1",
        "X-Warrant-Token-Exp": "1893456000",
    }

    for mode in (Mode.full, Mode.no_provenance, Mode.prompt_only):
        with pytest.raises(ChainSourceError):
            config.chain_from_headers(headers, mode=mode)


def test_no_exchange_requires_the_identifying_headers() -> None:
    with pytest.raises(ChainSourceError, match="X-Warrant-Act"):
        config.chain_from_headers(
            {"X-Warrant-Sub": "h-alice", "X-Warrant-Task-Id": "t", "X-Warrant-Token-Exp": "1"},
            mode=Mode.no_exchange,
        )


def test_task_dir_keeps_a_crafted_task_id_inside_the_run_root(tmp_path: Path) -> None:
    assert config.task_dir(tmp_path, "task-1") == tmp_path / "task-1"
    # A crafted id stays inside the root, and carries a digest of the original
    # because the sanitizer changed it.
    escaped = config.task_dir(tmp_path, "../../escape")
    assert escaped.parent == tmp_path
    assert escaped.name.startswith(".._.._escape-")
    with pytest.raises(ValueError):
        config.task_dir(tmp_path, "..")
    with pytest.raises(ValueError):
        config.task_dir(tmp_path, "")


def test_two_distinct_task_ids_never_share_a_run_directory() -> None:
    """`a_b`, `a/b`, and `a b` used to be one directory, and so one ledger.

    Sharing a directory means sharing a provenance set, which is the one input
    the design says an agent cannot forge. `no-exchange` takes the task id from
    an agent-supplied header, so the collision is reachable.
    """
    ids = ["a_b", "a/b", "a b", "a\\b"]

    directories = {config.task_dir("/runs", task_id).name for task_id in ids}

    assert len(directories) == len(ids), directories
    assert config.task_dir("/runs", "a_b").name == "a_b", "a safe id keeps its name"
