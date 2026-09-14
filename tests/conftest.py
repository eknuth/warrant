"""Fixtures shared by the W5 tests.

Every fixture that can write gives the test a temp directory, so no test leaves
a ledger, a decision log, or a database in the repository.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from warrant.log import DecisionLog
from warrant.models import ActionKind, AuthzRequest, Chain, Provenance, Source, Tier

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def chain() -> Chain:
    return Chain(
        sub="h-alice",
        act="agent-triage",
        task_id="task-1",
        scopes=["read", "write"],
        groups=["engineering"],
        token_exp=datetime(2030, 1, 1, tzinfo=UTC),
    )


@pytest.fixture
def make_source() -> Callable[..., Source]:
    def _make(**overrides: object) -> Source:
        data: dict[str, object] = {
            "system": "gitea",
            "kind": "issue",
            "id": "issue-1",
            "author": "carol",
            "author_tier": Tier.member,
            "digest": "sha256:abc",
        }
        data.update(overrides)
        return Source.model_validate(data)

    return _make


@pytest.fixture
def make_request(chain: Chain) -> Callable[..., AuthzRequest]:
    def _make(provenance: Provenance | None = None, **overrides: object) -> AuthzRequest:
        default_provenance = (
            provenance if provenance is not None else Provenance(task_id=chain.task_id)
        )
        data: dict[str, object] = {
            "chain": chain,
            "tool": "gitea.search",
            "action_kind": ActionKind.read,
            "resource": "repo-acme-api",
            "args_digest": "sha256:args",
            "provenance": default_provenance,
            "ts": datetime.now(UTC),
        }
        data.update(overrides)
        return AuthzRequest.model_validate(data)

    return _make


@pytest.fixture
def policy_dir(tmp_path: Path) -> Callable[..., Path]:
    """Write Cedar policies into a temp directory and return it."""

    def _make(*policies: str) -> Path:
        directory = tmp_path / "policies"
        directory.mkdir(exist_ok=True)
        for index, text in enumerate(policies):
            (directory / f"{index:02d}_test.cedar").write_text(text, encoding="utf-8")
        return directory

    return _make


@pytest.fixture
def decision_log(tmp_path: Path) -> DecisionLog:
    return DecisionLog(tmp_path / "runs")
