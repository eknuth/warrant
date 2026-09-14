"""The request and decision model, including the computed provenance fields."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from warrant.models import (
    ActionKind,
    AuthzRequest,
    Chain,
    Provenance,
    Source,
    Tier,
    Verdict,
)


def chain() -> Chain:
    return Chain(
        sub="h-alice",
        act="agent-triage",
        task_id="task-1",
        scopes=["read"],
        groups=["engineering"],
        token_exp=datetime(2030, 1, 1, tzinfo=UTC),
    )


def test_provenance_computes_the_least_trusted_tier() -> None:
    provenance = Provenance(
        task_id="task-1",
        sources=[
            Source(
                system="gitea",
                kind="issue",
                id="i1",
                author="alice",
                author_tier=Tier.owner,
                digest="d1",
            ),
            Source(
                system="mail",
                kind="message",
                id="m1",
                author="stranger",
                author_tier=Tier.external,
                digest="d2",
            ),
            Source(
                system="postgres",
                kind="row",
                id="r1",
                author="member",
                author_tier=Tier.member,
                digest="d3",
            ),
        ],
    )

    assert provenance.min_tier is Tier.external
    assert provenance.has_external is True


def test_provenance_with_no_sources_reads_as_owner_and_not_external() -> None:
    provenance = Provenance(task_id="task-1")

    assert provenance.sources == []
    assert provenance.min_tier is Tier.owner
    assert provenance.has_external is False


def test_computed_fields_survive_a_json_round_trip() -> None:
    provenance = Provenance(
        task_id="task-1",
        sources=[
            Source(
                system="mail",
                kind="message",
                id="m1",
                author="stranger",
                author_tier=Tier.external,
                digest="d2",
            )
        ],
    )

    restored = Provenance.model_validate_json(provenance.model_dump_json())

    assert restored.min_tier is Tier.external
    assert restored.has_external is True


def test_request_rejects_provenance_from_another_task() -> None:
    request = {
        "chain": chain(),
        "tool": "gitea.search",
        "action_kind": ActionKind.read,
        "resource": "repo-acme-api",
        "args_digest": "sha256:args",
        "provenance": Provenance(task_id="another-task"),
        "ts": datetime.now(UTC),
    }

    with pytest.raises(ValidationError, match="provenance is for task"):
        AuthzRequest.model_validate(request)


def test_request_requires_a_timezone_aware_timestamp() -> None:
    request = {
        "chain": chain(),
        "tool": "gitea.search",
        "action_kind": ActionKind.read,
        "resource": "repo-acme-api",
        "args_digest": "sha256:args",
        "provenance": Provenance(task_id="task-1"),
        "ts": datetime(2026, 1, 1),
    }

    with pytest.raises(ValidationError):
        AuthzRequest.model_validate(request)


def test_request_rejects_an_unknown_action_kind() -> None:
    request = {
        "chain": chain(),
        "tool": "gitea.search",
        "action_kind": "delete",
        "resource": "repo-acme-api",
        "args_digest": "sha256:args",
        "provenance": Provenance(task_id="task-1"),
        "ts": datetime.now(UTC),
    }

    with pytest.raises(ValidationError):
        AuthzRequest.model_validate(request)


def test_verdicts_are_the_three_values() -> None:
    assert {verdict.value for verdict in Verdict} == {"allow", "deny", "escalate"}
