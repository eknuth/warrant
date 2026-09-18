"""Time-boxed grants: the narrow allowance an approval mints.

The store is a file, so these tests use a temporary runs directory and a fake
clock. The two properties that matter are that the match is exact on the task,
the tool, and the resource, and that the expiry is enforced.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from warrant.grants import SOURCE_HUMAN, GrantStore, grant_policy_id

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def store(tmp_path: Path) -> GrantStore:
    return GrantStore(tmp_path / "runs")


def test_a_minted_grant_is_found_for_its_own_call(tmp_path: Path) -> None:
    grants = store(tmp_path)
    grant = grants.mint(
        task_id="task-1",
        tool="db.rotate_api_key",
        resource="db-customer-1",
        minutes=10,
        now=NOW,
    )

    found = grants.find(
        task_id="task-1",
        tool="db.rotate_api_key",
        resource="db-customer-1",
        now=NOW + timedelta(minutes=9),
    )

    assert found is not None
    assert found.id == grant.id
    assert found.expires_at == NOW + timedelta(minutes=10)


def test_a_grant_is_written_to_the_runs_directory(tmp_path: Path) -> None:
    grants = store(tmp_path)
    grants.mint(task_id="t", tool="x", resource="r", minutes=1, now=NOW)

    assert grants.path == tmp_path / "runs" / "grants.jsonl"
    assert grants.path.exists()


@pytest.mark.parametrize(
    ("task_id", "tool", "resource"),
    [
        ("task-other", "db.rotate_api_key", "db-customer-1"),
        ("task-1", "db.update_ticket", "db-customer-1"),
        ("task-1", "db.rotate_api_key", "db-customer-2"),
    ],
)
def test_a_grant_never_answers_another_task_tool_or_resource(
    tmp_path: Path, task_id: str, tool: str, resource: str
) -> None:
    grants = store(tmp_path)
    grants.mint(
        task_id="task-1",
        tool="db.rotate_api_key",
        resource="db-customer-1",
        minutes=10,
        now=NOW,
    )

    assert (
        grants.find(task_id=task_id, tool=tool, resource=resource, now=NOW + timedelta(minutes=1))
        is None
    )


def test_an_expired_grant_is_not_found(tmp_path: Path) -> None:
    grants = store(tmp_path)
    grants.mint(
        task_id="task-1",
        tool="db.rotate_api_key",
        resource="db-customer-1",
        minutes=10,
        now=NOW,
    )

    assert (
        grants.find(
            task_id="task-1",
            tool="db.rotate_api_key",
            resource="db-customer-1",
            now=NOW + timedelta(minutes=10),
        )
        is None
    ), "the expiry is exclusive: at its own minute the grant is over"


def test_the_latest_matching_grant_wins(tmp_path: Path) -> None:
    grants = store(tmp_path)
    first = grants.mint(task_id="t", tool="x", resource="r", minutes=5, now=NOW)
    second = grants.mint(
        task_id="t", tool="x", resource="r", minutes=5, now=NOW + timedelta(minutes=1)
    )

    found = grants.find(task_id="t", tool="x", resource="r", now=NOW + timedelta(minutes=2))

    assert found is not None
    assert found.id == second.id
    assert first.id != second.id


@pytest.mark.parametrize("minutes", [0, -1, 61])
def test_a_time_box_outside_the_bounds_is_refused(tmp_path: Path, minutes: int) -> None:
    with pytest.raises(ValueError, match="time box"):
        store(tmp_path).mint(task_id="t", tool="x", resource="r", minutes=minutes, now=NOW)


def test_the_policy_id_names_the_grant(tmp_path: Path) -> None:
    grant = store(tmp_path).mint(task_id="t", tool="x", resource="r", minutes=5, now=NOW)

    assert grant_policy_id(grant) == f"grant:{grant.id}"


def test_an_unreadable_line_is_skipped_not_fatal(tmp_path: Path) -> None:
    grants = store(tmp_path)
    grants.mint(task_id="t", tool="x", resource="r", minutes=5, now=NOW)
    with grants.path.open("a", encoding="utf-8") as handle:
        handle.write("{ this is not json\n")
    grants.mint(task_id="t", tool="y", resource="r", minutes=5, now=NOW)

    assert grants.find(task_id="t", tool="x", resource="r", now=NOW) is not None
    assert grants.find(task_id="t", tool="y", resource="r", now=NOW) is not None


def test_the_default_source_is_a_person(tmp_path: Path) -> None:
    grant = store(tmp_path).mint(task_id="t", tool="x", resource="r", minutes=5, now=NOW)

    assert grant.source == SOURCE_HUMAN
