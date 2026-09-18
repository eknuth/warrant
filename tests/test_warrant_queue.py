"""The human queue: what a person is asked, and what their answer mints.

The queue is a file under the runs directory, so these tests use a temporary
one and a fake clock. The CLI tests call `main` with the queue injected, which
is the same code path `python -m warrant queue` runs.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from warrant.grants import GrantStore
from warrant.models import AuthzRequest
from warrant.queue import Queue, main

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def queue_for(tmp_path: Path) -> Queue:
    return Queue(tmp_path / "runs")


def test_a_deferred_call_lands_with_its_full_request(
    tmp_path: Path, make_request: Callable[..., AuthzRequest]
) -> None:
    queue = queue_for(tmp_path)
    request = make_request()

    item = queue.add(request, reason="the ledger names no ticket or issue", now=NOW)

    assert item.status == "pending"
    assert item.request.tool == request.tool
    assert item.request.chain.task_id == request.chain.task_id
    assert item.request.provenance.sources == request.provenance.sources
    written = queue.path.read_text(encoding="utf-8")
    assert request.chain.act in written
    assert queue.pending() == [item]


def test_the_queue_file_is_queue_jsonl_under_the_runs_root(
    tmp_path: Path, make_request: Callable[..., AuthzRequest]
) -> None:
    queue = queue_for(tmp_path)
    queue.add(make_request(), reason="no verdict", now=NOW)

    assert queue.path == tmp_path / "runs" / "queue.jsonl"
    assert queue.path.exists()


def test_an_approved_entry_mints_a_grant_for_exactly_its_call(
    tmp_path: Path, make_request: Callable[..., AuthzRequest]
) -> None:
    queue = queue_for(tmp_path)
    request = make_request(tool="db.rotate_api_key", resource="db-customer-1")
    item = queue.add(request, reason="the verdict did not cite the ledger", now=NOW)

    resolved, grant = queue.approve(item.id, 10, now=NOW)

    assert resolved.status == "approved"
    assert resolved.grant_id == grant.id
    assert resolved.minutes == 10
    assert grant.task_id == request.chain.task_id
    assert grant.tool == "db.rotate_api_key"
    assert grant.resource == "db-customer-1"
    assert grant.expires_at == NOW + timedelta(minutes=10)
    store = GrantStore(tmp_path / "runs")
    assert (
        store.find(
            task_id=request.chain.task_id,
            tool="db.rotate_api_key",
            resource="db-customer-1",
            now=NOW + timedelta(minutes=1),
        )
        is not None
    )
    assert queue.pending() == []


def test_an_approved_entry_is_not_pending_twice(
    tmp_path: Path, make_request: Callable[..., AuthzRequest]
) -> None:
    queue = queue_for(tmp_path)
    item = queue.add(make_request(), reason="no verdict", now=NOW)
    queue.approve(item.id, 10, now=NOW)

    with pytest.raises(ValueError, match="already approved"):
        queue.approve(item.id, 10, now=NOW)


def test_an_unknown_entry_is_refused(
    tmp_path: Path, make_request: Callable[..., AuthzRequest]
) -> None:
    queue = queue_for(tmp_path)

    with pytest.raises(KeyError):
        queue.approve("nope", 10, now=NOW)
    with pytest.raises(KeyError):
        queue.deny("nope", now=NOW)


def test_a_time_box_outside_the_bounds_is_refused(
    tmp_path: Path, make_request: Callable[..., AuthzRequest]
) -> None:
    queue = queue_for(tmp_path)
    item = queue.add(make_request(), reason="no verdict", now=NOW)

    with pytest.raises(ValueError, match="time box"):
        queue.approve(item.id, 0, now=NOW)
    assert queue.pending() == [item]


def test_a_denied_entry_mints_nothing(
    tmp_path: Path, make_request: Callable[..., AuthzRequest]
) -> None:
    queue = queue_for(tmp_path)
    item = queue.add(make_request(), reason="no verdict", now=NOW)

    resolved = queue.deny(item.id, now=NOW)

    assert resolved.status == "denied"
    assert resolved.grant_id is None
    assert not GrantStore(tmp_path / "runs").path.exists()
    assert queue.pending() == []


def test_the_latest_snapshot_of_an_entry_wins(
    tmp_path: Path, make_request: Callable[..., AuthzRequest]
) -> None:
    queue = queue_for(tmp_path)
    item = queue.add(make_request(), reason="no verdict", now=NOW)
    queue.deny(item.id, now=NOW)

    latest = queue.get(item.id)

    assert latest is not None
    assert latest.status == "denied"
    assert len(queue.read()) == 2, "the pending line is kept; the resolution is appended"


def test_an_unreadable_line_is_skipped_not_fatal(
    tmp_path: Path, make_request: Callable[..., AuthzRequest]
) -> None:
    queue = queue_for(tmp_path)
    queue.add(make_request(), reason="no verdict", now=NOW)
    with queue.path.open("a", encoding="utf-8") as handle:
        handle.write("{ not json\n")
    queue.add(make_request(), reason="another", now=NOW)

    assert len(queue.pending()) == 2


# -- the CLI ----------------------------------------------------------------


def test_the_cli_lists_pending_entries(
    tmp_path: Path, make_request: Callable[..., AuthzRequest], capsys: pytest.CaptureFixture[str]
) -> None:
    queue = queue_for(tmp_path)
    request = make_request(tool="db.rotate_api_key", resource="db-customer-1")
    item = queue.add(request, reason="no cited source is in the ledger", now=NOW)

    assert main(["list"], queue=queue) == 0
    out = capsys.readouterr().out
    assert item.id in out
    assert "db.rotate_api_key -> db-customer-1" in out
    assert "no cited source is in the ledger" in out


def test_the_cli_says_when_nothing_is_pending(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["list"], queue=queue_for(tmp_path)) == 0
    assert capsys.readouterr().out.strip() == "no pending escalations"


def test_the_cli_approves_with_a_time_box(
    tmp_path: Path, make_request: Callable[..., AuthzRequest], capsys: pytest.CaptureFixture[str]
) -> None:
    queue = queue_for(tmp_path)
    item = queue.add(make_request(), reason="no verdict", now=NOW)

    assert main(["approve", item.id, "--minutes", "10"], queue=queue) == 0
    assert f"approved {item.id}" in capsys.readouterr().out
    assert queue.get(item.id).status == "approved"


def test_the_cli_denies(tmp_path: Path, make_request: Callable[..., AuthzRequest]) -> None:
    queue = queue_for(tmp_path)
    item = queue.add(make_request(), reason="no verdict", now=NOW)

    assert main(["deny", item.id], queue=queue) == 0
    assert queue.get(item.id).status == "denied"


def test_the_cli_reports_a_bad_id_and_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["approve", "nope", "--minutes", "10"], queue=queue_for(tmp_path)) == 2
    assert "no queue entry" in capsys.readouterr().err


def test_the_cli_reports_a_bad_time_box_and_exits_two(
    tmp_path: Path, make_request: Callable[..., AuthzRequest], capsys: pytest.CaptureFixture[str]
) -> None:
    queue = queue_for(tmp_path)
    item = queue.add(make_request(), reason="no verdict", now=NOW)

    assert main(["approve", item.id, "--minutes", "61"], queue=queue) == 2
    assert "time box" in capsys.readouterr().err
