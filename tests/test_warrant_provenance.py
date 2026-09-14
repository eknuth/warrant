"""The provenance ledger: memory, the JSONL evidence, and the ablation."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from warrant.config import Mode
from warrant.models import Source, Tier
from warrant.provenance import Ledger, ledger_path


def test_two_records_come_back_and_leave_two_lines(
    tmp_path: Path, make_source: Callable[..., Source]
) -> None:
    ledger = Ledger(root=tmp_path)

    ledger.record("task-1", make_source(id="issue-1", author_tier=Tier.member))
    ledger.record("task-1", make_source(id="message-1", author_tier=Tier.external))

    provenance = ledger.get("task-1")
    assert [source.id for source in provenance.sources] == ["issue-1", "message-1"]
    assert provenance.min_tier is Tier.external
    assert provenance.has_external is True

    lines = ledger_path(tmp_path, "task-1").read_text().splitlines()
    assert len(lines) == 2


def test_a_fresh_ledger_replays_the_file(
    tmp_path: Path, make_source: Callable[..., Source]
) -> None:
    """The point of the JSONL: a crash leaves the evidence behind."""
    Ledger(root=tmp_path).record("task-1", make_source(id="issue-1"))

    replayed = Ledger(root=tmp_path).get("task-1")

    assert [source.id for source in replayed.sources] == ["issue-1"]


def test_an_unknown_task_is_an_empty_provenance(tmp_path: Path) -> None:
    provenance = Ledger(root=tmp_path).get("never-seen")

    assert provenance.sources == []
    assert provenance.task_id == "never-seen"
    assert not ledger_path(tmp_path, "never-seen").exists()


def test_no_provenance_records_nothing_and_reads_empty(
    tmp_path: Path, make_source: Callable[..., Source]
) -> None:
    ledger = Ledger(root=tmp_path, mode=Mode.no_provenance)

    ledger.record("task-1", make_source())

    assert ledger.get("task-1").sources == []
    assert not ledger_path(tmp_path, "task-1").exists()


def test_a_crafted_task_id_cannot_escape_the_run_root(
    tmp_path: Path, make_source: Callable[..., Source]
) -> None:
    ledger = Ledger(root=tmp_path)

    ledger.record("../escape", make_source())

    written = ledger_path(tmp_path, "../escape")
    assert written.resolve().is_relative_to(tmp_path.resolve())
    assert written.read_text().splitlines()
    assert not (tmp_path.parent / "escape").exists()


def test_sources_are_stored_by_task(tmp_path: Path, make_source: Callable[..., Source]) -> None:
    ledger = Ledger(root=tmp_path)

    ledger.record("task-1", make_source(id="one"))
    ledger.record("task-2", make_source(id="two"))

    assert [source.id for source in ledger.get("task-1").sources] == ["one"]
    assert [source.id for source in ledger.get("task-2").sources] == ["two"]
