"""The provenance ledger: memory, the JSONL evidence, and the ablation."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from warrant.config import Mode
from warrant.models import Source, Tier
from warrant.provenance import Ledger, classify, ledger_path


def test_two_records_come_back_and_leave_two_lines(
    tmp_path: Path, make_source: Callable[..., Source]
) -> None:
    ledger = Ledger(root=tmp_path)

    ledger.record("task-1", "triage-agent", make_source(id="issue-1", author_tier=Tier.member))
    ledger.record("task-1", "triage-agent", make_source(id="message-1", author_tier=Tier.external))

    provenance = ledger.get("task-1", "triage-agent")
    assert [source.id for source in provenance.sources] == ["issue-1", "message-1"]
    assert provenance.min_tier is Tier.external
    assert provenance.has_external is True

    lines = ledger_path(tmp_path, "task-1", "triage-agent").read_text().splitlines()
    assert len(lines) == 2


def test_a_fresh_ledger_replays_the_file(
    tmp_path: Path, make_source: Callable[..., Source]
) -> None:
    """The point of the JSONL: a crash leaves the evidence behind."""
    Ledger(root=tmp_path).record("task-1", "triage-agent", make_source(id="issue-1"))

    replayed = Ledger(root=tmp_path).get("task-1", "triage-agent")

    assert [source.id for source in replayed.sources] == ["issue-1"]


def test_an_unknown_task_is_an_empty_provenance(tmp_path: Path) -> None:
    provenance = Ledger(root=tmp_path).get("never-seen", "triage-agent")

    assert provenance.sources == []
    assert provenance.task_id == "never-seen"
    assert not ledger_path(tmp_path, "never-seen", "triage-agent").exists()


def test_no_provenance_records_nothing_and_reads_empty(
    tmp_path: Path, make_source: Callable[..., Source]
) -> None:
    ledger = Ledger(root=tmp_path, mode=Mode.no_provenance)

    ledger.record("task-1", "triage-agent", make_source())

    assert ledger.get("task-1", "triage-agent").sources == []
    assert not ledger_path(tmp_path, "task-1", "triage-agent").exists()


def test_a_crafted_task_id_cannot_escape_the_run_root(
    tmp_path: Path, make_source: Callable[..., Source]
) -> None:
    ledger = Ledger(root=tmp_path)

    ledger.record("../escape", "triage-agent", make_source())

    written = ledger_path(tmp_path, "../escape", "triage-agent")
    assert written.resolve().is_relative_to(tmp_path.resolve())
    assert written.read_text().splitlines()
    assert not (tmp_path.parent / "escape").exists()


def test_sources_are_stored_by_task(tmp_path: Path, make_source: Callable[..., Source]) -> None:
    ledger = Ledger(root=tmp_path)

    ledger.record("task-1", "triage-agent", make_source(id="one"))
    ledger.record("task-2", "triage-agent", make_source(id="two"))

    assert [source.id for source in ledger.get("task-1", "triage-agent").sources] == ["one"]
    assert [source.id for source in ledger.get("task-2", "triage-agent").sources] == ["two"]


def test_one_actor_cannot_read_another_actors_ledger(
    tmp_path: Path, make_source: Callable[..., Source]
) -> None:
    """The task id is the caller's, so the actor has to be part of the key.

    An agent writes `scope=task-id:<value>` itself, so it can name a task id
    that is not its own. Keying the ledger on the id alone let it read the
    sources another agent had recorded under that id, and let its own reads
    append to that other agent's file.
    """
    ledger = Ledger(root=tmp_path)
    ledger.record("shared-task", "triage-agent", make_source(id="secret.env"))

    assert [source.id for source in ledger.get("shared-task", "triage-agent").sources] == [
        "secret.env"
    ]
    assert ledger.get("shared-task", "support-agent").sources == []


def test_a_replayed_ledger_is_still_per_actor(
    tmp_path: Path, make_source: Callable[..., Source]
) -> None:
    Ledger(root=tmp_path).record("task-1", "triage-agent", make_source(id="issue-1"))

    fresh = Ledger(root=tmp_path)

    assert [source.id for source in fresh.get("task-1", "triage-agent").sources] == ["issue-1"]
    assert fresh.get("task-1", "support-agent").sources == []
    assert (
        ledger_path(tmp_path, "task-1", "triage-agent").parent
        == ledger_path(tmp_path, "task-1", "support-agent").parent
    )


# -- the classifier ---------------------------------------------------------


def test_an_instruction_file_from_a_non_member_is_external(
    make_source: Callable[..., Source],
) -> None:
    instructions = make_source(
        system="gitea",
        kind="file",
        id="acme/widgets:.github/copilot-instructions.md@main",
        author="mallory",
        author_tier=Tier.external,
    )

    assert classify(instructions) is Tier.external


def test_an_instruction_file_from_a_member_keeps_the_member_tier(
    make_source: Callable[..., Source],
) -> None:
    instructions = make_source(
        system="gitea",
        kind="file",
        id="acme/widgets:.github/copilot-instructions.md@main",
        author="bob",
        author_tier=Tier.member,
    )

    assert classify(instructions) is Tier.member


def test_an_instruction_file_with_no_resolvable_author_is_external(
    make_source: Callable[..., Source],
) -> None:
    """A commit with no forge account is not a member either."""
    instructions = make_source(
        system="gitea",
        kind="file",
        id="acme/widgets:AGENTS.md@main",
        author="",
        author_tier=Tier.unknown,
    )

    assert classify(instructions) is Tier.external


def test_every_instruction_path_shape_is_covered(
    make_source: Callable[..., Source],
) -> None:
    for path in (".cursor/rules/style.md", "CLAUDE.md", "config/widgets.rules", "docs/AGENTS.md"):
        source = make_source(
            system="gitea",
            kind="file",
            id=f"acme/widgets:{path}@main",
            author="mallory",
            author_tier=Tier.external,
        )
        assert classify(source) is Tier.external, path


def test_an_ordinary_file_keeps_the_upstream_tier(make_source: Callable[..., Source]) -> None:
    ordinary = make_source(
        system="gitea",
        kind="file",
        id="acme/widgets:app.py@main",
        author="bob",
        author_tier=Tier.member,
    )

    assert classify(ordinary) is Tier.member


def test_a_raw_sql_read_has_no_author_to_grade(make_source: Callable[..., Source]) -> None:
    query = make_source(system="db", kind="query", id="q1", author="", author_tier=Tier.member)

    assert classify(query) is Tier.unknown


def test_a_mail_sender_outside_the_member_domain_is_external(
    make_source: Callable[..., Source],
) -> None:
    outside = make_source(system="mail", kind="message", id="m1", author="stranger@other.test")

    assert classify(outside) is Tier.external


def test_a_mail_sender_inside_the_member_domain_keeps_the_member_tier(
    make_source: Callable[..., Source],
) -> None:
    inside = make_source(system="mail", kind="message", id="m1", author="desk@acme.test")

    assert classify(inside) is Tier.member
