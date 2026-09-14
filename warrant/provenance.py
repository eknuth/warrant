"""The provenance ledger: what one actor has read in one task.

Warrant records a `Source` as it forwards each read, keyed by the task id *and*
the actor. The in-memory dict answers the next request; the JSONL file under
`runs/<task_id>/provenance/<actor>.jsonl` is the evidence a crash leaves behind,
and `get` replays it when the process that recorded it is gone.

The actor is part of the key because the task id is not. `scope=task-id:<value>`
is written by the caller of the token exchange, so an agent chooses its own task
id; keying the ledger on the id alone let one agent name another task's id and
inherit its sources, and let one agent's reads append to another task's file.
Binding the file to the actor closes both directions without needing the task id
to be trustworthy: a task id that was never this actor's reads as empty, and
every actor's evidence stays on disk under its own name.

In the `no-provenance` ablation nothing is recorded and `get` returns an empty
set, which is how W15 measures what the provenance checks are worth.
"""

from __future__ import annotations

from pathlib import Path

from warrant import config
from warrant.config import RUNS_DIR, Mode, task_dir
from warrant.models import Provenance, Source

LEDGER_NAME = "provenance.jsonl"
LEDGER_DIR = "provenance"


def ledger_dir(root: Path | str, task_id: str) -> Path:
    """The directory holding one task's per-actor ledger files."""
    return task_dir(root, task_id) / LEDGER_DIR


def ledger_path(root: Path | str, task_id: str, actor: str) -> Path:
    """The JSONL file holding one actor's sources in one task.

    `actor` is a client id from a verified token, but it still names a file, so
    it is sanitized on the way. The digest the sanitizer appends keeps two
    different actors from sharing a file.
    """
    return ledger_dir(root, task_id) / f"{task_dir('.', actor).name}.jsonl"


class Ledger:
    """Sources by task and actor, in memory and on disk."""

    def __init__(self, root: Path | str = RUNS_DIR, mode: Mode | None = None) -> None:
        self.root = Path(root)
        # `Mode(...)` rather than the value as given: a bare string that happens
        # to match would compare unequal against `is`, silently disabling the
        # ablation and corrupting the measurement.
        self._mode = Mode(mode) if mode is not None else config.current_mode()
        self._sources: dict[tuple[str, str], list[Source]] = {}

    def record(self, task_id: str, actor: str, source: Source) -> None:
        """Record one read. A no-op under `no-provenance`."""
        if self._mode is Mode.no_provenance:
            return
        self._sources.setdefault((task_id, actor), []).append(source)
        path = ledger_path(self.root, task_id, actor)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(source.model_dump_json() + "\n")

    def get(self, task_id: str, actor: str) -> Provenance:
        """Every source this actor read in this task, memory first, then the file."""
        if self._mode is Mode.no_provenance:
            return Provenance(task_id=task_id)
        key = (task_id, actor)
        sources = self._sources.get(key)
        if sources is None:
            sources = self._read(task_id, actor)
            self._sources[key] = sources
        return Provenance(task_id=task_id, sources=list(sources))

    def _read(self, task_id: str, actor: str) -> list[Source]:
        path = ledger_path(self.root, task_id, actor)
        if not path.exists():
            return []
        return [
            Source.model_validate_json(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
