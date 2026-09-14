"""The provenance ledger: what an agent has read in one task.

Warrant records a `Source` as it forwards each read, keyed by task id. The
in-memory dict answers the next request; the JSONL file under
`runs/<task_id>/provenance.jsonl` is the evidence a crash leaves behind, and
`get` replays it when the process that recorded it is gone.

In the `no-provenance` ablation nothing is recorded and `get` returns an empty
set, which is how W15 measures what the provenance checks are worth.
"""

from __future__ import annotations

from pathlib import Path

from warrant import config
from warrant.config import RUNS_DIR, Mode, task_dir
from warrant.models import Provenance, Source

LEDGER_NAME = "provenance.jsonl"


def ledger_path(root: Path | str, task_id: str) -> Path:
    """The JSONL file holding one task's sources."""
    return task_dir(root, task_id) / LEDGER_NAME


class Ledger:
    """Sources by task, in memory and on disk."""

    def __init__(self, root: Path | str = RUNS_DIR, mode: Mode | None = None) -> None:
        self.root = Path(root)
        self._mode = mode if mode is not None else config.current_mode()
        self._sources: dict[str, list[Source]] = {}

    def record(self, task_id: str, source: Source) -> None:
        """Record one read. A no-op under `no-provenance`."""
        if self._mode is Mode.no_provenance:
            return
        self._sources.setdefault(task_id, []).append(source)
        path = ledger_path(self.root, task_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(source.model_dump_json() + "\n")

    def get(self, task_id: str) -> Provenance:
        """Every source recorded for the task, memory first, then the file."""
        if self._mode is Mode.no_provenance:
            return Provenance(task_id=task_id)
        sources = self._sources.get(task_id)
        if sources is None:
            sources = self._read(task_id)
            self._sources[task_id] = sources
        return Provenance(task_id=task_id, sources=list(sources))

    def _read(self, task_id: str) -> list[Source]:
        path = ledger_path(self.root, task_id)
        if not path.exists():
            return []
        return [
            Source.model_validate_json(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
