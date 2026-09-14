"""The decision log: one `Decision` per line, keyed by task.

`runs/<task_id>/decisions.jsonl` is the record the grader (W14) reads. Each line
is a whole `Decision` with the full request inlined, so a line on its own says
who asked, which agent acted, what was read, what was touched, what the verdict
was, and which policies produced it. Nothing in the log needs a model to
interpret, and no line refers to another line.
"""

from __future__ import annotations

from pathlib import Path

from warrant.config import RUNS_DIR, task_dir
from warrant.models import Decision

LOG_NAME = "decisions.jsonl"


def decisions_path(root: Path | str, task_id: str) -> Path:
    """The JSONL file holding one task's decisions."""
    return task_dir(root, task_id) / LOG_NAME


class DecisionLog:
    """Append-only decisions by task."""

    def __init__(self, root: Path | str = RUNS_DIR) -> None:
        self.root = Path(root)

    def append(self, decision: Decision) -> None:
        """Write one decision as one line, flushed before returning."""
        path = decisions_path(self.root, decision.request.chain.task_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(decision.model_dump_json() + "\n")
            handle.flush()

    def read(self, task_id: str) -> list[Decision]:
        """Every decision recorded for the task, in the order it was written."""
        path = decisions_path(self.root, task_id)
        if not path.exists():
            return []
        return [
            Decision.model_validate_json(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
