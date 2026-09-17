"""PreToolUse hook on bash: a parked results column sits out of the report's way.

Runs through the harness's command-hook bridge, which puts the tool name in
`tool_name` and the tool arguments in `tool_input`, so this hook sees the tool
named `bash`.

What it enforces: a parked column goes to
`evals/results/<park>/<ablation>/<model>/<scenario>/<n>`, never to a layout the
report reads as live. The report is pointed at one column directory and globs
`<ablation>/<model>/<scenario>/<repeat>/grade.json`; a column renamed to a name
that is not one of the six ablations, with cells at the same depth, is the shape
the report would read as a live ablation named after the parking directory.

The config and provider names mirror `evals.ablations.ABLATION_NAMES` and the
runner's model routes; `tests/test_evals_ablations.py` keeps the ablation list
equal to this one.

Blocks only when the final layout leaves cells at three levels under
`evals/results/` beneath a directory name that no runner writes. Simulates the
command's `mkdir`, `mv`, and `cp` segments in order, following `cd`. A
destination that exists on disk or was created earlier in the same command is
read as "move into". A trailing slash on a destination that does not exist is a
rename. `rsync`, `tar`, and moves done from inside a script are not covered.
Everything else passes through: exit 0, no output, and so does any unexpected
error. Standard library only, no network.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

# Mirrors `evals.ablations.ABLATION_NAMES` and the model directory the runner
# writes; `tests/test_evals_ablations.py` checks the ablations half.
CONFIGS = ("full", "task-taint", "content-taint", "no-provenance", "no-exchange", "prompt-only")
PROVIDERS = ("deepseek",)
RESULTS = "evals/results/"
SEPARATORS = set("&|;\n()")


def live_name(name: str) -> bool:
    """Whether `name` is a column directory the eval runner writes."""
    if name in CONFIGS:
        return True
    return any(name == f"{c}-{p}" for c in CONFIGS for p in PROVIDERS)


def segments(command: str) -> list[list[str]]:
    text = command.split("<<", 1)[0]
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars="();|&\n")
        lex.whitespace = " \t\r"
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        tokens = text.replace("&&", " ; ").split()
    out: list[list[str]] = []
    current: list[str] = []
    for tok in tokens:
        if tok and set(tok) <= SEPARATORS:
            if current:
                out.append(current)
            current = []
        else:
            current.append(tok)
    if current:
        out.append(current)
    return out


def under_results(path: str) -> str | None:
    """The path relative to `evals/results/` without a trailing slash, or None."""
    idx = path.find(RESULTS)
    if idx < 0:
        return None
    rest = path[idx + len(RESULTS) :].strip("/")
    return "/".join(p for p in rest.split("/") if p and p != ".")


def depth(rel: str) -> int:
    return len(rel.split("/")) if rel else 0


def resolve(base: Path, target: str) -> Path:
    expanded = os.path.expanduser(target)
    return Path(expanded) if os.path.isabs(expanded) else base / expanded


class Layout:
    """What the command does to `evals/results/`, tracked by relative path.

    `cells_below` maps a relative path to how many levels its cells sit below
    it: 2 for a config, 1 for a scenario, 0 for a cell. `created` holds the
    directories `mkdir` made in this command.
    """

    def __init__(self, cwd: Path) -> None:
        self.cwd = cwd
        self.cells_below: dict[str, int] = {}
        self.created: set[str] = set()

    def is_dir(self, raw: str, rel: str) -> bool:
        if rel in self.created:
            return True
        return resolve(self.cwd, raw.rstrip("/") or "/").is_dir()

    def cells_of(self, rel: str) -> int | None:
        if rel in self.cells_below:
            return self.cells_below[rel]
        d = depth(rel)
        return 3 - d if 1 <= d <= 3 else None

    def mkdir(self, args: list[str]) -> None:
        for raw in args:
            if raw.startswith("-"):
                continue
            rel = under_results(raw)
            if rel is not None:
                self.created.add(rel)

    def move(self, args: list[str], *, copy: bool) -> None:
        paths = [a for a in args if not a.startswith("-")]
        if len(paths) < 2:
            return
        raw_dest = paths[-1]
        dest = under_results(raw_dest)
        for raw_src in paths[:-1]:
            src = under_results(raw_src)
            if src is None:
                continue
            cells = self.cells_of(src)
            if not copy:
                self.cells_below.pop(src, None)
            if dest is None or cells is None:
                continue
            into = self.is_dir(raw_dest, dest)
            final = f"{dest}/{Path(src).name}".strip("/") if into else dest
            self.cells_below[final] = cells
            if not copy:
                self.created.discard(src)

    def offenders(self) -> list[str]:
        out = []
        for rel, cells in self.cells_below.items():
            if depth(rel) + cells == 3 and not live_name(rel.split("/")[0]):
                out.append(rel)
        return out


def check(command: str, cwd: Path) -> str | None:
    if RESULTS not in command:
        return None
    layout = Layout(cwd)
    for seg in segments(command):
        head = seg[0]
        if head == "cd":
            layout.cwd = resolve(layout.cwd, seg[1]) if len(seg) > 1 else Path.home()
        elif head == "mkdir":
            layout.mkdir(seg[1:])
        elif head in ("mv", "cp"):
            layout.move(seg[1:], copy=head == "cp")
    offenders = layout.offenders()
    if not offenders:
        return None
    where = ", ".join(f"evals/results/{rel}" for rel in offenders)
    return (
        f"blocked: {where} would leave cells at three levels under evals/results/, where the "
        "report adds them to the live column whose config field they carry and that column's n "
        "doubles. Park a column four levels deep: mkdir -p evals/results/<park> && "
        "mv evals/results/<config> evals/results/<park>/<config> (AGENTS.md, Harness)."
    )


def run() -> int:
    payload = json.load(sys.stdin)
    if payload.get("tool_name") not in ("Bash", "bash"):
        return 0
    command = payload["tool_input"]["command"]
    if not isinstance(command, str):
        return 0
    reason = check(command, Path(str(payload.get("cwd") or ".")))
    if reason:
        print(reason, file=sys.stderr)
        return 2
    return 0


def main() -> int:
    try:
        return run()
    except Exception:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
