"""PreToolUse hook on bash: one run at a time.

Runs through the harness's command-hook bridge, which puts the tool name in
`tool_name` and the tool arguments in `tool_input`, so this hook sees the tool
named `bash`.

What it enforces: never start a run while another is running. Two OTLP emits

Blocks, with exit 2 and a reason on stderr, a command that would start a run
while a process whose command line matches the pattern is already running. A
command starts a run when one of its segments, after `nohup`, `time`, `env`, and
`VAR=x` prefixes are stripped, has `uv run python`, `python`, or `python3` at its
head running `scripts/dsh_run.py` or `-m evals.run`, with `-m gen.emit`, or with
`gen/emit.py`; or has `zsh`, `bash`, `sh`, or a bare path at its head whose
script basename is `*pass*.sh` (the one English word that shape catches,
`bypass.sh`, is excluded).

A match counts only when the running process is itself shaped like a run. The
default pattern matches any command line that names the runner, which includes a
shell whose arguments merely mention the filename; that process is ignored now.
`WARRANT_RUN_PATTERN` is taken at face value, so a test can still plant a
harmless marker process and have the hook find it.

A command that only mentions a pass script or a run inside a string or a
filename (`grep`, `cat`, `echo`, `git commit -m`) passes: a pass runs for a
while and the hook must not refuse every command for that long. Text after a
heredoc marker (`<<`) is a document, not shell.

The pattern can be overridden with `WARRANT_RUN_PATTERN` so a test can plant a
harmless marker process. Everything else passes through: exit 0, no output, and
so does any unexpected error. Standard library only, no network.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

DEFAULT_PATTERN = r"dsh_run\.py|evals\.run|gen\.emit"
PASS_SCRIPT = re.compile(r"^(?!bypass\.sh$)(?=.*pass).*\.sh$")
WRAPPERS = {"nohup", "time", "env", "caffeinate", "exec", "sudo"}
SHELLS = {"zsh", "bash", "sh"}
SEPARATORS = set("&|;\n()")


def segments(command: str) -> list[list[str]]:
    text = command.split("<<", 1)[0]
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars="();|&\n")
        lex.whitespace = " \t\r"
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        tokens = text.replace("&&", " ; ").replace("||", " ; ").split()
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


def strip_prefixes(tokens: list[str]) -> list[str]:
    while tokens and (
        tokens[0] in WRAPPERS or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0])
    ):
        tokens = tokens[1:]
    return tokens


PYTHON = re.compile(r"^python[0-9.]*$")


def python_args(tokens: list[str]) -> list[str] | None:
    """The arguments after a `python`, `python3`, or `uv run python[3]` head, else None.

    The head may be a path, which is what a running process shows for an
    interpreter (`/venv/bin/python3.12`). The basename is the name to match.
    """
    if PYTHON.match(Path(tokens[0]).name):
        return tokens[1:]
    if tokens[0] == "uv" and len(tokens) >= 3 and tokens[1] == "run":
        if PYTHON.match(Path(tokens[2]).name):
            return tokens[3:]
    return None


def starts_run(segment: list[str]) -> bool:
    tokens = strip_prefixes(segment)
    if not tokens:
        return False
    args = python_args(tokens)
    if args is not None:
        module = (
            args[args.index("-m") + 1]
            if "-m" in args and args.index("-m") + 1 < len(args)
            else None
        )
        if module == "evals.run":
            # W15's runner. It has no `--emit` flag; the ported Receipts hook
            # required one, so every eval run was invisible to this guard.
            return True
        if module == "gen.emit":
            return True
        if any(a == "gen/emit.py" or a.endswith("/gen/emit.py") for a in args):
            return True
        return any(a == "scripts/dsh_run.py" or a.endswith("/dsh_run.py") for a in args)
    head = tokens[0]
    if head in SHELLS:
        scripts = [a for a in tokens[1:] if not a.startswith("-")]
        return bool(scripts) and bool(PASS_SCRIPT.match(Path(scripts[0]).name))
    if "/" in head or head.endswith(".sh"):
        return bool(PASS_SCRIPT.match(Path(head).name))
    return False


def process_listing(pattern: str) -> list[tuple[str, str]]:
    """(pid, command line) for each process `pgrep -f` matches.

    BSD `pgrep` wants `-fl` for the command line; procps wants `-af`. On BSD
    `-af` means something else (include ancestors) and prints bare pids, so the
    platform picks the flag rather than trying one and parsing what comes back.
    """
    flag = "-fl" if sys.platform == "darwin" else "-af"
    try:
        proc = subprocess.run(["pgrep", flag, pattern], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return []
    listing: list[tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.strip().split(maxsplit=1)
        if parts and parts[0].isdigit():
            listing.append((parts[0], parts[1] if len(parts) > 1 else ""))
    return listing


def running_pids(pattern: str, *, require_runner: bool) -> list[str]:
    """The pids matching `pattern`, minus this process and, when asked, non-runners.

    The default pattern matches any command line that names the runner, which
    includes a shell that merely mentions the filename. When the caller has not
    overridden the pattern, a match only counts if its own command line is
    shaped like a run, so the hook sees an actual runner. An explicit
    `WARRANT_RUN_PATTERN` is taken at face value, because the test that plants a
    marker process relies on that.
    """
    pids: list[str] = []
    for pid, command in process_listing(pattern):
        if int(pid) == os.getpid():
            continue
        if require_runner and not any(starts_run(seg) for seg in segments(command)):
            continue
        pids.append(pid)
    return pids


def check(command: str, override: str | None) -> str | None:
    if not any(starts_run(seg) for seg in segments(command)):
        return None
    pattern = override or DEFAULT_PATTERN
    pids = running_pids(pattern, require_runner=not override)
    if not pids:
        return None
    return (
        f"run blocked: a process matching '{pattern}' is already running (pid "
        f"{', '.join(pids)}). Two runs at once share the provider budget and the results "
        "tree, and neither is trustworthy. Wait for the running one to finish, then start "
        "this one (AGENTS.md, Harness)."
    )


def run() -> int:
    payload = json.load(sys.stdin)
    if payload.get("tool_name") not in ("Bash", "bash"):
        return 0
    command = payload["tool_input"]["command"]
    if not isinstance(command, str):
        return 0
    reason = check(command, os.environ.get("WARRANT_RUN_PATTERN"))
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
