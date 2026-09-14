"""PreToolUse hook on bash: only merge a pull request that is green and current.

Runs through the harness's command-hook bridge, which puts the tool name in
`tool_name` and the tool arguments in `tool_input`, so this hook sees the tool
named `bash` with a `command` field.

What it enforces: the merge rule in AGENTS.md. `gh pr merge` is the one action
that lands work on `main`, and it is refused unless all three hold, in this
order:

1. `origin/main` is an ancestor of `HEAD`, so the branch already contains the
   latest `main` and a rebase is not owed.
2. The working tree is clean, so nothing is merged that is only in the tree.
3. `make test` and `make lint` both pass, run at the top level of the
   repository the merge lands in.

Unlike `lint_after_commit.py`, which warns and fails open, this hook blocks:
it stands in front of a deliberate action rather than reporting on one that
already happened. A missing `make` target, a missing `gh`, or any other
condition it cannot verify is a block with the reason on stderr, because a
guard that waves through what it cannot check is not a guard.

The check runs in the repository the merge lands in: the command's segments are
followed in order, `cd <path>` and `git -C <path>` both move it, and the
payload's `cwd` is where it starts. Any unexpected error exits 0, so a bug in
this hook cannot block every bash call; the deliberate refusals are the only
nonzero exits. Standard library only, no network.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

SEPARATORS = set("&|;\n()")
GH_FLAG_WITH_VALUE = {"-R", "--repo", "--hostname"}
# The bridge caps a hook's timeout at 90 seconds, so each command gets less.
GIT_TIMEOUT_S = 10
MAKE_TIMEOUT_S = 75
TAIL_LINES = 12


def segments(command: str) -> list[list[str]]:
    """The command split on shell separators, so each tool call is its own list."""
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


def resolve(base: Path, target: str) -> Path:
    expanded = os.path.expanduser(target)
    return (base / expanded).resolve() if not os.path.isabs(expanded) else Path(expanded)


def is_merge(tokens: list[str]) -> bool:
    """Whether this segment is a `gh pr merge` call.

    Leading `VAR=value` assignments are dropped, and `gh`'s global flags are
    skipped, so `gh -R owner/repo pr merge 9` is the same call as
    `gh pr merge 9`. A `--help` or `-h` argument is not a merge: asking what the
    command does cannot land anything.
    """
    rest = list(tokens)
    while rest and ("=" in rest[0] and not rest[0].startswith("-")):
        rest = rest[1:]
    if not rest or Path(rest[0]).name != "gh":
        return False
    words = rest[1:]
    if any(word in ("-h", "--help") for word in words):
        return False
    positionals = []
    index = 0
    while index < len(words):
        word = words[index]
        if word in GH_FLAG_WITH_VALUE:
            index += 2
            continue
        if word.startswith("-"):
            index += 1
            continue
        positionals.append(word)
        index += 1
    return positionals[:2] == ["pr", "merge"]


def merge_directory(command: str, cwd: Path) -> Path:
    """Where the merge lands: the payload's cwd, moved by `cd` and `git -C`."""
    directory = cwd
    for seg in segments(command):
        if seg[0] == "cd" and len(seg) > 1:
            directory = resolve(directory, seg[1])
            continue
        if seg[0] == "git" and "-C" in seg:
            index = seg.index("-C")
            if len(seg) > index + 1:
                directory = resolve(directory, seg[index + 1])
    return directory


def git(directory: Path, *args: str) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_S,
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def project_dir(directory: Path) -> Path | None:
    proc = git(directory, "rev-parse", "--show-toplevel")
    if proc is None or proc.returncode != 0 or not proc.stdout.strip():
        return None
    return Path(proc.stdout.strip())


def contains_origin_main(project: Path) -> tuple[bool, str]:
    """Whether `origin/main` is an ancestor of HEAD."""
    remote = git(project, "rev-parse", "--verify", "--quiet", "origin/main")
    if remote is None:
        return False, "git could not be run"
    if remote.returncode != 0 or not remote.stdout.strip():
        return False, (
            "there is no `origin/main` here to compare against, so the branch cannot be "
            "shown to be current. `git fetch origin` first."
        )
    ancestor = git(project, "merge-base", "--is-ancestor", "origin/main", "HEAD")
    if ancestor is None:
        return False, "git could not be run"
    if ancestor.returncode != 0:
        return False, (
            "`origin/main` is not an ancestor of HEAD, so this branch is behind or diverged "
            "and a rebase is owed (AGENTS.md, Rules). `git fetch origin && git rebase "
            "origin/main`, then re-run the checks."
        )
    return True, ""


def clean_tree(project: Path) -> tuple[bool, str]:
    """Whether the working tree has nothing uncommitted, staged, or untracked."""
    proc = git(project, "status", "--porcelain")
    if proc is None or proc.returncode != 0:
        return False, "git status did not run, so the tree cannot be shown to be clean"
    dirty = [line for line in proc.stdout.splitlines() if line.strip()]
    if dirty:
        listed = "; ".join(dirty[:5])
        more = "" if len(dirty) <= 5 else f" and {len(dirty) - 5} more"
        return False, (
            f"the working tree is not clean ({listed}{more}). A merge records what is "
            "committed, so uncommitted work is not what lands: commit it or set it aside "
            "before merging."
        )
    return True, ""


def make_target_exists(project: Path, target: str) -> bool:
    """Whether `make` has this target here.

    `make -p -n <target>` prints make's database and runs nothing. A target that
    exists is annotated `File has been updated`; one that does not exist carries
    `File does not exist` and `File has not been updated` instead. The
    annotation is not always on its own line: some make builds join the target
    line with the first comment (`test: #  Phony target ...`), so the window
    starts at the target line and is read as a whole rather than line by line.
    A fixed short window misses the annotation in that layout and reports a
    target that exists as missing, which would refuse every merge on such a
    build.
    """
    try:
        proc = subprocess.run(
            ["make", "-p", "-n", target],
            cwd=project,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    lines = proc.stdout.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith(f"{target}:"):
            continue
        window = " ".join(lines[index : index + 20])
        return "has been updated" in window and "has not been updated" not in window
    return False


def run_make(project: Path, target: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["make", target],
            cwd=project,
            capture_output=True,
            text=True,
            timeout=MAKE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return False, f"`make {target}` did not finish within {MAKE_TIMEOUT_S}s"
    except OSError as error:
        return False, f"`make {target}` could not run: {error}"
    output = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, output


def tail(output: str) -> str:
    return "\n".join(output.splitlines()[-TAIL_LINES:])


def check(command: str, cwd: Path) -> str | None:
    """The reason to block the merge, or None."""
    directory = merge_directory(command, cwd)
    project = project_dir(directory)
    if project is None:
        return (
            f"there is no git repository at {directory}, so the branch behind this merge "
            "cannot be checked."
        )
    ok, reason = contains_origin_main(project)
    if not ok:
        return f"merge blocked: {reason}"
    ok, reason = clean_tree(project)
    if not ok:
        return f"merge blocked: {reason}"
    for target in ("test", "lint"):
        if not make_target_exists(project, target):
            return (
                f"merge blocked: there is no `{target}` target in {project / 'Makefile'}, so "
                f"`make {target}` cannot be shown to pass (AGENTS.md, Rules)."
            )
        ok, output = run_make(project, target)
        if not ok:
            return (
                f"merge blocked: `make {target}` failed, so the branch is not green.\n"
                f"{tail(output)}"
            )
    return None


def run() -> int:
    payload = json.load(sys.stdin)
    if payload.get("tool_name") not in ("Bash", "bash"):
        return 0
    command = payload["tool_input"]["command"]
    if not isinstance(command, str) or "gh" not in command:
        return 0
    if not any(is_merge(seg) for seg in segments(command)):
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
