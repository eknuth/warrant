"""PostToolUse hook on bash: after a commit, say so if lint is red.

Runs through the harness's command-hook bridge, which puts the tool name in
`tool_name` and the tool arguments in `tool_input`, so this hook sees the tool
named `bash`.

What it enforces: the rule that `make lint` passes before an issue is called done
(AGENTS.md, Rules), applied at the commit. A block on every commit would make
each commit wait on lint; this warning costs the same second but never stands
between a person and their commit.

After any `git commit` this runs `make lint` at the top level of the git
repository the session's `cwd` is in, so a worktree session lints the checkout it
committed to. When lint fails, the tail of its output goes to stderr with exit 2,
which the bridge feeds back to the model as a warning; the commit already
happened and nothing is undone. When it passes, or the command was not a commit,
or there is no Makefile yet (W0), exit 0 with no output, and so does any
unexpected error. Standard library only, no network.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

IS_COMMIT = re.compile(r"\bgit\b[^\n;|&]*\bcommit\b")


def project_dir(cwd: Path) -> Path | None:
    """The git top level of `cwd`, else `cwd` itself when it is a project.

    A repository with no commits yet has no resolvable `HEAD`, and
    `rev-parse --show-toplevel` still answers for it. When that fails there is
    no repository here, so the only thing left to try is `cwd`: falling back to
    a configured project directory would lint a different checkout than the one
    the commit landed in.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", str(cwd), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return Path(proc.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        pass
    return cwd if (cwd / "Makefile").is_file() else None


def lint_target_exists(project: Path) -> bool:
    """Whether `make` has a `lint` target here.

    `make -p -n lint` prints make's database and runs nothing. Its entry for a
    target that does not exist is annotated "File has not been updated", and the
    same name exists in the database either way, so the annotation is what tells
    the two apart. Without this, `make lint` on a project that has not defined
    the target yet exits non-zero and the hook reports red lint for work that was
    never linted.

    The annotation is not always on its own line: some make builds join the
    target line with the first comment (`lint: #  Phony target ...`), so the
    window starts at the target line and is read as a whole. A fixed short
    window misses the annotation in that layout and reports a project with a
    lint target as having none, so this hook silently stopped checking lint
    rather than failing loudly.
    """
    try:
        proc = subprocess.run(
            ["make", "-p", "-n", "lint"],
            cwd=project,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    lines = proc.stdout.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("lint:"):
            window = " ".join(lines[index : index + 20])
            return "has been updated" in window and "has not been updated" not in window
    return False


def lint(project: Path) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["make", "lint"], cwd=project, capture_output=True, text=True, timeout=60
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"make lint did not run: {exc}"
    output = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, output


def run() -> int:
    payload = json.load(sys.stdin)
    if payload.get("tool_name") not in ("Bash", "bash"):
        return 0
    command = payload["tool_input"]["command"]
    if not isinstance(command, str) or not IS_COMMIT.search(command):
        return 0
    project = project_dir(Path(str(payload.get("cwd") or ".")))
    if project is None or not (project / "Makefile").is_file():
        return 0
    if not lint_target_exists(project):
        return 0
    ok, output = lint(project)
    if ok:
        return 0
    tail = "\n".join(output.splitlines()[-15:])
    print(
        "lint is red after this commit; fix it and amend or commit again before calling "
        f"the issue done (AGENTS.md, Rules).\n{tail}",
        file=sys.stderr,
    )
    return 2


def main() -> int:
    try:
        return run()
    except Exception:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
