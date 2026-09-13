"""PreToolUse hook on bash: keep keys and the secrets file out of git.

Runs through the harness's command-hook bridge, which puts the tool name in
`tool_name` and the tool arguments in `tool_input`, so this hook sees the tool
named `bash` with a `command` field.

What it enforces: secrets come only from `.env` and never reach a commit
(AGENTS.md, Rules). Blocks, with exit 2 and a reason on stderr:

- `git add` or `git commit` naming `.env` or `.env.*` as a path, except
  `.env.example`.
- `git commit` when the staged diff (plus the working tree for `-a`) adds a
  line matching a key pattern, or an `API_KEY=`-style assignment with a value
  that is not verbatim in `.env.example`.

Placeholders in angle brackets or starting with `$` pass. The stderr names the
file and the pattern, never the value.

The diff is read where the commit will run: the hook walks the command's
segments in order, follows `cd <path>`, and honors `git -C <path>`, starting
from the payload's `cwd`. `.env.example` is read from that repository's top
level. Text after a heredoc marker (`<<`) is a document, not shell, and is not
read. Everything else passes through: exit 0, no output. Any unexpected error
also exits 0, because a hook that fails closed would block every bash call.
Standard library only, no network.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

# A match means "this line carries a credential", so the shapes here are the
# specific, long ones real keys have. A short plausible token in a test fixture
# or a doc is not a finding; a real key is long enough to match.
KEY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("a key with a prefix reserved for keys", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("an ingest key", re.compile(r"\bhcaik_[A-Za-z0-9]{20,}")),
    ("a management key", re.compile(r"\bhcamk_[A-Za-z0-9]{20,}")),
    ("an AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("a Linear API key", re.compile(r"\blin_api_[A-Za-z0-9]{20,}")),
]
ENV_ASSIGNMENT = re.compile(
    r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD))\s*=\s*(\S*)"
)
FORBIDDEN_NAMES = {".env", ".credentials.yaml"}
SEPARATORS = set("&|;\n()")


def shell_part(command: str) -> str:
    """The command text before the first heredoc marker."""
    return command.split("<<", 1)[0]


def segments(command: str) -> list[list[str]]:
    text = shell_part(command)
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


def effective_dir(command: str, cwd: Path) -> Path:
    """Where `git` will actually run for this command.

    The payload's `cwd` is the session workspace, which is not always where the
    command acts: `git -C <path> commit` and `cd <path> && git commit` both
    commit somewhere else. Following them here is what keeps the hook reading
    the repository the commit lands in rather than the one it was launched
    from.
    """
    directory = cwd
    for seg in segments(command):
        if seg[0] == "cd" and len(seg) > 1:
            directory = resolve(directory, seg[1])
            continue
        if seg[0] == "git":
            _, _, dash_c = git_call(seg)
            if dash_c:
                directory = resolve(directory, dash_c)
    return directory


def git_call(tokens: list[str]) -> tuple[str | None, list[str], str | None]:
    """(subcommand, its arguments, the `-C` directory) for a git segment, else (None, [], None)."""
    if not tokens or tokens[0] != "git":
        return None, [], None
    rest = tokens[1:]
    directory = None
    while rest and rest[0].startswith("-"):
        if rest[0] == "-C" and len(rest) > 1:
            directory = rest[1]
            rest = rest[2:]
        elif rest[0] == "-c":
            rest = rest[2:]
        else:
            rest = rest[1:]
    return (rest[0], rest[1:], directory) if rest else (None, [], directory)


def resolve(base: Path, target: str) -> Path:
    expanded = os.path.expanduser(target)
    return (base / expanded).resolve() if not os.path.isabs(expanded) else Path(expanded)


def forbidden_name(arg: str) -> str | None:
    """The arg if it names a secrets file, else None. `.env.example` is allowed."""
    name = Path(arg.rstrip("/")).name
    if name in FORBIDDEN_NAMES or (name.startswith(".env.") and name != ".env.example"):
        return arg
    return None


def names_forbidden_path(args: list[str]) -> str | None:
    for arg in args:
        hit = forbidden_name(arg)
        if hit:
            return arg
    return None


def project_root(directory: Path) -> Path:
    """The git top level of `directory`, else the bridge's project dir, else `directory`."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return Path(proc.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        pass
    for var in ("WARRANT_PROJECT_DIR", "DSH_PROJECT_DIR"):
        fallback = os.environ.get(var)
        if fallback:
            return Path(fallback)
    return directory


def is_placeholder(value: str) -> bool:
    """Whether `value` is written as a placeholder rather than a secret.

    A bracketed or shell-substituted value is a promise to fill it in later.
    Anything else is either the real thing or too close to it to wave through.
    """
    value = value.strip().strip("'\"")
    bracketed = value.startswith("<") and value.endswith(">")
    return bool(value) and (bracketed or value.startswith("$") or value.startswith("{{"))


def placeholder_lines(project: Path) -> set[str]:
    """The lines of `.env.example` whose values are placeholders.

    This file is committed, so it is not a trust anchor. An allowlist taken from
    it wholesale lets anyone add a real credential there and then commit that
    same line anywhere, which is a guard bypassed by editing the file it guards.
    Only bracket-shaped values are admitted, so a real value added to
    `.env.example` is a finding wherever it appears, including in that file.
    """
    path = project / ".env.example"
    if not path.is_file():
        return set()
    allowed = set()
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        match = ENV_ASSIGNMENT.match(stripped)
        if match and is_placeholder(match.group(2)):
            allowed.add(stripped)
    return allowed


def _git_diff(cwd: Path, *args: str) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["git", "diff", *args, "--no-color", "--unified=0"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def staged_diff(cwd: Path, *, include_working_tree: bool) -> str:
    proc = _git_diff(cwd, "HEAD") if include_working_tree else _git_diff(cwd, "--cached")
    if proc is not None and proc.returncode != 0:
        # No HEAD yet (first commit): the cached diff is against the empty tree.
        proc = _git_diff(cwd, "--cached")
    return proc.stdout if proc is not None and proc.returncode == 0 else ""


def scan_diff(diff: str, allowed: set[str]) -> list[str]:
    """Findings as `file: pattern` strings for every added line that looks like a key."""
    findings = []
    current = "?"
    for line in diff.splitlines():
        if line.startswith("+++ "):
            current = line[4:].removeprefix("b/")
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        added = line[1:]
        if forbidden_name(current):
            findings.append(f"{current}: the secrets file itself")
            continue
        for label, pattern in KEY_PATTERNS:
            if pattern.search(added):
                findings.append(f"{current}: {label}")
        m = ENV_ASSIGNMENT.match(added)
        if m and m.group(2) and not is_placeholder(m.group(2)):
            if added.strip() not in allowed:
                findings.append(f"{current}: {m.group(1)}= with a value that is not a placeholder")
    return findings


def check(command: str, cwd: Path) -> str | None:
    """The reason to block, or None."""
    for seg in segments(command):
        sub, args, _ = git_call(seg)
        if sub not in ("add", "commit"):
            continue
        hit = names_forbidden_path(args)
        if hit:
            return f"git {sub} names {hit}: the secrets file stays out of git (AGENTS.md, Rules)."
        if sub == "commit":
            # The diff is read where the commit will run, not where the shell
            # was launched: `git -C <path> commit` commits somewhere else.
            where = effective_dir(command, cwd)
            all_tracked = any(
                a in ("-a", "--all")
                or (a.startswith("-") and not a.startswith("--") and "a" in a[1:])
                for a in args
            )
            diff = staged_diff(where, include_working_tree=all_tracked)
            findings = scan_diff(diff, placeholder_lines(project_root(where)))
            if findings:
                listed = "; ".join(sorted(set(findings)))
                return (
                    "commit blocked: an added line looks like a key or names the secrets file "
                    f"({listed}). Secrets come only from .env (AGENTS.md, Rules). Remove the line, "
                    "or if it is a placeholder, write it in angle brackets."
                )
    return None


def run() -> int:
    payload = json.load(sys.stdin)
    if payload.get("tool_name") not in ("Bash", "bash"):
        return 0
    command = payload["tool_input"]["command"]
    if not isinstance(command, str) or "git" not in command:
        return 0
    cwd = Path(str(payload.get("cwd") or "."))
    reason = check(command, cwd)
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
