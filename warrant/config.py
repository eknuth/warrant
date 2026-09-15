"""Warrant's ablation modes and the run directory layout.

`WARRANT_MODE` is read once per process, at import, into `DEFAULT_MODE`. The
engine and the ledger accept an explicit `mode` too, so a test can exercise a
mode without touching the environment. W15 explains the modes to a reader.

The four modes:

* `full` is the real configuration: the chain comes from the verified token
  exchange and the ledger records what was read.
* `no-provenance` drops the ledger. `Ledger.get` returns an empty provenance
  set, which is the baseline for "checks that depend on what the agent read".
* `no-exchange` builds the chain from `X-Warrant-*` headers the agent sends
  instead of from a token. This is deliberately the dishonest baseline: a
  hijacked agent vouches for itself. The verified path needs the token exchange
  that W2 owns, so in every other mode `chain_from_headers` refuses rather than
  pretend.
* `prompt-only` makes every decision allow and records that it did, with
  `policy_ids == ["ablation:prompt-only"]`. It is the floor, not a policy set.

`task_dir` is the one place a task id becomes a path. It sanitizes, so a task
id cannot escape the run directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from warrant.models import Chain

MODE_ENV = "WARRANT_MODE"
RUNS_DIR_ENV = "WARRANT_RUNS_DIR"
COMMIT_ENV = "WARRANT_COMMIT"
DIRTY_ENV = "WARRANT_DIRTY"

# The checkout this file is part of. `warrant/config.py` is one level down, so
# the parent of its parent is the root of whichever checkout is running.
REPO_ROOT = Path(__file__).resolve().parents[1]


def main_checkout(root: Path = REPO_ROOT) -> Path:
    """The checkout that owns the git directory, worktree or not.

    In a worktree, `<root>/.git` is a file holding `gitdir: <main>/.git/worktrees/<name>`,
    so the main checkout is two levels up from there. Reading that pointer is
    what makes the runs directory the same from every worktree, and it costs no
    subprocess. Without it the default would be the worktree's own parent, which
    is a directory of worktrees rather than the checkout.
    """
    pointer = root / ".git"
    if pointer.is_dir():
        return root
    if pointer.is_file():
        text = pointer.read_text(encoding="utf-8").strip()
        if text.startswith("gitdir:"):
            gitdir = Path(text.split(":", 1)[1].strip())
            if not gitdir.is_absolute():
                gitdir = (root / gitdir).resolve()
            # <main>/.git/worktrees/<name>
            if gitdir.parent.name == "worktrees":
                return gitdir.parent.parent.parent
    return root


def default_runs_dir() -> Path:
    """Where the ledger and the decision log write, as an absolute path.

    An absolute default is the point. A relative `runs` resolves against the
    process's working directory, so a run started from a worktree wrote its
    decisions and its ledger into that worktree, and two runs of the same task
    from two checkouts landed in two different places. One directory that every
    checkout shares is what lets a run be compared with a run.

    The environment variable wins, so an eval run can be pointed at a column
    directory. Otherwise the main checkout's `runs/`, which is gitignored.
    """
    override = os.environ.get(RUNS_DIR_ENV)
    if override:
        return Path(override).expanduser()
    return main_checkout() / "runs"


# Read once, at import, the way the mode is.
RUNS_DIR = default_runs_dir()

PROMPT_ONLY_POLICY_ID = "ablation:prompt-only"

# In `no-exchange` the agent names itself with these headers. Nothing verifies
# them, which is the point of the ablation.
HEADER_SUB = "X-Warrant-Sub"
HEADER_ACT = "X-Warrant-Act"
HEADER_TASK_ID = "X-Warrant-Task-Id"
HEADER_SCOPES = "X-Warrant-Scopes"
HEADER_GROUPS = "X-Warrant-Groups"
HEADER_TOKEN_EXP = "X-Warrant-Token-Exp"

REQUIRED_HEADERS = (HEADER_SUB, HEADER_ACT, HEADER_TASK_ID, HEADER_TOKEN_EXP)

_SAFE_TASK_ID = re.compile(r"[^A-Za-z0-9._-]")


class Mode(StrEnum):
    """The four ablations, named as `WARRANT_MODE` names them."""

    full = "full"
    no_provenance = "no-provenance"
    no_exchange = "no-exchange"
    prompt_only = "prompt-only"


class ChainSourceError(RuntimeError):
    """Raised when a chain cannot be built under the current mode."""


def parse_mode(value: str | None) -> Mode:
    """Turn `WARRANT_MODE` into a `Mode`, defaulting to `full`.

    An unrecognized value is an error, not a silent fallback: a typo that
    quietly disabled provenance would be worse than a failed start.
    """
    if value is None or value == "":
        return Mode.full
    try:
        return Mode(value)
    except ValueError as exc:
        allowed = ", ".join(mode.value for mode in Mode)
        raise ValueError(f"{MODE_ENV}={value!r} is not one of: {allowed}") from exc


# Read once, at import. This is the process's mode unless a caller passes one.
DEFAULT_MODE: Mode = parse_mode(os.environ.get(MODE_ENV))


def current_mode() -> Mode:
    """The mode this process started with."""
    return DEFAULT_MODE


def _commit_from_env() -> str | None:
    """The commit a caller passed in, for a checkout without git.

    The container image has no git and no `.git`, so `commit_sha` there could
    only ever answer None and every run record from compose carried no commit.
    `WARRANT_COMMIT` carries the value the caller exported from the checkout.
    """
    value = os.environ.get(COMMIT_ENV, "").strip()
    return value or None


def _dirty_from_env() -> bool | None:
    """Whether the tree was dirty, from `WARRANT_DIRTY`, or None when unset.

    The same fallback as `_commit_from_env`. An unrecognized value is None,
    which means "not checked" rather than False.
    """
    value = os.environ.get(DIRTY_ENV, "").strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    return None


def commit_sha(root: Path | None = None) -> str | None:
    """The commit the running checkout is at, or None when there is no answer.

    A run has to say which code produced it. That is the difference between two
    columns in the eval table and two runs of the same column, and it is the
    first question a surprising number raises. Returns None rather than raising
    when git is absent or the directory is not a repository: metadata the run
    cannot have is not a reason to fail the run.

    When git cannot answer, `WARRANT_COMMIT` is the fallback. The container the
    smoke runs in has no git, so the value the caller exported from the
    checkout is what the run record carries there.
    """
    where = root if root is not None else REPO_ROOT
    try:
        proc = subprocess.run(
            ["git", "-C", str(where), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _commit_from_env()
    if proc.returncode != 0 or not proc.stdout.strip():
        return _commit_from_env()
    return proc.stdout.strip()


def commit_is_dirty(root: Path | None = None) -> bool | None:
    """Whether the checkout has uncommitted changes, or None when unchecked.

    The sha alone is not the provenance of a run: the same sha with a dirty tree
    is a different program. None means the question could not be asked, which is
    not the same answer as False.

    When git cannot answer, `WARRANT_DIRTY` is the fallback, with the same
    meaning as `commit_sha`'s.
    """
    where = root if root is not None else REPO_ROOT
    try:
        proc = subprocess.run(
            ["git", "-C", str(where), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _dirty_from_env()
    if proc.returncode != 0:
        return _dirty_from_env()
    return bool(proc.stdout.strip())


def write_run_metadata(directory: Path | str, **extra: Any) -> Path:
    """Write `metadata.json` into one run directory and return its path.

    The keys are the ones every run has: the commit, whether the tree was dirty,
    the mode, and the time the run started. `extra` carries what only some runs
    know (`tool`, `model`, `session`), and wins over the defaults.
    """
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    metadata: dict[str, Any] = {
        "commit": commit_sha(),
        "dirty": commit_is_dirty(),
        "mode": current_mode().value,
        "started_at": datetime.now(UTC).isoformat(),
    }
    metadata.update(extra)
    target = path / "metadata.json"
    target.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def bad_task_id(task_id: str) -> bool:
    """Whether a task id cannot name a run directory.

    The same rule `task_dir` enforces, exposed so the gateway can answer a bad
    id with a tool error instead of letting the decision log raise out of the
    request when it turns the id into a path.
    """
    safe = _SAFE_TASK_ID.sub("_", task_id)
    return not safe or set(safe) <= {"."}


def task_dir(root: Path | str, task_id: str) -> Path:
    """The run directory for one task, with the task id made safe for a path.

    Every character outside `[A-Za-z0-9._-]` becomes `_`, and a name that is
    only dots is rejected, so a crafted task id cannot walk out of `root`.

    When the sanitizer changes the id, a short digest of the original is
    appended. Without it `a_b`, `a/b`, and `a b` all name `runs/a_b`, and two
    tasks share one provenance ledger and one decision log: a task could inherit
    another task's provenance set, which is the one input this design says an
    agent cannot forge. `no-exchange` takes the task id from a header the agent
    sends, so the collision is reachable rather than theoretical. A task id that
    is already safe keeps its readable name.
    """
    safe = _SAFE_TASK_ID.sub("_", task_id)
    if not safe or set(safe) <= {"."}:
        raise ValueError(f"task id {task_id!r} cannot name a run directory")
    if safe != task_id:
        digest = hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:12]
        safe = f"{safe}-{digest}"
    return Path(root) / safe


def _split_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [part for part in re.split(r"[,\s]+", raw.strip()) if part]


def _parse_exp(raw: str) -> datetime:
    """The token expiry as a datetime, or a `ChainSourceError`.

    Every way this can fail is a bad header, so every one of them is the same
    error type. `OverflowError` used to escape for an expiry far in the future,
    which is a header an agent controls in `no-exchange` and not something a
    caller should have to catch separately.
    """
    try:
        seconds = int(raw)
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (ValueError, OverflowError, OSError) as exc:
        raise ChainSourceError(f"{HEADER_TOKEN_EXP} is not a usable unix time: {raw!r}") from exc


def chain_from_headers(headers: Mapping[str, str], *, mode: Mode | None = None) -> Chain:
    """Build a `Chain` from agent-supplied headers.

    This exists for the `no-exchange` ablation only. In `full` (and every other
    mode) the chain has to come from the verified token, which is W2's
    `warrant/oidc.py` and W6's request path; this function raises rather than
    return a chain it cannot vouch for.

    Header lookups are case-insensitive, because HTTP header names are.
    """
    mode = mode if mode is not None else current_mode()
    if mode is not Mode.no_exchange:
        raise ChainSourceError(
            f"the chain from headers is the no-exchange ablation, not {mode.value}; "
            "the verified chain comes from the token exchange"
        )

    lookup = {name.lower(): value for name, value in headers.items()}
    missing = [name for name in REQUIRED_HEADERS if name.lower() not in lookup]
    if missing:
        raise ChainSourceError(f"missing headers: {', '.join(missing)}")

    return Chain(
        sub=lookup[HEADER_SUB.lower()],
        act=lookup[HEADER_ACT.lower()],
        task_id=lookup[HEADER_TASK_ID.lower()],
        scopes=_split_list(lookup.get(HEADER_SCOPES.lower())),
        groups=_split_list(lookup.get(HEADER_GROUPS.lower())),
        token_exp=_parse_exp(lookup[HEADER_TOKEN_EXP.lower()]),
    )
