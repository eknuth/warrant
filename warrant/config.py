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
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from warrant.models import Chain

MODE_ENV = "WARRANT_MODE"

# Where the ledger and the decision log write. `runs/` is gitignored.
RUNS_DIR = Path("runs")

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
