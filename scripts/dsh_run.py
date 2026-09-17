"""Run one Warrant issue through the DeepSeek Harness Python SDK, headlessly.

Thin wrapper, no agent logic of its own. It starts one SDK runtime on the
`warrant-sdk` profile, sends one prompt, prints the final answer, and records
what the run cost to `runs/dsh/<session>.json` so a README can report the build
cost without anyone retyping a number.

A session id names one run. The runtime refuses a prompt for an id that already
exists, so the runner does not continue a conversation by reusing one; a failed
run is recorded beside an existing record rather than over it.

    uv run python scripts/dsh_run.py --effort max --session w5 "Implement EDW-1420"

On effort: there is one DeepSeek cloud model, so the effort levels are
`off`, `low`, `high`, `max`. The Linear label on the issue is the level to pass
here.

On the profile: `warrant-sdk` is the project's SDK composition. The web profile
bundles the browser surface and cannot also serve the SDK's stdio JSON-RPC
protocol, so the SDK path gets its own profile built from the same sources in
`infra/dsh/`. `make dsh-profile` installs it.

On the runtime binary: `dsh_bin` defaults to the `dsh` on PATH, which reuses the
installed harness instead of unpacking the SDK wheel's bundled runtime. Pass
`--dsh-bin` to select another one; omit it only if `dsh` is not installed.

Usage is read from the run's own events. The SDK's `RunResult` carries no usage
field, so the wrapper folds the session events and records the token counts the
provider reported. When a run reports none, the record says so in
`usage_source` rather than writing zeros that read like a measurement.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# `[tool.uv] package = false` keeps the project out of the venv, and running a
# file puts its own directory on `sys.path` rather than the repository root. Add
# the root here so `uv run python scripts/dsh_run.py ...` can import `warrant`
# from any cwd with no `PYTHONPATH` from the caller.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from warrant.config import RUNS_DIR as RUNS_ROOT
from warrant.config import commit_is_dirty, commit_sha

DEFAULT_PROVIDER = "deepseek-official"
DEFAULT_MODEL = "deepseek-flash"
DEFAULT_PROFILE = "warrant-sdk"
EFFORTS = ("off", "low", "high", "max")

REPO_ROOT = Path(__file__).resolve().parents[1]
# The shared run directory, not this checkout's: a harness run started from a
# worktree records its cost beside every other run.
RUNS_DIR = RUNS_ROOT / "dsh"

USAGE_KEYS = (
    "inputTokens",
    "outputTokens",
    "cacheReadTokens",
    "cacheWriteTokens",
    "uncachedInputTokens",
    "totalTokens",
    "reasoningTokens",
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="dsh_run.py",
        description="Run one prompt through the DeepSeek Harness SDK and record what it cost.",
    )
    parser.add_argument("prompt", nargs="*", help="the prompt; reads stdin when omitted")
    parser.add_argument(
        "--effort",
        choices=EFFORTS,
        default="high",
        help="reasoning effort for the run (default: high, the project default)",
    )
    parser.add_argument(
        "--session",
        default=None,
        help="session id; must be new and one path component, the runtime rejects a reused one",
    )
    parser.add_argument("--profile", default=DEFAULT_PROFILE, help="dsh profile to run")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="model id")
    parser.add_argument("--provider", default=DEFAULT_PROVIDER, help="provider route")
    parser.add_argument("--max-tokens", type=int, default=None, help="per-request output cap")
    parser.add_argument(
        "--dsh-home",
        default=os.environ.get("DSH_HOME") or str(Path.home() / ".dsh"),
        help="harness home (default: $DSH_HOME or ~/.dsh)",
    )
    parser.add_argument(
        "--dsh-bin",
        default=shutil.which("dsh"),
        help="the dsh executable (default: the one on PATH)",
    )
    parser.add_argument(
        "--cwd", default=str(REPO_ROOT), help="agent workspace (default: the repo root)"
    )
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=None,
        help="bound each turn; unbounded by default",
    )
    args = parser.parse_args(argv)
    if args.session is not None:
        try:
            record_stem(args.session)
        except ValueError as exc:
            parser.error(str(exc))
    if not args.prompt:
        text = sys.stdin.read().strip()
        if not text:
            parser.error("no prompt: pass one as an argument or on stdin")
        args.prompt = [text]
    return args


def read_prompt(args: argparse.Namespace) -> str:
    return " ".join(args.prompt)


def usage_from_events(events: list[dict[str, Any]]) -> tuple[dict[str, int], str]:
    """Fold the run's events for the token counts the provider reported.

    Walks every event's `data` for a mapping carrying one of the known usage
    keys, and sums each key over all of them. Returns the totals plus a short
    label saying where they came from, so an empty result is visible as an
    empty result rather than as zero tokens.
    """
    totals: dict[str, int] = {}
    sources: set[str] = set()
    for event in events:
        data = event.get("data")
        if not isinstance(data, dict):
            continue
        for candidate in (data, data.get("usage"), data.get("message"), data.get("response")):
            if not isinstance(candidate, dict):
                continue
            found = {k: v for k, v in candidate.items() if k in USAGE_KEYS and isinstance(v, int)}
            if found:
                for key, value in found.items():
                    totals[key] = totals.get(key, 0) + value
                sources.add(str(event.get("type") or "unknown"))
    if not totals:
        return {}, "unavailable"
    return totals, f"events:{','.join(sorted(sources))}"


def write_record(path: Path, record: dict[str, Any]) -> None:
    """Write the run record atomically, so a reader never sees half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def record_stem(session_id: str) -> str:
    """The record's file stem for one session id.

    A session id names one file under the runs directory, so an id that is not a
    single path component is refused. `--session ../../x` would otherwise make
    the record path climb out of that directory, and the record is written for a
    failed run too, so a runtime that rejects the id does not make the write
    unreachable.
    """
    if not session_id or session_id in (".", "..") or Path(session_id).name != session_id:
        raise ValueError(f"session id {session_id!r} must be one path component")
    return session_id


def record_target(session_id: str, *, failed: bool) -> Path:
    """Where one run's record goes.

    The canonical name is `<session>.json`. A failed run whose id already has a
    record goes to a sibling `<session>.failed-<stamp>.json` instead, so a
    failure cannot erase an earlier run's cost. A successful run keeps the
    canonical name.
    """
    stem = record_stem(session_id)
    base = RUNS_DIR / f"{stem}.json"
    if not failed or not base.exists():
        return base
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
    return RUNS_DIR / f"{stem}.failed-{stamp}.json"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    prompt = read_prompt(args)

    try:
        from deepseek_harness import DeepSeekHarness, SdkProtocolError
    except ImportError:
        print(
            "dsh_run.py needs the Python SDK: uv run --with deepseek-harness-sdk "
            "python scripts/dsh_run.py ...",
            file=sys.stderr,
        )
        return 2

    if args.dsh_bin is None:
        print(
            "no dsh on PATH and no --dsh-bin: install the harness (npm i -g "
            "@deepseek-ai/dsh) or let the SDK use its bundled runtime by omitting "
            "--dsh-bin",
            file=sys.stderr,
        )
        return 2

    if not Path(args.dsh_home).is_dir():
        print(
            f"no harness home at {args.dsh_home}: boot dsh once before running this",
            file=sys.stderr,
        )
        return 2

    session_id = args.session or f"dsh-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
    started = time.monotonic()
    started_at = datetime.now(UTC).isoformat()
    exit_code = 0
    final_response = ""
    finish_reason: str | None = None
    usage: dict[str, int] = {}
    usage_source = "unavailable"
    error: str | None = None

    try:
        with DeepSeekHarness(
            dsh_home=args.dsh_home,
            dsh_bin=args.dsh_bin,
            cwd=args.cwd,
            profile=args.profile,
            provider=args.provider,
            model=args.model,
            reasoning_effort=args.effort,
            max_tokens=args.max_tokens,
            request_timeout_seconds=args.timeout_s,
        ) as harness:
            result = harness.run(prompt, session_id=session_id)
        final_response = result.final_response
        finish_reason = result.finish_reason
        usage, usage_source = usage_from_events(result.events)
        if finish_reason not in (None, "completed"):
            exit_code = 1
    except Exception as exc:  # the record is the point: write it even on a failure
        error = f"{type(exc).__name__}: {exc}"
        exit_code = 1
        if isinstance(exc, SdkProtocolError):
            error = f"protocol error: {exc}"

    wall_s = round(time.monotonic() - started, 2)
    record: dict[str, Any] = {
        "session_id": session_id,
        # The commit, so a cost is the cost of some code rather than of "the
        # project". A dirty tree is a different program at the same sha.
        "commit": commit_sha(),
        "dirty": commit_is_dirty(),
        "effort": args.effort,
        "provider": args.provider,
        "model": args.model,
        "profile": args.profile,
        "cwd": args.cwd,
        "dsh_home": args.dsh_home,
        "prompt": prompt,
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat(),
        "wall_s": wall_s,
        "finish_reason": finish_reason,
        "exit_code": exit_code,
        "final_response": final_response,
        "usage": usage,
        "usage_source": usage_source,
    }
    if error:
        record["error"] = error

    record_path = record_target(session_id, failed=exit_code != 0)
    write_record(record_path, record)

    if final_response:
        print(final_response)
    if error:
        print(f"dsh_run: {session_id} failed: {error}", file=sys.stderr)
    print(
        f"dsh_run: session={session_id} effort={args.effort} wall_s={wall_s} record={record_path}"
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
