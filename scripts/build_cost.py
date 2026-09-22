"""Sum the harness records under `runs/dsh/` into one table.

    uv run python scripts/build_cost.py
    uv run python scripts/build_cost.py --write docs/build-cost.md

Each session the coding harness ran writes `runs/dsh/<session>.json` with a
`usage` block. The build cost is the sum of those records, and this script is
the one producer of that number: `docs/build-cost.md` is its output, and
`scripts/check_readme_numbers.py` reads that file, so a figure in the README
cannot drift from the records.

One session id names one run. A session that failed and was retried leaves a
sibling named `<session>.failed-<stamp>.json`; counting both would double the
session, so the successful record wins and the sibling is dropped from the
table and listed underneath. A record whose `exit_code` is not 0 is preferred
last for the same id.

W1 through W12 ran through the web interface of an earlier setup and wrote no
record here, so the total is a floor rather than the full cost of the build.
The generated file says so.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECORDS_DIR = ROOT / "runs" / "dsh"


@dataclass(frozen=True)
class Record:
    """One harness session, reduced to the fields the table prints."""

    session: str
    source: str
    effort: str
    exit_code: int
    failed_sibling: bool
    wall_s: float
    input_tokens: int
    output_tokens: int
    cache_tokens: int
    total_tokens: int

    @property
    def sort_key(self) -> tuple[int, int, float]:
        """The record to keep for one session id: live beats failed beats short."""
        return (0 if self.failed_sibling else 1, 1 if self.exit_code == 0 else 0, self.wall_s)


def load_records(directory: Path = RECORDS_DIR) -> tuple[list[Record], list[str]]:
    """Every session's chosen record, oldest first, plus the dropped siblings."""
    chosen: dict[str, Record] = {}
    for path in sorted(directory.glob("*.json")):
        raw = json.loads(path.read_text())
        usage = raw.get("usage") or {}
        record = Record(
            session=str(raw.get("session_id") or path.stem),
            source=path.name,
            effort=str(raw.get("effort") or ""),
            exit_code=int(raw.get("exit_code") or 0),
            failed_sibling=".failed-" in path.name,
            wall_s=float(raw.get("wall_s") or 0.0),
            input_tokens=int(usage.get("inputTokens") or 0),
            output_tokens=int(usage.get("outputTokens") or 0),
            cache_tokens=int(usage.get("cacheReadTokens") or 0),
            total_tokens=int(usage.get("totalTokens") or 0),
        )
        current = chosen.get(record.session)
        if current is None or record.sort_key > current.sort_key:
            chosen[record.session] = record
    kept = sorted(chosen.values(), key=lambda r: (-r.wall_s, r.session))
    dropped = [
        path.name
        for path in sorted(directory.glob("*.json"))
        if path.name not in {record.source for record in kept}
    ]
    return kept, dropped


def totals(records: list[Record]) -> Record:
    """The sum row. `session`, `source`, `effort`, and the flags are not summed."""
    return Record(
        session=f"{len(records)} sessions",
        source="",
        effort="",
        exit_code=0,
        failed_sibling=False,
        wall_s=sum(record.wall_s for record in records),
        input_tokens=sum(record.input_tokens for record in records),
        output_tokens=sum(record.output_tokens for record in records),
        cache_tokens=sum(record.cache_tokens for record in records),
        total_tokens=sum(record.total_tokens for record in records),
    )


def render(records: list[Record], dropped: list[str]) -> str:
    total = totals(records)
    lines = [
        "# Build cost",
        "",
        "The harness records under `runs/dsh/`, summed by `scripts/build_cost.py`.",
        "This file is generated: run `make build-cost` after a session lands and commit",
        "the result. One row per session id. A session that failed and was retried has",
        "a sibling named `*.failed-*.json`, and the sibling is dropped so one session is",
        "counted once.",
        "",
        "| session | effort | exit | wall s | input | output | cache reads | total |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for record in records:
        lines.append(
            f"| `{record.session}` | {record.effort} | {record.exit_code} | "
            f"{record.wall_s:,.0f} | {record.input_tokens:,} | {record.output_tokens:,} | "
            f"{record.cache_tokens:,} | {record.total_tokens:,} |"
        )
    lines.append(
        f"| **{total.session}** | | | **{total.wall_s:,.0f}** | "
        f"**{total.input_tokens:,}** | **{total.output_tokens:,}** | "
        f"**{total.cache_tokens:,}** | **{total.total_tokens:,}** |"
    )
    hours = total.wall_s / 3600
    lines += [
        "",
        f"Totals: **{total.total_tokens:,} tokens** ({total.input_tokens:,} input, "
        f"{total.output_tokens:,} output, {total.cache_tokens:,} cache reads) over "
        f"**{hours:.1f} hours** of recorded wall time.",
        "",
        "W1 through W12 ran through the web interface and wrote no record under",
        "`runs/dsh/`, so this is a floor rather than the full cost of the build.",
    ]
    if dropped:
        lines += [
            "",
            "Dropped as a retry of a session already in the table: "
            + ", ".join(f"`{name}`" for name in dropped)
            + ".",
        ]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--write",
        metavar="PATH",
        help="write the table to PATH instead of printing it",
    )
    parser.add_argument(
        "--records",
        metavar="DIR",
        default=str(RECORDS_DIR),
        help="the directory of harness records (default: runs/dsh)",
    )
    args = parser.parse_args(argv)
    directory = Path(args.records)
    if not directory.is_dir():
        print(f"no records directory: {directory}", file=sys.stderr)
        return 1
    records, dropped = load_records(directory)
    if not records:
        print(f"no records in {directory}", file=sys.stderr)
        return 1
    text = render(records, dropped)
    if args.write:
        Path(args.write).write_text(text)
        print(f"wrote {args.write}: {len(records)} sessions")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
