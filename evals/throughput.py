"""Measure throughput and estimate the full column from the stored cell records.

    uv run python -m evals.throughput --column smoke

The runner writes a `meta.json` into every finished cell with the cell's wall
time, and each finished task writes a `usage.json` with the tokens it spent.
This reads both from one column, groups the cells by model, prints seconds per
cell and output tokens per second, and multiplies the measured seconds per cell
by the number of cells a full column holds. The estimate is a measurement from
the cells that ran, not a default: the mean is over the cells the caller points
it at, so a four-cell smoke of one ablation estimates the whole column at that
ablation's cost, and the printed line names the cells it divided by.

A cell in error holds no `grade.json` but it does hold a `meta.json` and the
`usage.json` of every task that finished before the failure. Its wall time and
its partial token count are part of the column's record and appear here, so a
column that spends its budget failing is measured as that. The seconds per cell
include every attempt the runner made, because the retry is part of the cost.

The rate is output tokens over the whole wall time, seed and gateway switch and
tool calls included, so it is lower than the model's generation rate. The
seconds per cell is the number the estimate needs, and it is the one the runner
measured.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean

from evals.ablations import ABLATION_NAMES
from gen.schema import available_scenarios

RESULTS_DIR = Path(__file__).resolve().parent / "results"
CELL_META_NAME = "meta.json"
USAGE_NAME = "usage.json"
FULL_REPEATS = 3


@dataclass(frozen=True)
class CellRecord:
    """One cell's wall time and token counts, read from its `meta.json`."""

    ablation: str
    model: str
    scenario_id: str
    repeat: int
    status: str
    wall_s: float | None
    input_tokens: int
    output_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True)
class Measurement:
    """What a set of cells measured."""

    cells: int
    measured: int
    token_cells: int
    total_wall_s: float
    mean_wall_s: float
    output_tokens: int
    output_tokens_per_s: float
    full_cells: int
    estimate_s: float


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _token_count(value: object) -> int:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0


def _run_tokens(cell_root: Path) -> tuple[int, int] | None:
    """The input and output tokens the cell's finished tasks recorded, or None.

    One task writes its `usage.json` when its loop returns, so a cell that failed
    on a later task still has the counts of the tasks that finished. The sum is
    the partial cost, which is more than a zero and less than a completed task's.
    """
    totals = [0, 0]
    found = False
    for path in sorted((cell_root / "run").glob("*/" + USAGE_NAME)):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        found = True
        totals[0] += _token_count(data.get("input_tokens"))
        totals[1] += _token_count(data.get("output_tokens"))
    return (totals[0], totals[1]) if found else None


def read_cells(results_dir: Path = RESULTS_DIR) -> list[CellRecord]:
    """Every readable cell record under one column, sorted.

    Both cell depths are read: the four-level
    `<ablation>/<model>/<scenario>/<repeat>/meta.json` and the three-level
    `<ablation>/<scenario>/<repeat>/meta.json` a column written before the model
    level existed carries. Tokens come from the cell's task records when they
    exist, which is what lets an error cell report the work its finished tasks
    did, and fall back to the runner's own totals otherwise.
    """
    paths = sorted(Path(results_dir).glob("*/*/*/*/" + CELL_META_NAME))
    paths += sorted(Path(results_dir).glob("*/*/*/" + CELL_META_NAME))
    cells: list[CellRecord] = []
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        tokens = data.get("tokens")
        tokens = tokens if isinstance(tokens, dict) else {}
        input_tokens = _token_count(tokens.get("input_tokens"))
        output_tokens = _token_count(tokens.get("output_tokens"))
        from_tasks = _run_tokens(path.parent)
        if from_tasks is not None:
            input_tokens, output_tokens = from_tasks
        cells.append(
            CellRecord(
                ablation=str(data.get("ablation") or ""),
                model=str(data.get("model") or ""),
                scenario_id=str(data.get("scenario_id") or ""),
                repeat=int(data.get("repeat") or 0),
                status=str(data.get("status") or ""),
                wall_s=_number(data.get("elapsed_s")),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
        )
    cells.sort(key=lambda item: (item.ablation, item.model, item.scenario_id, item.repeat))
    return cells


def measure(
    cells: Sequence[CellRecord],
    *,
    scenarios: int,
    ablations: int,
    repeats: int,
) -> Measurement:
    """The measured seconds per cell and the full-column estimate.

    Every cell with a wall time enters the mean, including an error cell: the
    time a failed cell costs to produce is part of what the column costs. The
    token rate is over the same timed cells, so a column that fails still reports
    the tokens its finished tasks spent.
    """
    measured = [cell for cell in cells if cell.wall_s is not None]
    token_cells = [cell for cell in measured if cell.output_tokens]
    total_wall = sum(cell.wall_s for cell in measured if cell.wall_s is not None)
    output = sum(cell.output_tokens for cell in measured)
    if measured:
        mean_wall = fmean(cell.wall_s for cell in measured if cell.wall_s is not None)
    else:
        mean_wall = 0.0
    full_cells = scenarios * ablations * repeats
    return Measurement(
        cells=len(cells),
        measured=len(measured),
        token_cells=len(token_cells),
        total_wall_s=total_wall,
        mean_wall_s=mean_wall,
        output_tokens=output,
        output_tokens_per_s=output / total_wall if total_wall else 0.0,
        full_cells=full_cells,
        estimate_s=mean_wall * full_cells,
    )


def _hours(seconds: float) -> str:
    return f"{seconds / 3600.0:,.1f} h"


def render(
    cells: Sequence[CellRecord],
    *,
    scenarios: int | None = None,
    ablations: int | None = None,
    repeats: int = FULL_REPEATS,
    column: str = "",
) -> str:
    """The measurement as Markdown, a pure function of its arguments."""
    scenario_count = scenarios if scenarios is not None else len(available_scenarios())
    ablation_count = ablations if ablations is not None else len(ABLATION_NAMES)
    lines = ["# Throughput", ""]
    if column:
        lines += [f"Column: `{column}`", ""]
    if not cells:
        lines += ["No cell records found.", ""]
        return "\n".join(lines)

    lines += [
        "| scenario | ablation | model | repeat | status | wall_s | output_tokens |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for cell in cells:
        wall = f"{cell.wall_s:,.1f}" if cell.wall_s is not None else ""
        lines.append(
            f"| {cell.scenario_id} | {cell.ablation} | {cell.model} | {cell.repeat} | "
            f"{cell.status} | {wall} | {cell.output_tokens:,} |"
        )
    lines.append("")

    models = sorted({cell.model for cell in cells})
    for model in models:
        subset = [cell for cell in cells if cell.model == model]
        result = measure(
            subset, scenarios=scenario_count, ablations=ablation_count, repeats=repeats
        )
        lines.append(
            f"`{model}`: {result.measured} of {result.cells} cell(s) timed, "
            f"{result.token_cells} with token records, "
            f"{result.mean_wall_s:,.1f} s per cell, "
            f"{result.output_tokens:,} output tokens at "
            f"{result.output_tokens_per_s:,.2f} tokens/s of wall time. "
            f"Full column: {scenario_count} scenarios x {ablation_count} ablations x "
            f"{repeats} repeats = {result.full_cells} cells, "
            f"{result.estimate_s:,.0f} s ({_hours(result.estimate_s)})."
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="evals.throughput",
        description="Measure tokens per second and the full-column time from a results column.",
    )
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--column", default=None, help="the column under evals/results/")
    parser.add_argument("--scenarios", type=int, default=None, help="scenarios in the estimate")
    parser.add_argument("--ablations", type=int, default=None, help="ablations in the estimate")
    parser.add_argument("--repeats", type=int, default=FULL_REPEATS, help="repeats in the estimate")
    args = parser.parse_args(argv)
    results_dir = Path(args.results_dir)
    column = args.column
    if column:
        results_dir = results_dir / column
    cells = read_cells(results_dir)
    print(
        render(
            cells,
            scenarios=args.scenarios,
            ablations=args.ablations,
            repeats=args.repeats,
            column=column or "",
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
