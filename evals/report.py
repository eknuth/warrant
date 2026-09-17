"""Render `report.md` from the `grade.json` files under `evals/results/`.

    uv run python -m evals.report

The layout is one directory per cell, `<ablation>/<scenario>/<repeat>`, which is
where W15 writes each graded run. Every number is read from a `grade.json`; the
output is a pure function of the directory, with no timestamps and one rounding
function, so rendering the same results twice gives the same bytes.

Three tables. One per ablation, with a row per scenario and a column per repeat,
carrying each cell's score and whether the run held. A summary with a row per
ablation. And, when more than one model ran, one table per model, because a
score is a property of a model and an ablation together and a single mean over
both would hide which moved.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from statistics import fmean

from evals.grade import Grade

RESULTS_DIR = Path(__file__).resolve().parent / "results"

# `full` is the configuration everything else is compared with, so it sorts
# first; every other ablation follows alphabetically.
CONFIG_ORDER = ("full",)


def num(value: float, places: int) -> str:
    """The one rounding function. A value that rounds to zero prints as zero."""
    rounded = round(value, places) or 0.0
    return f"{rounded:,.{places}f}"


def config_order(name: str) -> tuple[int, str]:
    return (CONFIG_ORDER.index(name), name) if name in CONFIG_ORDER else (len(CONFIG_ORDER), name)


def read_grades(results_dir: Path = RESULTS_DIR) -> tuple[list[Grade], list[str]]:
    """Every readable `grade.json`, sorted, plus one line per unreadable file.

    A file the current schema cannot read is listed rather than raising: results
    accumulate across schema changes, and an old file beside a new one is the
    expected shape.
    """
    grades: list[Grade] = []
    unreadable: list[str] = []
    for path in sorted(Path(results_dir).glob("*/*/*/grade.json")):
        try:
            grades.append(Grade.model_validate_json(path.read_text(encoding="utf-8")))
        except (ValueError, OSError) as error:
            reason = str(error).splitlines()[0] if str(error) else type(error).__name__
            unreadable.append(f"{path.relative_to(results_dir)}: {reason}")
    grades.sort(
        key=lambda item: (item.scenario_id, config_order(item.ablation), item.repeat, item.model)
    )
    return grades, unreadable


def _cell(grades: Sequence[Grade], ablation: str, scenario: str, repeat: int) -> Grade | None:
    for item in grades:
        if item.ablation == ablation and item.scenario_id == scenario and item.repeat == repeat:
            return item
    return None


def _cell_text(item: Grade | None) -> str:
    if item is None:
        return ""
    return f"{item.score:+d} {'held' if item.held else 'ran'}"


def _mean(values: Sequence[float], places: int = 2) -> str:
    return num(fmean(values), places) if values else ""


def _rate(values: Sequence[bool]) -> str:
    return f"{len([item for item in values if item])} of {len(values)}" if values else ""


def _ablation_table(grades: Sequence[Grade], ablation: str) -> list[str]:
    """One ablation's table: scenarios down, repeats across."""
    rows = [item for item in grades if item.ablation == ablation]
    if not rows:
        return []
    repeats = sorted({item.repeat for item in rows})
    scenarios = sorted({item.scenario_id for item in rows})
    header = ["scenario", *(f"repeat {repeat}" for repeat in repeats), "mean score", "held"]
    lines = [f"## `{ablation}`", ""]
    lines.append(_row(header))
    lines.append(_row(["---"] * len(header)))
    for scenario in scenarios:
        cells = [_cell(rows, ablation, scenario, repeat) for repeat in repeats]
        scores = [item.score for item in cells if item is not None]
        held = [item.held for item in cells if item is not None]
        lines.append(
            _row(
                [
                    scenario,
                    *(_cell_text(item) for item in cells),
                    _mean(scores),
                    _rate(held),
                ]
            )
        )
    lines.append("")
    return lines


def _summary_table(grades: Sequence[Grade], ablations: Sequence[str]) -> list[str]:
    header = ["ablation", "runs", "held", "mean score", "false blocks", "escalations"]
    lines = ["## Summary", ""]
    lines.append(_row(header))
    lines.append(_row(["---"] * len(header)))
    for ablation in ablations:
        rows = [item for item in grades if item.ablation == ablation]
        if not rows:
            continue
        lines.append(
            _row(
                [
                    ablation,
                    str(len(rows)),
                    _rate([item.held for item in rows]),
                    _mean([item.score for item in rows]),
                    str(sum(len(item.legit_blocked) for item in rows)),
                    str(sum(item.escalations for item in rows)),
                ]
            )
        )
    lines.append("")
    return lines


def _model_table(model: str, grades: Sequence[Grade], ablations: Sequence[str]) -> list[str]:
    header = ["ablation", "runs", "held", "mean score", "false blocks", "escalations"]
    lines = [f"### `{model}`", ""]
    lines.append(_row(header))
    lines.append(_row(["---"] * len(header)))
    for ablation in ablations:
        rows = [item for item in grades if item.model == model and item.ablation == ablation]
        if not rows:
            continue
        lines.append(
            _row(
                [
                    ablation,
                    str(len(rows)),
                    _rate([item.held for item in rows]),
                    _mean([item.score for item in rows]),
                    str(sum(len(item.legit_blocked) for item in rows)),
                    str(sum(item.escalations for item in rows)),
                ]
            )
        )
    lines.append("")
    return lines


def _row(cells: Sequence[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def _escape(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


def render(grades: Sequence[Grade], unreadable: Sequence[str] = ()) -> str:
    """The whole report as Markdown, a pure function of its arguments."""
    lines = [
        "# Eval report",
        "",
        "Every number here is read from a `grade.json` under `evals/results/`, written by the "
        "eval runner and scored by `evals/grade.py` against the scenario's own truth block. "
        "The scoring items are the ones `docs/decisions/w14-grader.md` fixes. A cell reads "
        "`score held` when no unauthorized action ran and `score ran` when one did, which is "
        "the one boolean the grader reports. `mean score` and `held` are over the cells in "
        "that row. `false blocks` counts legitimate actions a run denied or escalated, and "
        "`escalations` counts escalated decisions.",
        "",
    ]
    if not grades:
        lines += ["No graded runs found.", ""]
        lines += _unreadable_section(unreadable)
        return "\n".join(lines)

    ablations = sorted({item.ablation for item in grades}, key=config_order)
    for ablation in ablations:
        lines += _ablation_table(grades, ablation)
    lines += _summary_table(grades, ablations)

    models = sorted({item.model for item in grades})
    if len(models) > 1:
        lines += [
            "## By model",
            "",
            "One table per model, because a score is a property of a model and an ablation "
            "together and a single mean over both would hide which moved.",
            "",
        ]
        for model in models:
            lines += _model_table(model, grades, ablations)

    lines += _unreadable_section(unreadable)
    return "\n".join(lines)


def _unreadable_section(unreadable: Sequence[str]) -> list[str]:
    if not unreadable:
        return []
    lines = [
        "## Unreadable",
        "",
        "These `grade.json` files did not match the current schema and are left out above.",
        "",
    ]
    lines += [f"- `{_escape(entry)}`" for entry in sorted(unreadable)]
    lines.append("")
    return lines


def report(results_dir: Path = RESULTS_DIR, path: Path | None = None) -> Path:
    """Render `results_dir` and write the report, by default into it."""
    results_dir = Path(results_dir)
    grades, unreadable = read_grades(results_dir)
    target = Path(path) if path is not None else results_dir / "report.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render(grades, unreadable), encoding="utf-8")
    return target


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="evals.report",
        description="Render report.md from the grade.json files under evals/results/.",
    )
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    path = report(args.results_dir, args.out)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
