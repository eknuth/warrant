"""The throughput measurement reads the cell records the runner wrote.

The runner writes `meta.json` into every finished cell with `elapsed_s`, and
each finished task writes a `usage.json` with the tokens it spent. These tests
build that layout by hand and check the seconds per cell, the tokens per second,
the partial count an error cell reports, and the full-column estimate, with no
model.
"""

from __future__ import annotations

import json
from pathlib import Path

from evals.throughput import measure, read_cells, render


def write_cell_meta(
    root: Path,
    *,
    ablation: str = "full",
    model: str = "qwen-local:qwen3.8:27b@off",
    scenario: str = "08-quiet-control",
    repeat: int = 1,
    status: str = "ok",
    elapsed_s: float | None = 100.0,
    input_tokens: int = 1000,
    output_tokens: int = 200,
) -> Path:
    model_dir = "".join(char if char.isalnum() or char in "._-" else "_" for char in model)
    path = root / ablation / model_dir / scenario / str(repeat) / "meta.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    meta: dict[str, object] = {
        "ablation": ablation,
        "model": model,
        "scenario_id": scenario,
        "repeat": repeat,
        "status": status,
        "tokens": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    }
    if elapsed_s is not None:
        meta["elapsed_s"] = elapsed_s
    path.write_text(json.dumps(meta), encoding="utf-8")
    return path


def test_read_cells_reads_the_four_level_cell(tmp_path: Path) -> None:
    write_cell_meta(tmp_path, elapsed_s=12.5, output_tokens=42)

    cells = read_cells(tmp_path)

    assert len(cells) == 1
    assert cells[0].scenario_id == "08-quiet-control"
    assert cells[0].model == "qwen-local:qwen3.8:27b@off"
    assert cells[0].wall_s == 12.5
    assert cells[0].output_tokens == 42


def test_read_cells_reads_partial_task_usage_for_an_error_cell(tmp_path: Path) -> None:
    """A cell that failed on a later task still reports the tasks that finished."""
    path = write_cell_meta(tmp_path, status="error", elapsed_s=300.0, output_tokens=0)
    task = path.parent / "run" / "finished-task"
    task.mkdir(parents=True)
    (task / "usage.json").write_text(
        json.dumps({"input_tokens": 500, "output_tokens": 150}), encoding="utf-8"
    )

    cells = read_cells(tmp_path)

    assert cells[0].status == "error"
    assert cells[0].output_tokens == 150
    assert cells[0].input_tokens == 500


def test_measure_uses_seconds_per_cell_and_multiplies_the_column(tmp_path: Path) -> None:
    write_cell_meta(
        tmp_path, scenario="08-quiet-control", repeat=1, elapsed_s=100.0, output_tokens=200
    )
    write_cell_meta(
        tmp_path, scenario="09-external-but-honest", repeat=2, elapsed_s=200.0, output_tokens=400
    )

    result = measure(read_cells(tmp_path), scenarios=10, ablations=6, repeats=3)

    assert result.measured == 2
    assert result.token_cells == 2
    assert result.mean_wall_s == 150.0
    assert result.output_tokens_per_s == 2.0
    assert result.full_cells == 180
    assert result.estimate_s == 27000.0


def test_measure_counts_an_error_cells_wall_time_and_partial_tokens(tmp_path: Path) -> None:
    failed = write_cell_meta(
        tmp_path, scenario="01-issue-injection", status="error", elapsed_s=300.0
    )
    task = failed.parent / "run" / "finished-task"
    task.mkdir(parents=True)
    (task / "usage.json").write_text(
        json.dumps({"input_tokens": 500, "output_tokens": 150}), encoding="utf-8"
    )

    result = measure(read_cells(tmp_path), scenarios=10, ablations=6, repeats=3)

    assert result.measured == 1
    assert result.token_cells == 1
    assert result.mean_wall_s == 300.0
    assert result.output_tokens_per_s == 0.5


def test_measure_skips_a_cell_with_no_wall_time() -> None:
    from evals.throughput import CellRecord

    cells = [
        CellRecord("full", "m", "08-quiet-control", 1, "error", None, 0, 0),
        CellRecord("full", "m", "08-quiet-control", 2, "ok", 60.0, 100, 200),
    ]

    result = measure(cells, scenarios=10, ablations=6, repeats=3)

    assert result.measured == 1
    assert result.mean_wall_s == 60.0


def test_render_names_the_measurement_and_the_estimate(tmp_path: Path) -> None:
    write_cell_meta(tmp_path, elapsed_s=100.0, output_tokens=200)
    write_cell_meta(
        tmp_path, scenario="09-external-but-honest", repeat=2, elapsed_s=200.0, output_tokens=400
    )

    text = render(read_cells(tmp_path), scenarios=10, ablations=6, repeats=3, column="smoke")

    assert "Column: `smoke`" in text
    assert "2 of 2 cell(s) timed, 2 with token records, 150.0 s per cell" in text
    assert "600 output tokens at 2.00 tokens/s" in text
    assert "10 scenarios x 6 ablations x 3 repeats = 180 cells" in text
    assert "27,000 s (7.5 h)" in text


def test_render_estimates_each_model_separately(tmp_path: Path) -> None:
    """A full column is one model, so the estimate is one per model."""
    write_cell_meta(tmp_path, model="fast:model@off", elapsed_s=10.0, output_tokens=100)
    write_cell_meta(
        tmp_path,
        model="slow:model@off",
        scenario="09-external-but-honest",
        elapsed_s=100.0,
        output_tokens=100,
    )

    text = render(read_cells(tmp_path), scenarios=10, ablations=6, repeats=3)

    assert "`fast:model@off`:" in text and "1,800 s (0.5 h)" in text
    assert "`slow:model@off`:" in text and "18,000 s (5.0 h)" in text


def test_render_reports_an_error_cell_status(tmp_path: Path) -> None:
    write_cell_meta(tmp_path, status="error", elapsed_s=5.0, output_tokens=0)

    text = render(read_cells(tmp_path), scenarios=10, ablations=6, repeats=3)

    assert "| 08-quiet-control | full | qwen-local:qwen3.8:27b@off | 1 | error | 5.0 | 0 |" in text
