"""The report is a pure function of the results directory.

W15 writes `grade.json` into
`evals/results/<ablation>/<model>/<scenario>/<repeat>/`; these tests build that
layout by hand, and one test builds the older three-level cell to check the
back-compat read. The tables, the summary, the per-cell wall time, and that
rendering the same directory twice gives the same bytes are checked here.
"""

from __future__ import annotations

import json
from pathlib import Path

from evals.grade import Finding, Grade, GradeItem, write_grade
from evals.report import read_grades, render, report
from evals.run import safe_model_dir


def make_grade(
    *,
    scenario_id: str,
    ablation: str,
    repeat: int,
    model: str = "deepseek-flash",
    score: int = 6,
    held: bool = True,
    blocked: int = 0,
    escalations: int = 0,
    wall_s: float | None = None,
) -> Grade:
    return Grade(
        scenario_id=scenario_id,
        ablation=ablation,
        model=model,
        repeat=repeat,
        score=score,
        held=held,
        items=[GradeItem(rule="chain-complete", points=2, evidence="fixture")],
        unauthorized_ran=[]
        if held
        else [Finding(tool="gitea.get_file", origin="fixture", evidence="{}")],
        legit_blocked=[
            Finding(tool="db.update_ticket", origin="fixture", evidence="{}", verdict="deny")
            for _ in range(blocked)
        ],
        chain_complete=True,
        escalations=escalations,
        wall_s=wall_s,
    )


def write_cell(root: Path, grade: Grade) -> Path:
    return write_grade(
        grade,
        root
        / grade.ablation
        / safe_model_dir(grade.model)
        / grade.scenario_id
        / str(grade.repeat)
        / "grade.json",
    )


def test_read_grades_sorts_cells_and_lists_unreadable_files(tmp_path: Path) -> None:
    write_cell(
        tmp_path, make_grade(scenario_id="08-quiet-control", ablation="no-provenance", repeat=1)
    )
    write_cell(tmp_path, make_grade(scenario_id="01-issue-injection", ablation="full", repeat=2))
    write_cell(tmp_path, make_grade(scenario_id="08-quiet-control", ablation="full", repeat=1))
    broken = tmp_path / "full" / "02-scope-collapse" / "1" / "grade.json"
    broken.parent.mkdir(parents=True)
    broken.write_text("{not json", encoding="utf-8")

    grades, unreadable = read_grades(tmp_path)

    assert [(item.ablation, item.scenario_id, item.repeat) for item in grades] == [
        ("full", "01-issue-injection", 2),
        ("full", "08-quiet-control", 1),
        ("no-provenance", "08-quiet-control", 1),
    ]
    assert len(unreadable) == 1
    assert "02-scope-collapse" in unreadable[0]


def test_render_writes_one_table_per_ablation_and_a_summary(tmp_path: Path) -> None:
    write_cell(tmp_path, make_grade(scenario_id="08-quiet-control", ablation="full", repeat=1))
    write_cell(
        tmp_path,
        make_grade(
            scenario_id="08-quiet-control", ablation="full", repeat=2, score=-18, held=False
        ),
    )
    write_cell(
        tmp_path, make_grade(scenario_id="08-quiet-control", ablation="no-provenance", repeat=1)
    )

    text = render(read_grades(tmp_path)[0])

    assert "## `full`" in text
    assert "## `no-provenance`" in text
    assert "## Summary" in text
    assert "| 08-quiet-control | +6 held | -18 ran |" in text
    assert "| full | 2 | 1 of 2 | -6.00 | 0 | 0 |" in text
    assert "## By model" not in text


def test_render_adds_per_model_tables_only_for_more_than_one_model(tmp_path: Path) -> None:
    write_cell(
        tmp_path,
        make_grade(
            scenario_id="08-quiet-control", ablation="full", repeat=1, model="deepseek-flash"
        ),
    )
    write_cell(
        tmp_path,
        make_grade(scenario_id="08-quiet-control", ablation="full", repeat=2, model="other-model"),
    )

    text = render(read_grades(tmp_path)[0])

    assert "## By model" in text
    assert "### `deepseek-flash`" in text
    assert "### `other-model`" in text
    assert "## Summary" not in text, "a combined mean would hide which model moved"


def test_a_cell_shows_its_wall_time_next_to_the_score(tmp_path: Path) -> None:
    write_cell(
        tmp_path,
        make_grade(scenario_id="08-quiet-control", ablation="full", repeat=1, wall_s=12.5),
    )
    write_cell(
        tmp_path,
        make_grade(scenario_id="08-quiet-control", ablation="full", repeat=2, wall_s=200.0),
    )

    text = render(read_grades(tmp_path)[0])

    assert "| 08-quiet-control | +6 held 12.5s | +6 held 200.0s |" in text


def test_two_models_for_one_scenario_get_their_own_rows(tmp_path: Path) -> None:
    """A model column is what stops one model's cell standing in for another."""
    write_cell(
        tmp_path,
        make_grade(
            scenario_id="08-quiet-control",
            ablation="full",
            repeat=1,
            model="deepseek:deepseek-flash@off",
            score=6,
        ),
    )
    write_cell(
        tmp_path,
        make_grade(
            scenario_id="08-quiet-control",
            ablation="full",
            repeat=1,
            model="qwen-local:qwen3.8:27b@off",
            score=4,
            held=False,
        ),
    )

    text = render(read_grades(tmp_path)[0])

    assert "| scenario | model | repeat 1 | mean score | held |" in text
    assert "| 08-quiet-control | deepseek:deepseek-flash@off | +6 held |" in text
    assert "| 08-quiet-control | qwen-local:qwen3.8:27b@off | +4 ran |" in text


def test_read_grades_reads_the_older_three_level_cell(tmp_path: Path) -> None:
    write_grade(
        make_grade(scenario_id="08-quiet-control", ablation="full", repeat=1),
        tmp_path / "full" / "08-quiet-control" / "1" / "grade.json",
    )

    grades, unreadable = read_grades(tmp_path)

    assert [item.scenario_id for item in grades] == ["08-quiet-control"]
    assert unreadable == []


def test_rendering_the_same_directory_twice_is_byte_identical(tmp_path: Path) -> None:
    write_cell(tmp_path, make_grade(scenario_id="08-quiet-control", ablation="full", repeat=1))
    write_cell(tmp_path, make_grade(scenario_id="01-issue-injection", ablation="full", repeat=1))

    first = render(read_grades(tmp_path)[0])
    second = render(read_grades(tmp_path)[0])

    assert first == second


def test_report_writes_report_md_into_the_results_directory(tmp_path: Path) -> None:
    write_cell(tmp_path, make_grade(scenario_id="08-quiet-control", ablation="full", repeat=1))

    path = report(tmp_path)

    assert path == tmp_path / "report.md"
    assert path.read_text(encoding="utf-8").startswith("# Eval report")


def test_an_empty_results_directory_says_so(tmp_path: Path) -> None:
    text = render([])
    assert "No graded runs found." in text


def test_a_grade_json_round_trips_through_the_report_reader(tmp_path: Path) -> None:
    grade = make_grade(scenario_id="08-quiet-control", ablation="full", repeat=1, blocked=1)
    path = write_cell(tmp_path, grade)
    loaded = Grade.model_validate_json(path.read_text(encoding="utf-8"))
    assert loaded == grade
    assert (
        json.loads(path.read_text(encoding="utf-8"))["legit_blocked"][0]["tool"]
        == "db.update_ticket"
    )
