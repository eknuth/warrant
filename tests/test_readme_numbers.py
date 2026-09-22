"""The README's numbers have to be numbers something else produced.

`scripts/check_readme_numbers.py` is the check; this runs it on the committed
README so it cannot rot, and pins the pieces of the checker that would let a
made-up figure through if they were wrong. The strongest check here is the
ablation table: every held, false-block, and mean-score value in the README has
to equal the value in the generated report's summary row for the same ablation.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_readme_numbers.py"
REPORT = ROOT / "evals" / "results" / "v1" / "report.md"


def _load():
    spec = importlib.util.spec_from_file_location("check_readme_numbers", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _table_rows(text: str, heading: str) -> list[list[str]]:
    """The rows of the first table after `heading`, header row included."""
    rows: list[list[str]] = []
    for line in text.split(heading, 1)[1].splitlines():
        if line.startswith("|"):
            rows.append([cell.strip().strip("`") for cell in line.strip("|").split("|")])
        elif rows:
            break
    return rows


def _first_table(text: str) -> list[list[str]]:
    """The rows of the first table in `text`, header row included."""
    rows: list[list[str]] = []
    for line in text.splitlines():
        if line.startswith("|"):
            rows.append([cell.strip().strip("`") for cell in line.strip("|").split("|")])
        elif rows:
            break
    return rows


def test_checker_passes_on_the_committed_readme():
    result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, cwd=ROOT)
    assert result.returncode == 0, result.stdout + result.stderr


def test_tokenizer_reads_the_shapes_the_readme_uses():
    check = _load()
    line = "| `no-exchange` | 27 of 30 | 35 | -2.33 | 10,046 | 167.2 | 12.5 |"
    tokens = [token for token, _ in check.tokens_with_lines(line)]
    assert tokens == ["27", "30", "35", "-2.33", "10,046", "167.2", "12.5"]


def test_an_invented_number_fails(tmp_path, monkeypatch):
    check = _load()
    readme = (ROOT / "README.md").read_text().replace("| 3.30 |", "| 3.31 |")
    fake = tmp_path / "README.md"
    fake.write_text(readme)
    monkeypatch.setattr(check, "README", fake)
    assert check.main() == 1


def test_identifiers_do_not_vouch_for_numbers():
    """A digit in a path, an issue id, a date, or a model name is not a number."""
    check = _load()
    line = (
        "docs/diagrams/architecture.png W19 W21 EDW-1434 2026-09-21 "
        "`qwen-local:qwen3.8:27b@off` and 579,942,251"
    )
    tokens = [token for token, _ in check.tokens_with_lines(check.strip_code(line))]
    assert tokens == ["579,942,251"]


def test_a_number_known_only_through_an_identifier_fails(tmp_path, monkeypatch):
    check = _load()
    readme = (ROOT / "README.md").read_text().replace("30 of 30", "31 of 30")
    fake = tmp_path / "README.md"
    fake.write_text(readme)
    monkeypatch.setattr(check, "README", fake)
    assert check.main() == 1


def test_code_fences_and_inline_code_are_stripped():
    check = _load()
    stripped = check.strip_code("a `x = 99` b\n```\n77\n```\nc 5\n")
    assert "99" not in stripped
    assert "77" not in stripped
    assert "5" in stripped


def test_word_count_ignores_tables_and_fences():
    check = _load()
    text = "one two three\n| a | b |\n```\nfour five\n```\nsix\n"
    assert check.prose_words(text) == 4


def test_the_claim_is_first():
    check = _load()
    assert check.claim_is_first((ROOT / "README.md").read_text())
    assert not check.claim_is_first("# Title\n\n## A heading\n\nprose\n")
    assert not check.claim_is_first("# Title\n\n| a | b |\n")
    assert not check.claim_is_first("# Title\n\n![d](x.png)\n")


def test_the_readme_ablation_table_matches_the_generated_report():
    """Every held, false-block, and score value is the report's own value."""
    report_rows = _table_rows(REPORT.read_text(), "## Summary")
    header = report_rows[0]
    report = {
        row[header.index("ablation")]: {
            "held": row[header.index("held")],
            "false blocks": row[header.index("false blocks")],
            "mean score": row[header.index("mean score")],
        }
        for row in report_rows[2:]
    }
    readme_rows = _table_rows((ROOT / "README.md").read_text(), "## The run")
    header = readme_rows[0]
    readme = {
        row[header.index("ablation")]: {
            "held": row[header.index("held")],
            "false blocks": row[header.index("false blocks")],
            "mean score": row[header.index("mean score")],
        }
        for row in readme_rows[2:]
    }
    assert readme == report


def test_the_brief_quotes_the_same_table_values():
    """The one-page brief is read from; it must not drift from the report either."""
    report_rows = _table_rows(REPORT.read_text(), "## Summary")
    header = report_rows[0]
    report = {
        row[header.index("ablation")]: (
            row[header.index("held")],
            row[header.index("false blocks")],
            row[header.index("mean score")],
        )
        for row in report_rows[2:]
    }
    brief_rows = _first_table((ROOT / "docs" / "brief.md").read_text())
    header = brief_rows[0]
    brief = {
        row[header.index("ablation")]: (
            row[header.index("held")],
            row[header.index("false blocks")],
            row[header.index("mean score")],
        )
        for row in brief_rows[2:]
    }
    assert brief == report
