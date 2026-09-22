"""The build-cost table is generated from the harness records and must not drift.

`scripts/build_cost.py` is the one producer of the number in the README's build
paragraph. These tests pin the two things that would let a wrong figure through:
the dedupe that keeps one session from being counted twice, and the committed
table itself, which has to be byte-for-byte what the script renders from the
records on this machine.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build_cost.py"
RECORDS = ROOT / "runs" / "dsh"
COMMITTED = ROOT / "docs" / "build-cost.md"


def _load():
    spec = importlib.util.spec_from_file_location("build_cost", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # The module holds a dataclass, and dataclasses resolves its string
    # annotations through sys.modules; a module loaded without registering
    # itself there fails at class creation.
    sys.modules["build_cost"] = module
    spec.loader.exec_module(module)
    return module


def _record(session: str, *, failed: bool, exit_code: int, tokens: int) -> dict:
    usage = {
        "inputTokens": tokens,
        "outputTokens": tokens,
        "cacheReadTokens": tokens,
        "totalTokens": tokens * 3,
    }
    name = f"{session}.failed-20260101-000000-000000.json" if failed else f"{session}.json"
    return {
        "name": name,
        "payload": {
            "session_id": session,
            "effort": "high",
            "exit_code": exit_code,
            "wall_s": 10.0,
            "usage": usage,
            "started_at": "2026-01-01T00:00:00+00:00",
        },
    }


def _write(directory: Path, record: dict) -> None:
    (directory / record["name"]).write_text(json.dumps(record["payload"]))


def test_a_failed_sibling_is_dropped_not_counted_twice(tmp_path):
    build = _load()
    _write(tmp_path, _record("w99", failed=False, exit_code=0, tokens=100))
    _write(tmp_path, _record("w99", failed=True, exit_code=1, tokens=0))
    records, dropped = build.load_records(tmp_path)
    assert len(records) == 1
    assert records[0].total_tokens == 300
    assert records[0].exit_code == 0
    assert dropped == ["w99.failed-20260101-000000-000000.json"]


def test_a_live_record_wins_over_a_failed_one_with_the_same_id(tmp_path):
    build = _load()
    _write(tmp_path, _record("w99", failed=False, exit_code=1, tokens=5))
    _write(tmp_path, _record("w99", failed=True, exit_code=0, tokens=100))
    records, dropped = build.load_records(tmp_path)
    assert len(records) == 1
    assert records[0].total_tokens == 15
    assert dropped == ["w99.failed-20260101-000000-000000.json"]


def test_the_render_names_the_floor(tmp_path):
    build = _load()
    _write(tmp_path, _record("w99", failed=False, exit_code=0, tokens=100))
    records, dropped = build.load_records(tmp_path)
    text = build.render(records, dropped)
    assert "| **1 sessions** |" in text
    assert "300 tokens" in text
    assert "W1 through W12 ran through the web interface" in text


def test_the_committed_table_matches_the_records_it_names():
    """Every committed row is the record it names, and the totals are their sum.

    A later session adds a record the table does not list yet, which is what
    `make build-cost` is for; that must not fail this check. What must hold is
    that no listed row disagrees with the record on disk and that the totals
    row is the sum of the listed rows.
    """
    if not RECORDS.is_dir():
        pytest.skip("no runs/dsh in this checkout")
    build = _load()
    records, _ = build.load_records(RECORDS)
    by_session = {record.session: record for record in records}
    text = COMMITTED.read_text()

    listed = []
    for line in text.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        session = cells[0].strip("`")
        assert session in by_session, f"{session} is in the table but not on disk"
        record = by_session[session]
        assert cells[1] == record.effort, session
        assert cells[2] == str(record.exit_code), session
        assert cells[3] == f"{record.wall_s:,.0f}", session
        assert cells[4] == f"{record.input_tokens:,}", session
        assert cells[5] == f"{record.output_tokens:,}", session
        assert cells[6] == f"{record.cache_tokens:,}", session
        assert cells[7] == f"{record.total_tokens:,}", session
        listed.append(record)
    assert listed, "the committed table lists no sessions"

    total_line = next(line for line in text.splitlines() if line.startswith("| **"))
    cells = [cell.strip().strip("*") for cell in total_line.strip("|").split("|")]
    assert cells[0] == f"{len(listed)} sessions"
    assert cells[3] == f"{sum(record.wall_s for record in listed):,.0f}"
    assert cells[4] == f"{sum(record.input_tokens for record in listed):,}"
    assert cells[5] == f"{sum(record.output_tokens for record in listed):,}"
    assert cells[6] == f"{sum(record.cache_tokens for record in listed):,}"
    assert cells[7] == f"{sum(record.total_tokens for record in listed):,}"
