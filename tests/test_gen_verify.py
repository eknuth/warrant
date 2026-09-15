"""The readback checks that need no running stack.

The Gitea, database, and mailbox checks need the compose stack and live in
`tests/test_gen_integration.py`. The graph checks read one SQLite file, so they
run anywhere: a graph with the scenario's rows passes, a graph without them
fails, and the printed report is stable.
"""

from __future__ import annotations

from pathlib import Path

from gen.schema import load_scenario
from gen.seed import reset_graph
from gen.verify import Check, VerifyReport, render, verify_graph


def test_a_reset_graph_passes_the_graph_checks(tmp_path: Path) -> None:
    scenario = load_scenario("08-quiet-control")
    database = tmp_path / "warrant.db"

    with reset_graph(scenario, database):
        pass

    checks = verify_graph(scenario, database)

    assert checks and all(check.ok for check in checks)


def test_a_graph_without_the_scenario_rows_fails(tmp_path: Path) -> None:
    scenario = load_scenario("08-quiet-control")
    database = tmp_path / "warrant.db"

    with reset_graph(None, database):
        pass

    checks = verify_graph(scenario, database)

    assert not all(check.ok for check in checks)
    assert any(check.name == "graph db resources" and not check.ok for check in checks)


def test_a_wrong_owner_fails_the_readback(tmp_path: Path) -> None:
    import sqlite3

    scenario = load_scenario("08-quiet-control")
    database = tmp_path / "warrant.db"
    with reset_graph(scenario, database):
        pass
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE resources SET owner_human_id = 'h-carol' WHERE id = 'db-ticket-12'")
        conn.commit()

    checks = verify_graph(scenario, database)

    assert any(check.name == "graph db resources" and not check.ok for check in checks)
    assert any(check.name == "graph agents" and check.ok for check in checks)


def test_render_is_one_line_per_check() -> None:
    report = VerifyReport(
        scenario_id="08-quiet-control",
        checks=[Check(name="a", ok=True, detail="fine"), Check(name="b", ok=False, detail="bad")],
    )

    assert render(report) == ("verify 08-quiet-control: FAILED\n  ok   a: fine\n  FAIL b: bad")


def test_a_report_is_ok_only_when_every_check_is() -> None:
    assert VerifyReport("x", [Check("a", True, "")]).ok is True
    assert VerifyReport("x", [Check("a", True, ""), Check("b", False, "")]).ok is False
