"""The readback checks that need no running stack.

The Gitea, database, and mailbox checks need the compose stack and live in
`tests/test_gen_integration.py`. The graph checks read one SQLite file, so they
run anywhere: a graph with the scenario's rows passes, a graph without them
fails, a mutated field fails, and the printed report is stable.
"""

from __future__ import annotations

import copy
import sqlite3
from pathlib import Path

import yaml

from gen.schema import SCENARIO_DIR, Scenario, load_scenario
from gen.seed import reset_graph
from gen.verify import Check, VerifyReport, render, verify_graph


def scenario_with_agent(**overrides: object) -> Scenario:
    """The quiet-control fixture plus one scenario-owned agent."""
    data = copy.deepcopy(yaml.safe_load((SCENARIO_DIR / "08-quiet-control.yml").read_text()))
    agent: dict = {
        "client_id": "audit-agent",
        "owner": "carol",
        "justification": "watch the desk",
        "justification_expires_at": "2027-01-01T00:00:00Z",
        "allowed_tools": ["gitea.get_issue"],
    }
    agent.update(overrides)
    data["seed"]["graph"]["agents"] = [agent]
    return Scenario.model_validate(data)


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
    scenario = load_scenario("08-quiet-control")
    database = tmp_path / "warrant.db"
    with reset_graph(scenario, database):
        pass
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE resources SET owner_human_id = 'h-carol' WHERE id = 'db-ticket-12'")
        conn.commit()

    checks = verify_graph(scenario, database)

    assert any(check.name == "graph db resources" and not check.ok for check in checks)


def test_a_scenario_agent_passes_the_graph_checks(tmp_path: Path) -> None:
    scenario = scenario_with_agent()
    database = tmp_path / "warrant.db"

    with reset_graph(scenario, database):
        pass

    checks = verify_graph(scenario, database)

    assert all(check.ok for check in checks)


def test_a_mutated_expiry_fails_the_readback(tmp_path: Path) -> None:
    """Finding 2: the scenario agent's justification expiry is compared."""
    scenario = scenario_with_agent()
    database = tmp_path / "warrant.db"
    with reset_graph(scenario, database):
        pass
    with sqlite3.connect(database) as conn:
        conn.execute(
            "UPDATE agents SET justification_expires_at = '2028-01-01T00:00:00Z' "
            "WHERE id = 'audit-agent'"
        )
        conn.commit()

    checks = verify_graph(scenario, database)

    assert any(check.name == "graph agents" and not check.ok for check in checks)


def test_an_extra_agent_fails_the_set_check(tmp_path: Path) -> None:
    """Finding 12: the graph may not hold an agent the scenario did not name."""
    scenario = load_scenario("08-quiet-control")
    database = tmp_path / "warrant.db"
    with reset_graph(scenario, database):
        pass
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO agents (id, client_id, owner_human_id, justification, "
            "justification_expires_at, allowed_tools) "
            "VALUES ('stray-agent', 'stray-agent', 'h-bob', 'stray', NULL, '[]')"
        )
        conn.commit()

    checks = verify_graph(scenario, database)

    assert any(check.name == "graph agent set" and not check.ok for check in checks)


def test_render_is_one_line_per_check() -> None:
    report = VerifyReport(
        scenario_id="08-quiet-control",
        checks=[Check(name="a", ok=True, detail="fine"), Check(name="b", ok=False, detail="bad")],
    )

    assert render(report) == ("verify 08-quiet-control: FAILED\n  ok   a: fine\n  FAIL b: bad")


def test_a_report_is_ok_only_when_every_check_is() -> None:
    assert VerifyReport("x", [Check("a", True, "")]).ok is True
    assert VerifyReport("x", [Check("a", True, ""), Check("b", False, "")]).ok is False
