"""The seeder's pieces that need no running stack.

The Gitea, database, and mailbox writes need the compose stack, and
`tests/test_gen_integration.py` covers those. What is here is the graph work and
the path rules: the ticket and customer rows the seeder derives from the DB
block, the total reload that leaves no agent behind, and the graph path the
gateway shares.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from gen.schema import load_scenario
from gen.seed import (
    default_graph_db,
    reset_graph,
    reset_runs,
    scenario_graph_rows,
    scenario_run_dir,
)
from warrant import graph

REPO = Path(__file__).resolve().parents[1]
SEED = REPO / "infra" / "graph.yml"


def test_the_db_block_becomes_ticket_and_customer_graph_rows() -> None:
    """W10 left these rows to W12; the scenario's DB block is where they come from."""
    scenario = load_scenario("08-quiet-control")

    with graph.Graph(":memory:") as base:
        base.seed(yaml.safe_load(SEED.read_text(encoding="utf-8")))
        rows = scenario_graph_rows(scenario, base)

    resources = {row["id"]: row for row in rows["resources"]}
    assert resources["db-customer-1"]["name"] == "1"
    assert resources["db-customer-1"]["kind"] == "db_customer"
    assert resources["db-customer-1"]["owner_human_id"] == "h-bob"
    assert resources["db-ticket-12"]["name"] == "12"
    assert resources["db-ticket-12"]["kind"] == "db_ticket"
    assert resources["db-ticket-12"]["owner_human_id"] == "h-bob"


def test_the_scenario_agents_carry_their_owner_and_authority() -> None:
    scenario = load_scenario("01-issue-injection")

    with graph.Graph(":memory:") as base:
        base.seed(yaml.safe_load(SEED.read_text(encoding="utf-8")))
        rows = scenario_graph_rows(scenario, base)

    agent = next(row for row in rows["agents"] if row["id"] == "triage-agent")
    assert agent["owner_human_id"] == "h-alice"
    assert "gitea.set_repo_visibility" in agent["allowed_tools"]


def test_reset_graph_leaves_no_agent_from_the_previous_scenario(tmp_path: Path) -> None:
    database = tmp_path / "warrant.db"
    scenario = load_scenario("01-issue-injection")

    with reset_graph(scenario, database):
        pass
    with reset_graph(None, database) as reopened:
        # The shipped graph still has the four shipped agents, and only those.
        assert "triage-agent" in {agent.id for agent in reopened.agents()}
        assert len(reopened.agents()) == 4
        assert reopened.resource_named("1", "db_customer") is None


def test_reset_graph_puts_the_scenario_agents_in_place(tmp_path: Path) -> None:
    database = tmp_path / "warrant.db"

    with reset_graph(load_scenario("08-quiet-control"), database) as opened:
        assert opened.agent("support-agent") is not None
        ticket = opened.resource_named("12", "db_ticket")
        assert ticket is not None and ticket.owner_human_id == "h-bob"


def test_the_default_graph_db_lives_under_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gateway bind-mounts `runs/`, so the seeder's file is the gateway's file."""
    monkeypatch.delenv("WARRANT_GRAPH_DB", raising=False)
    monkeypatch.setenv("WARRANT_RUNS_DIR", "/tmp/w12-runs")

    assert default_graph_db() == Path("/tmp/w12-runs/graph/warrant.db")


def test_the_graph_db_environment_variable_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARRANT_GRAPH_DB", "/tmp/somewhere/warrant.db")

    assert default_graph_db() == Path("/tmp/somewhere/warrant.db")


def test_reset_runs_gives_a_fresh_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WARRANT_RUNS_DIR", str(tmp_path))
    directory = scenario_run_dir("08-quiet-control")
    directory.mkdir(parents=True)
    stale = directory / "old.json"
    stale.write_text("{}", encoding="utf-8")

    fresh = reset_runs("08-quiet-control")

    assert fresh == directory
    assert fresh.is_dir()
    assert not stale.exists()
