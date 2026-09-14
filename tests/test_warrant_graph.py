"""The access graph: the shipped fixture, the loader, and the CLI."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from warrant import graph

REPO = Path(__file__).resolve().parents[1]
SEED = REPO / "infra" / "graph.yml"


@pytest.fixture
def loaded(tmp_path: Path) -> graph.Graph:
    with graph.load(SEED, tmp_path / "warrant.db") as opened:
        yield opened


def test_the_shipped_fixture_has_three_humans_and_three_agents(loaded: graph.Graph) -> None:
    assert [human.id for human in loaded.humans()] == ["h-alice", "h-bob", "h-carol"]
    assert [agent.id for agent in loaded.agents()] == [
        "orphan-agent",
        "support-agent",
        "triage-agent",
    ]


def test_an_agent_row_round_trips_through_sqlite(loaded: graph.Graph) -> None:
    agent = loaded.agent("support-agent")

    assert agent is not None
    assert agent.client_id == "support-agent"
    assert agent.owner_human_id == "h-bob"
    assert agent.justification == "answer the support mailbox"
    assert agent.justification_expires_at is not None
    assert agent.justification_expires_at.year == 2027
    assert agent.allowed_tools == ["mail.search", "mail.send", "db.query"]


def test_a_human_row_round_trips_through_sqlite(loaded: graph.Graph) -> None:
    human = loaded.human("h-carol")

    assert human is not None
    assert human.login == "carol"
    assert human.groups == ["engineering", "reviewers"]


def test_tool_and_resource_rows_round_trip(loaded: graph.Graph) -> None:
    tool = loaded.tool("mail.send")
    resource = loaded.resource("table-orders")

    assert tool is not None
    assert (tool.server, tool.name, tool.action_kind, tool.resource_kind) == (
        "mail",
        "send",
        "send",
        "mailbox",
    )
    assert resource is not None
    assert (resource.kind, resource.name, resource.owner_human_id, resource.sensitivity) == (
        "db_table",
        "public.orders",
        "h-alice",
        "confidential",
    )


def test_a_resource_resolves_from_the_name_a_tool_call_carries(loaded: graph.Graph) -> None:
    found = loaded.resource_named("acme/widgets", "repo")

    assert found is not None
    assert found.id == "repo-acme-widgets"
    assert loaded.resource_named("acme/widgets", "db_table") is None
    assert loaded.resource_named("nobody's-repo") is None


def test_an_unknown_id_is_none_not_an_error(loaded: graph.Graph) -> None:
    assert loaded.human("nobody") is None
    assert loaded.agent("nobody") is None
    assert loaded.tool("nobody") is None
    assert loaded.resource("nobody") is None


def test_an_agent_may_have_no_owner(tmp_path: Path) -> None:
    seed = tmp_path / "graph.yml"
    seed.write_text(
        """
humans:
  - id: h-solo
    login: solo
    groups: []
agents:
  - id: agent-solo
    client_id: c-solo
    owner_human_id: null
    justification: no owner on file
    justification_expires_at: null
    allowed_tools: []
"""
    )

    with graph.load(seed, tmp_path / "warrant.db") as opened:
        agent = opened.agent("agent-solo")

    assert agent is not None
    assert agent.owner_human_id is None
    assert agent.justification_expires_at is None
    assert agent.allowed_tools == []


def test_loading_twice_leaves_the_same_graph(tmp_path: Path) -> None:
    database = tmp_path / "warrant.db"
    graph.load(SEED, database).close()
    with graph.load(SEED, database) as second:
        assert len(second.humans()) == 3
        assert len(second.agents()) == 3
        assert len(second.tools()) == 14
        assert len(second.resources()) == 5


def test_an_agent_with_an_unknown_owner_is_refused(tmp_path: Path) -> None:
    """The foreign key is what keeps an orphan agent out of the graph."""
    database = tmp_path / "warrant.db"
    with graph.Graph(database) as opened:
        with pytest.raises(sqlite3.IntegrityError):
            opened.seed(
                {
                    "humans": [],
                    "agents": [
                        {
                            "id": "agent-orphan",
                            "client_id": "c",
                            "owner_human_id": "h-missing",
                            "allowed_tools": [],
                        }
                    ],
                }
            )


def test_the_cli_loads_a_seed_and_reports_what_it_wrote(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    database = tmp_path / "warrant.db"

    assert graph.main(["load", str(SEED), "--db", str(database)]) == 0

    output = capsys.readouterr().out
    assert "humans=3" in output
    assert "agents=3" in output
    assert str(database) in output
    with graph.Graph(database) as opened:
        assert len(opened.agents()) == 3


def test_load_rejects_a_seed_that_is_not_a_mapping(tmp_path: Path) -> None:
    seed = tmp_path / "graph.yml"
    seed.write_text("- not\n- a mapping\n")

    with pytest.raises(ValueError, match="mapping"):
        graph.load(seed, tmp_path / "warrant.db")


def test_a_seed_entry_missing_a_column_names_it(tmp_path: Path) -> None:
    seed = tmp_path / "graph.yml"
    seed.write_text("humans:\n  - id: h1\n")

    with pytest.raises(ValueError, match="login"):
        graph.load(seed, tmp_path / "warrant.db")
