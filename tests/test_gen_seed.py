"""The seeder's pieces that need no running stack.

The Gitea, database, and mailbox writes need the compose stack, and
`tests/test_gen_integration.py` covers those. What is here is the graph work and
the path rules: the ticket and customer rows the seeder derives from the DB
block, the scenario-owned agents, the total reload that leaves no agent behind,
and the graph path the gateway shares.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

import gen.__main__ as cli
from gen.schema import SCENARIO_DIR, Scenario, load_scenario
from gen.seed import (
    SeedError,
    SeedReport,
    default_graph_db,
    reset_graph,
    reset_runs,
    scenario_graph_rows,
    scenario_run_dir,
    write_seed_manifest,
)
from warrant import graph
from warrant.config import main_checkout

REPO = Path(__file__).resolve().parents[1]
SEED = REPO / "infra" / "graph.yml"


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


def test_the_db_block_becomes_a_mailbox_row_for_an_honest_reply() -> None:
    """A reply resolves its resource from the address, so the row has to exist."""
    scenario = load_scenario("08-quiet-control")

    with graph.Graph(":memory:") as base:
        base.seed(yaml.safe_load(SEED.read_text(encoding="utf-8")))
        rows = scenario_graph_rows(scenario, base)

    mailboxes = [row for row in rows["resources"] if row["kind"] == "mailbox"]
    assert len(mailboxes) == 1
    assert mailboxes[0]["name"] == "dana@acme.test"
    assert mailboxes[0]["owner_human_id"] == "h-bob"
    assert mailboxes[0]["sensitivity"] == "internal"


def test_a_shipped_mailbox_is_left_to_the_shipped_row() -> None:
    """The seeder derives rows the graph lacks, and does not shadow one it has."""
    data = copy.deepcopy(yaml.safe_load((SCENARIO_DIR / "08-quiet-control.yml").read_text()))
    data["seed"]["db"]["customers"].append(
        {"id": 2, "name": "Desk", "email": "support@acme.test", "owner_login": "bob"}
    )
    scenario = Scenario.model_validate(data)

    with graph.Graph(":memory:") as base:
        base.seed(yaml.safe_load(SEED.read_text(encoding="utf-8")))
        rows = scenario_graph_rows(scenario, base)

    names = [row["name"] for row in rows["resources"] if row["kind"] == "mailbox"]
    assert "support@acme.test" not in names
    assert "dana@acme.test" in names


def test_a_scenario_agent_carries_its_owner_expiry_and_authority() -> None:
    scenario = scenario_with_agent()

    with graph.Graph(":memory:") as base:
        base.seed(yaml.safe_load(SEED.read_text(encoding="utf-8")))
        rows = scenario_graph_rows(scenario, base)

    agent = next(row for row in rows["agents"] if row["id"] == "audit-agent")
    assert agent["owner_human_id"] == "h-carol"
    assert agent["justification_expires_at"] == "2027-01-01T00:00:00Z"
    assert agent["allowed_tools"] == ["gitea.get_issue"]


def test_reset_graph_leaves_no_agent_from_the_previous_scenario(tmp_path: Path) -> None:
    database = tmp_path / "warrant.db"

    with reset_graph(scenario_with_agent(), database):
        pass
    with reset_graph(None, database) as reopened:
        # The shipped graph still has the four shipped agents, and only those.
        assert "audit-agent" not in {agent.id for agent in reopened.agents()}
        assert len(reopened.agents()) == 4
        assert reopened.resource_named("1", "db_customer") is None


def test_reset_graph_puts_the_scenario_agents_and_rows_in_place(tmp_path: Path) -> None:
    database = tmp_path / "warrant.db"

    with reset_graph(scenario_with_agent(), database) as opened:
        assert opened.agent("audit-agent") is not None
        assert opened.agent("support-agent") is not None
        ticket = opened.resource_named("12", "db_ticket")
        assert ticket is not None and ticket.owner_human_id == "h-bob"


def test_the_default_graph_db_ignores_the_runs_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """A column's runs override must not move the graph away from the gateway.

    The gateway opens `/app/runs/graph/warrant.db` through the mount, so the
    seeder's default stays on the main checkout's `runs/`, not on a
    `WARRANT_RUNS_DIR` a column set for its own records.
    """
    monkeypatch.delenv("WARRANT_GRAPH_DB", raising=False)
    monkeypatch.setenv("WARRANT_RUNS_DIR", "/tmp/w12-runs")

    assert default_graph_db() == main_checkout() / "runs" / "graph" / "warrant.db"


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


def test_the_seed_manifest_lands_in_the_run_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = SeedReport(
        scenario_id="08-quiet-control",
        elapsed_s=0.5,
        repos=["acme/widgets"],
        users=["bob"],
        customers=1,
        tickets=1,
        messages=1,
    )
    monkeypatch.setenv("WARRANT_RUNS_DIR", str(tmp_path))

    target = write_seed_manifest(report)

    assert target == tmp_path / "scenarios" / "08-quiet-control" / "seed.json"
    manifest = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert manifest["scenario_id"] == "08-quiet-control"
    assert manifest["repos"] == ["acme/widgets"]
    assert manifest["tickets"] == 1


def test_the_seed_cli_prints_the_run_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run_dir = tmp_path / "scenarios" / "08-quiet-control"
    report = SeedReport(scenario_id="08-quiet-control", elapsed_s=0.5, run_dir=run_dir)
    monkeypatch.setattr(cli, "seed", lambda scenario: report)

    assert cli.main(["seed", "08-quiet-control"]) == 0

    out = capsys.readouterr().out
    assert "seeded 08-quiet-control in 0.50s" in out
    assert f"run root: {run_dir}" in out


def test_the_verify_cli_has_no_all_flag() -> None:
    """Finding 7: only the last seeded scenario can be in place, so --all is gone."""
    with pytest.raises(SystemExit):
        cli.main(["verify", "--all"])


def test_the_seed_cli_reports_a_seed_error_as_one_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Finding 6: a failed step prints its name, not a traceback."""

    def explode(scenario: object) -> SeedReport:
        raise SeedError("postgres preflight: the support schema is missing ['customers']")

    monkeypatch.setattr(cli, "seed", explode)

    assert cli.main(["seed", "08-quiet-control"]) == 2

    captured = capsys.readouterr()
    assert captured.err.startswith("error: postgres preflight")
    assert "Traceback" not in captured.err


def test_the_compose_mount_and_graph_path_agree_with_the_seeder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding 1: the mount source and WARRANT_GRAPH_DB name the seeder's own file.

    A worktree's `make up` mounts `${WARRANT_RUNS_HOST_DIR}`, which the Makefile
    exports as an absolute main-checkout path, and the gateway opens
    `/app/runs/graph/warrant.db` through it. Both have to land on
    `default_graph_db()`, or verify passes green against a graph the gateway
    never reads.
    """
    monkeypatch.delenv("WARRANT_GRAPH_DB", raising=False)
    monkeypatch.delenv("WARRANT_RUNS_DIR", raising=False)
    monkeypatch.delenv("WARRANT_RUNS_HOST_DIR", raising=False)
    compose = yaml.safe_load((REPO / "compose.yml").read_text(encoding="utf-8"))
    warrant = compose["services"]["warrant"]

    mount = next(volume for volume in warrant["volumes"] if volume.endswith(":/app/runs"))
    source = mount[: -len(":/app/runs")]
    if source.startswith("${"):
        name, default = source[2:-1].split(":-", 1)
        assert name == "WARRANT_RUNS_HOST_DIR"
        host_runs = (main_checkout() / default).resolve()
    else:
        host_runs = Path(source).resolve()
    assert host_runs == (main_checkout() / "runs").resolve()

    graph = warrant["environment"]["WARRANT_GRAPH_DB"]
    assert graph == "/app/runs/graph/warrant.db"
    host_graph = host_runs / Path(graph).relative_to("/app/runs")
    assert host_graph.resolve() == default_graph_db().resolve()


def test_the_makefile_exports_and_creates_the_absolute_mount() -> None:
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")

    assert "WARRANT_RUNS_HOST_DIR" in makefile
    assert "scripts/repo_root.sh" in makefile
    assert "export WARRANT_RUNS_HOST_DIR" in makefile
    assert 'mkdir -p "$(WARRANT_RUNS_HOST_DIR)" "$(WARRANT_RUNS_HOST_DIR)/graph"' in makefile
