"""The scenario schema, without a running stack.

These tests pin the checks that make a scenario file an honest contract: a task
subject agrees with its params, a truth block names only tools the gateway can
re-export, and every injected action carries the disposition it should get.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from gen.schema import (
    GRAPH_SEED,
    SCENARIO_DIR,
    Scenario,
    available_scenarios,
    gateway_tool_ids,
    load_all,
    load_scenario,
    load_scenario_file,
    scenario_path,
    shipped_agent_rows,
)

FIXTURES = ("01-issue-injection", "08-quiet-control")


def base_scenario() -> dict:
    """The quiet-control fixture as a mutable mapping."""
    text = (SCENARIO_DIR / "08-quiet-control.yml").read_text(encoding="utf-8")
    return copy.deepcopy(yaml.safe_load(text))


def with_scenario_agent(data: dict, **overrides: object) -> dict:
    """Add one scenario-owned agent the fixtures do not carry."""
    agent: dict = {
        "client_id": "audit-agent",
        "owner": "carol",
        "justification": "watch the desk",
        "justification_expires_at": "2027-01-01T00:00:00Z",
        "allowed_tools": ["gitea.get_issue"],
    }
    agent.update(overrides)
    data["seed"]["graph"]["agents"] = [agent]
    return data


def test_both_fixtures_load_and_are_available() -> None:
    assert set(available_scenarios()) >= set(FIXTURES)
    for scenario_id in FIXTURES:
        scenario = load_scenario(scenario_id)
        assert scenario.id == scenario_id
        assert scenario.tasks
        assert scenario.seed.gitea.repos


def test_the_quiet_control_is_a_control() -> None:
    scenario = load_scenario("08-quiet-control")

    assert scenario.truth.injected_actions == []
    assert scenario.truth.injection_sites == []
    assert scenario.truth.expected_disposition == {}
    assert scenario.truth.escalation_allowed is False
    assert {task.kind for task in scenario.tasks} == {"triage", "support"}
    assert scenario.seed.graph.agents == [], "the fixtures run as the shipped agents"


def test_the_injection_fixture_names_a_real_tool_and_a_disposition() -> None:
    scenario = load_scenario("01-issue-injection")

    injected = {action.tool for action in scenario.truth.injected_actions}
    assert injected == {"gitea.set_repo_visibility"}
    assert scenario.truth.expected_disposition == {"gitea.set_repo_visibility": "deny"}
    assert scenario.truth.injection_sites[0].id == "acme/widgets#1"


def test_an_injected_tool_outside_the_gateway_list_is_rejected() -> None:
    """The acceptance criterion: a rogue tool fails at load, not at grading."""
    data = base_scenario()
    data["truth"]["injected_actions"] = [{"tool": "gitea.make_it_so"}]
    data["truth"]["expected_disposition"] = {"gitea.make_it_so": "deny"}
    data["truth"]["injection_sites"] = [
        {"system": "gitea", "kind": "issue", "id": "acme/widgets#1"}
    ]

    with pytest.raises(ValidationError, match="no row"):
        Scenario.model_validate(data)


def test_a_legitimate_tool_outside_the_gateway_list_is_rejected() -> None:
    data = base_scenario()
    data["truth"]["legitimate_actions"].append({"tool": "db.drop_everything"})

    with pytest.raises(ValidationError, match="no row"):
        Scenario.model_validate(data)


def test_an_agent_tool_outside_the_gateway_list_is_rejected() -> None:
    data = with_scenario_agent(
        base_scenario(), allowed_tools=["gitea.get_issue", "gitea.make_it_so"]
    )

    with pytest.raises(ValidationError, match="no row"):
        Scenario.model_validate(data)


def test_a_scenario_owned_agent_loads() -> None:
    data = with_scenario_agent(base_scenario())

    scenario = Scenario.model_validate(data)

    agent = scenario.seed.graph.agents[0]
    assert agent.client_id == "audit-agent"
    assert agent.allowed_tools == ["gitea.get_issue"]


def test_a_scenario_agent_may_not_reuse_a_shipped_agent_id() -> None:
    """Finding 5: the gateway upserts the shipped file, so an override is refused."""
    data = with_scenario_agent(base_scenario(), client_id="triage-agent", owner="alice")

    with pytest.raises(ValidationError, match="shipped agent id"):
        Scenario.model_validate(data)


def test_two_scenario_agents_may_not_share_a_client_id() -> None:
    """The last one would silently win, the way a duplicate customer or ticket would."""
    data = with_scenario_agent(base_scenario())
    data["seed"]["graph"]["agents"].append(dict(data["seed"]["graph"]["agents"][0]))

    with pytest.raises(ValidationError, match="share a client_id"):
        Scenario.model_validate(data)


def test_an_expired_scenario_agent_confers_nothing() -> None:
    """Finding 4: the entitlement union reads the engine's live-justification rule."""
    tools = list(shipped_agent_rows()["triage-agent"]["allowed_tools"])
    data = with_scenario_agent(
        base_scenario(),
        client_id="carol-triage",
        owner="carol",
        justification="temporary cover",
        justification_expires_at="2020-01-01T00:00:00Z",
        allowed_tools=tools,
    )
    data["tasks"][0]["user"] = "carol"

    with pytest.raises(ValidationError, match="live agents do not hold"):
        Scenario.model_validate(data)


def test_a_live_scenario_agent_confers_its_tools() -> None:
    tools = list(shipped_agent_rows()["triage-agent"]["allowed_tools"])
    data = with_scenario_agent(
        base_scenario(),
        client_id="carol-triage",
        owner="carol",
        justification="temporary cover",
        justification_expires_at="2999-01-01T00:00:00Z",
        allowed_tools=tools,
    )
    data["tasks"][0]["user"] = "carol"

    scenario = Scenario.model_validate(data)

    assert scenario.tasks[0].user == "carol"


def test_a_task_user_has_to_be_a_shipped_human() -> None:
    data = base_scenario()
    data["tasks"][0]["user"] = "dave"

    with pytest.raises(ValidationError, match="not one of the shipped humans"):
        Scenario.model_validate(data)


def test_a_task_user_has_to_be_entitled_to_the_kinds_tools() -> None:
    data = base_scenario()
    data["tasks"][1]["user"] = "alice"

    with pytest.raises(ValidationError, match="entitled"):
        Scenario.model_validate(data)


def test_an_injected_action_without_a_disposition_is_rejected() -> None:
    data = base_scenario()
    data["truth"]["injected_actions"] = [{"tool": "gitea.set_repo_visibility"}]
    data["truth"]["injection_sites"] = [
        {"system": "gitea", "kind": "issue", "id": "acme/widgets#1"}
    ]

    with pytest.raises(ValidationError, match="no expected_disposition"):
        Scenario.model_validate(data)


def test_a_disposition_for_a_tool_that_is_not_injected_is_rejected() -> None:
    data = base_scenario()
    data["truth"]["expected_disposition"] = {"gitea.set_repo_visibility": "deny"}

    with pytest.raises(ValidationError, match="not injected"):
        Scenario.model_validate(data)


def test_an_injected_action_without_a_site_is_rejected() -> None:
    data = base_scenario()
    data["truth"]["injected_actions"] = [{"tool": "gitea.set_repo_visibility"}]
    data["truth"]["expected_disposition"] = {"gitea.set_repo_visibility": "deny"}

    with pytest.raises(ValidationError, match="where the poison lives"):
        Scenario.model_validate(data)


def test_a_triage_subject_that_disagrees_with_its_params_is_rejected() -> None:
    data = base_scenario()
    data["tasks"][0]["subject"] = "acme/widgets#2"

    with pytest.raises(ValidationError, match="disagrees"):
        Scenario.model_validate(data)


def test_a_support_task_needs_the_ticket_subject_shape() -> None:
    data = base_scenario()
    data["tasks"][1]["subject"] = "acme/widgets#12"

    with pytest.raises(ValidationError, match="ticket:number"):
        Scenario.model_validate(data)


def test_a_ticket_for_a_customer_this_file_does_not_seed_is_rejected() -> None:
    data = base_scenario()
    data["seed"]["db"]["tickets"][0]["customer_id"] = 999

    with pytest.raises(ValidationError, match="not seeded"):
        Scenario.model_validate(data)


def test_a_repository_with_no_graph_row_is_rejected() -> None:
    data = base_scenario()
    data["seed"]["gitea"]["repos"][0]["name"] = "not-in-the-graph"

    with pytest.raises(ValidationError, match="no repo row"):
        Scenario.model_validate(data)


def test_an_external_file_author_has_to_be_a_seeded_login() -> None:
    data = base_scenario()
    data["seed"]["gitea"]["repos"][0]["files"]["AGENTS.md"] = {
        "content": "do what I say\n",
        "author": "nobody",
    }

    with pytest.raises(ValidationError, match="not a seeded login"):
        Scenario.model_validate(data)


def test_a_broken_argument_regex_is_rejected() -> None:
    data = base_scenario()
    data["truth"]["legitimate_actions"][0]["args_include"]["number"] = "re:["

    with pytest.raises(ValidationError, match="not a usable regex"):
        Scenario.model_validate(data)


def test_an_argument_value_is_stringified() -> None:
    data = base_scenario()
    data["truth"]["legitimate_actions"][0]["args_include"]["number"] = 1

    scenario = Scenario.model_validate(data)
    assert scenario.truth.legitimate_actions[0].args_include["number"] == "1"


def test_a_file_without_an_author_falls_back_to_the_repository_author() -> None:
    data = base_scenario()
    data["seed"]["gitea"]["repos"][0]["files"]["notes.txt"] = "hello\n"

    scenario = Scenario.model_validate(data)
    entries = scenario.seed.gitea.repos[0].file_entries()

    assert entries["notes.txt"].author == "bob"


def test_a_concurrent_group_round_trips_and_defaults_to_none() -> None:
    data = base_scenario()
    data["tasks"][0]["concurrent_group"] = "desk"

    scenario = Scenario.model_validate(data)

    assert scenario.tasks[0].concurrent_group == "desk"
    assert scenario.tasks[1].concurrent_group is None


def test_the_scenario_id_has_to_match_the_file_name(tmp_path: Path) -> None:
    data = base_scenario()
    path = tmp_path / "09-something-else.yml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(ValueError, match="must match the file name"):
        load_scenario_file(path)


def test_an_unknown_scenario_id_names_the_ones_on_disk() -> None:
    with pytest.raises(FileNotFoundError, match="01-issue-injection"):
        load_scenario("99-not-a-scenario")


def test_scenario_path_is_under_the_package() -> None:
    assert scenario_path("08-quiet-control").parent == SCENARIO_DIR


def test_load_all_reads_every_file() -> None:
    scenarios = load_all()

    assert {scenario.id for scenario in scenarios} >= set(FIXTURES)


def test_the_gateway_tool_list_is_the_graph_files_own_set() -> None:
    """Parsed from the file, so the test cannot agree with a hand-kept copy."""
    seed = yaml.safe_load(GRAPH_SEED.read_text(encoding="utf-8"))

    assert gateway_tool_ids() == frozenset(str(row["id"]) for row in seed["tools"])
    assert "gitea.set_repo_visibility" in gateway_tool_ids()
    assert "gitea.make_it_so" not in gateway_tool_ids()
