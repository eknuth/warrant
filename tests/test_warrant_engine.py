"""The Cedar adapter: mapped fields, the default deny, and the two-pass escalate."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import cedarpy
import pytest

from warrant.engine import DEFAULT_SCHEMA_PATH, CedarEngine
from warrant.graph import load as load_graph
from warrant.log import DecisionLog
from warrant.models import Chain, Provenance, Source, Tier, Verdict

REPO = Path(__file__).resolve().parents[1]
SEED = REPO / "infra" / "graph.yml"


@pytest.fixture
def graph_db(tmp_path: Path) -> Any:
    with load_graph(SEED, tmp_path / "warrant.db") as opened:
        yield opened


def engine_for(directory: Path, decision_log: DecisionLog, **kwargs: Any) -> CedarEngine:
    return CedarEngine(policies_dir=directory, decision_log=decision_log, **kwargs)


def test_a_trivial_permit_allows(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    directory = policy_dir('@id("permit-all")\npermit(principal, action, resource);')

    decision = engine_for(directory, decision_log, schema_path=None).decide(make_request())

    assert decision.verdict is Verdict.allow
    assert decision.policy_ids == ["permit-all"]


def test_a_trivial_forbid_denies(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    directory = policy_dir('@id("forbid-all")\nforbid(principal, action, resource);')

    decision = engine_for(directory, decision_log, schema_path=None).decide(make_request())

    assert decision.verdict is Verdict.deny
    assert decision.policy_ids == ["forbid-all"]


def test_an_empty_policy_set_denies(
    make_request: Any, decision_log: DecisionLog, tmp_path: Path
) -> None:
    """Cedar's default is deny, so an engine with no policies permits nothing."""
    empty = tmp_path / "policies"
    empty.mkdir()

    decision = engine_for(empty, decision_log, schema_path=None).decide(make_request())

    assert decision.verdict is Verdict.deny
    assert decision.policy_ids == []


def test_the_shipped_policy_set_denies_by_default(
    make_request: Any, decision_log: DecisionLog
) -> None:
    """The shipped tree permits nothing until W7 writes the policies."""
    decision = CedarEngine(decision_log=decision_log).decide(make_request())

    assert decision.verdict is Verdict.deny
    assert decision.policy_ids == []


def test_the_shipped_schema_parses_and_validates_the_mapping(policy_dir: Any) -> None:
    schema = DEFAULT_SCHEMA_PATH.read_text()
    policy = (
        '@id("p")\npermit(principal, action == Action::"read", resource)\n'
        "when { context.provenance.hasExternal && principal.allowedTools.contains(context.tool) };"
    )

    result = cedarpy.validate_policies(policy, schema)

    assert result.validation_passed, result.errors


def test_a_missing_policies_directory_fails_loudly(
    make_request: Any, decision_log: DecisionLog, tmp_path: Path
) -> None:
    with pytest.raises(FileNotFoundError):
        engine_for(tmp_path / "absent", decision_log)


def test_the_trivial_permit_still_evaluates_against_the_shipped_schema(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    directory = policy_dir('@id("permit-all")\npermit(principal, action, resource);')

    decision = engine_for(directory, decision_log, schema_path=DEFAULT_SCHEMA_PATH).decide(
        make_request()
    )

    assert decision.verdict is Verdict.allow


def test_external_provenance_is_visible_to_cedar_as_true(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """`context.provenance.hasExternal` is the attribute a policy forbids on."""
    directory = policy_dir(
        '@id("permit-read")\npermit(principal, action == Action::"read", resource);',
        '@id("forbid-external")\nforbid(principal, action == Action::"read", resource)\n'
        "when { context.provenance.hasExternal };",
    )
    engine = engine_for(directory, decision_log, schema_path=None)
    external = Provenance(
        task_id="task-1",
        sources=[
            Source(
                system="gitea",
                kind="issue",
                id="i1",
                author="stranger",
                author_tier=Tier.external,
                digest="d1",
            )
        ],
    )

    denied = engine.decide(make_request(provenance=external))
    allowed = engine.decide(make_request())

    assert denied.verdict is Verdict.deny
    assert denied.policy_ids == ["forbid-external"]
    assert allowed.verdict is Verdict.allow


def test_a_policy_can_permit_because_the_attribute_is_true(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """The same attribute read positively, so the test is not only about forbid."""
    directory = policy_dir(
        '@id("permit-external")\npermit(principal, action == Action::"read", resource)\n'
        "when { context.provenance.hasExternal };"
    )
    external = Provenance(
        task_id="task-1",
        sources=[
            Source(
                system="mail",
                kind="message",
                id="m1",
                author="stranger",
                author_tier=Tier.external,
                digest="d2",
            )
        ],
    )

    decision = engine_for(directory, decision_log, schema_path=None).decide(
        make_request(provenance=external)
    )

    assert decision.verdict is Verdict.allow
    assert decision.policy_ids == ["permit-external"]


def test_the_escalate_pass_uses_the_tool_from_the_context(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    directory = policy_dir(
        '@id("escalate-search")\npermit(principal, action == Action::"Escalate", resource)\n'
        'when { context.tool == "gitea.search" };'
    )

    decision = engine_for(directory, decision_log, schema_path=None).decide(make_request())

    assert decision.verdict is Verdict.escalate
    assert decision.policy_ids == ["escalate-search"]


def test_a_real_permit_does_not_consult_the_escalate_action(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = policy_dir(
        '@id("permit-read")\npermit(principal, action == Action::"read", resource);',
        '@id("escalate-search")\npermit(principal, action == Action::"Escalate", resource);',
    )
    engine = engine_for(directory, decision_log, schema_path=None)
    actions = count_cedar_actions(monkeypatch)

    decision = engine.decide(make_request())

    assert decision.verdict is Verdict.allow
    assert decision.policy_ids == ["permit-read"]
    assert actions == ["read"]


def test_a_deny_with_an_escalate_permit_escalates(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = policy_dir(
        '@id("forbid-read")\nforbid(principal, action == Action::"read", resource);',
        '@id("escalate-search")\npermit(principal, action == Action::"Escalate", resource)\n'
        'when { context.tool == "gitea.search" };',
    )
    engine = engine_for(directory, decision_log, schema_path=None)
    actions = count_cedar_actions(monkeypatch)

    decision = engine.decide(make_request())

    assert decision.verdict is Verdict.escalate
    assert decision.policy_ids == ["escalate-search"]
    assert actions == ["read", "Escalate"]


def test_a_deny_without_an_escalate_permit_stays_a_deny(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = policy_dir(
        '@id("forbid-read")\nforbid(principal, action == Action::"read", resource);'
    )
    engine = engine_for(directory, decision_log, schema_path=None)
    actions = count_cedar_actions(monkeypatch)

    decision = engine.decide(make_request())

    assert decision.verdict is Verdict.deny
    assert decision.policy_ids == ["forbid-read"]
    assert actions == ["read", "Escalate"]


def test_a_forbid_that_matches_every_action_also_forbids_escalation(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """Cedar's forbid beats every permit, including the escalate permit."""
    directory = policy_dir(
        '@id("forbid-all")\nforbid(principal, action, resource);',
        '@id("escalate-search")\npermit(principal, action == Action::"Escalate", resource);',
    )

    decision = engine_for(directory, decision_log, schema_path=None).decide(make_request())

    assert decision.verdict is Verdict.deny
    assert decision.policy_ids == ["forbid-all"]


def test_the_agent_maps_to_principal_with_owner_and_on_behalf_of(
    graph_db: Any, policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """The agent's owner is the graph's, the on-behalf-of is the verified sub."""
    directory = policy_dir(
        '@id("owns-and-acts")\npermit(principal, action == Action::"read", resource)\n'
        'when { principal.owner == Human::"h-alice" && principal.onBehalfOf == Human::"h-bob" };'
    )
    chain = Chain(
        sub="h-bob",
        act="agent-triage",
        task_id="task-1",
        scopes=["read"],
        groups=["support"],
        token_exp=datetime(2030, 1, 1, tzinfo=UTC),
    )
    engine = engine_for(directory, decision_log, schema_path=DEFAULT_SCHEMA_PATH, graph=graph_db)

    decision = engine.decide(make_request(chain=chain))

    assert decision.verdict is Verdict.allow
    assert decision.policy_ids == ["owns-and-acts"]


def test_on_behalf_of_is_not_the_owner(
    graph_db: Any, policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    directory = policy_dir(
        '@id("wrong-human")\npermit(principal, action == Action::"read", resource)\n'
        'when { principal.onBehalfOf == Human::"h-alice" };'
    )
    chain = Chain(
        sub="h-bob",
        act="agent-triage",
        task_id="task-1",
        scopes=["read"],
        groups=["support"],
        token_exp=datetime(2030, 1, 1, tzinfo=UTC),
    )

    decision = engine_for(
        directory, decision_log, schema_path=DEFAULT_SCHEMA_PATH, graph=graph_db
    ).decide(make_request(chain=chain))

    assert decision.verdict is Verdict.deny


def test_allowed_tools_and_justification_reach_the_policy(
    graph_db: Any, policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    directory = policy_dir(
        '@id("tool-and-justification")\npermit(principal, action == Action::"read", resource)\n'
        "when { principal.allowedTools.contains(context.tool) && context.justificationValid };"
    )
    engine = engine_for(directory, decision_log, schema_path=DEFAULT_SCHEMA_PATH, graph=graph_db)

    allowed = engine.decide(make_request())
    other_tool = engine.decide(make_request(tool="mail.send"))

    assert allowed.verdict is Verdict.allow
    assert other_tool.verdict is Verdict.deny


def test_a_missing_justification_is_not_valid(
    graph_db: Any, policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    directory = policy_dir(
        '@id("justified")\npermit(principal, action == Action::"read", resource)\n'
        "when { context.justificationValid };"
    )
    chain = Chain(
        sub="h-carol",
        act="agent-audit",
        task_id="task-1",
        scopes=["read"],
        groups=["engineering"],
        token_exp=datetime(2030, 1, 1, tzinfo=UTC),
    )

    decision = engine_for(
        directory, decision_log, schema_path=DEFAULT_SCHEMA_PATH, graph=graph_db
    ).decide(make_request(chain=chain))

    assert decision.verdict is Verdict.deny


def test_an_expired_justification_is_not_valid(
    graph_db: Any, policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    directory = policy_dir(
        '@id("justified")\npermit(principal, action == Action::"read", resource)\n'
        "when { context.justificationValid };"
    )
    chain = Chain(
        sub="h-bob",
        act="agent-support",
        task_id="task-1",
        scopes=["read"],
        groups=["support"],
        token_exp=datetime(2030, 1, 1, tzinfo=UTC),
    )
    expired = datetime(2027, 1, 2, tzinfo=UTC)

    decision = engine_for(
        directory, decision_log, schema_path=DEFAULT_SCHEMA_PATH, graph=graph_db
    ).decide(make_request(chain=chain, ts=expired))

    assert decision.verdict is Verdict.deny


def test_decide_writes_one_decision_line(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    directory = policy_dir('@id("permit-all")\npermit(principal, action, resource);')
    engine = engine_for(directory, decision_log, schema_path=None)

    decision = engine.decide(make_request())

    assert decision_log.read("task-1") == [decision]


def test_explain_says_why_without_writing_a_decision(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    directory = policy_dir(
        '@id("forbid-read")\nforbid(principal, action == Action::"read", resource);'
    )
    engine = engine_for(directory, decision_log, schema_path=None)

    text = engine.explain(make_request())

    assert "verdict: deny" in text
    assert "forbid-read" in text
    assert "forbid matched: forbid-read" in text
    assert decision_log.read("task-1") == []


def test_explain_shows_the_provenance_summary(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    directory = policy_dir('@id("permit-all")\npermit(principal, action, resource);')
    engine = engine_for(directory, decision_log, schema_path=None)
    provenance = Provenance(
        task_id="task-1",
        sources=[
            Source(
                system="mail",
                kind="message",
                id="m1",
                author="stranger",
                author_tier=Tier.external,
                digest="d2",
            )
        ],
    )

    text = engine.explain(make_request(provenance=provenance))

    assert "sources=1" in text
    assert "min_tier=external" in text
    assert "has_external=true" in text


def count_cedar_actions(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the action id of every cedarpy call the engine makes."""
    actions: list[str] = []
    real = cedarpy.is_authorized

    def counting(request: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
        actions.append(request["action"]["id"])
        return real(request, *args, **kwargs)

    monkeypatch.setattr(cedarpy, "is_authorized", counting)
    return actions


def test_a_request_cedar_cannot_evaluate_denies_without_escalating(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A broken request is a deny, not an escalate: escalation answers a deny."""
    directory = policy_dir(
        '@id("escalate-search")\npermit(principal, action == Action::"Escalate", resource);'
    )
    engine = engine_for(directory, decision_log, schema_path=DEFAULT_SCHEMA_PATH)

    class Broken:
        decision = cedarpy.Decision.NoDecision

        class diagnostics:
            reasons: list[str] = []
            errors = ["broken request"]
            id_annotations_by_reason: dict[str, str] = {}

    monkeypatch.setattr(cedarpy, "is_authorized", lambda *a, **k: Broken())
    decision = engine.decide(make_request())

    assert decision.verdict is Verdict.deny
    assert decision.policy_ids == []
    assert "request could not be evaluated" in decision.reasons
