"""The Cedar adapter: mapped fields, the default deny, and the two-pass escalate."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import cedarpy
import pytest

from warrant.engine import DEFAULT_SCHEMA_PATH, CedarEngine, schema_for
from warrant.graph import Graph
from warrant.graph import load as load_graph
from warrant.log import DecisionLog
from warrant.models import ActionKind, Chain, Provenance, Source, Tier, Verdict

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
        '@id("p")\npermit(principal, action == Action::"gitea.search_code", resource)\n'
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
        '@id("permit-read")\npermit(principal, action == Action::"gitea.search_code", resource);',
        '@id("forbid-external")\n'
        'forbid(principal, action == Action::"gitea.search_code", resource)\n'
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
        '@id("permit-external")\n'
        'permit(principal, action == Action::"gitea.search_code", resource)\n'
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
        '@id("escalate-search")\npermit(principal, action == Action::"escalate", resource)\n'
        'when { context.tool == "gitea.search_code" };'
    )

    decision = engine_for(directory, decision_log, schema_path=None).decide(make_request())

    assert decision.verdict is Verdict.escalate
    assert decision.policy_ids == ["escalate-search"]


def test_a_real_permit_does_not_consult_the_escalate_action(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = policy_dir(
        '@id("permit-read")\npermit(principal, action == Action::"gitea.search_code", resource);',
        '@id("escalate-search")\npermit(principal, action == Action::"escalate", resource);',
    )
    engine = engine_for(directory, decision_log, schema_path=None)
    actions = count_cedar_actions(monkeypatch)

    decision = engine.decide(make_request())

    assert decision.verdict is Verdict.allow
    assert decision.policy_ids == ["permit-read"]
    assert actions == ["gitea.search_code"]


def test_a_deny_with_an_escalate_permit_escalates(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = policy_dir(
        '@id("forbid-read")\nforbid(principal, action == Action::"gitea.search_code", resource);',
        '@id("escalate-search")\npermit(principal, action == Action::"escalate", resource)\n'
        'when { context.tool == "gitea.search_code" };',
    )
    engine = engine_for(directory, decision_log, schema_path=None)
    actions = count_cedar_actions(monkeypatch)

    decision = engine.decide(make_request())

    assert decision.verdict is Verdict.escalate
    # Both the deny that caused the escalation and the escalate permit are in
    # the line. Naming only the permit leaves a reader unable to say why the
    # action needed a human.
    assert decision.policy_ids == ["forbid-read", "escalate-search"]
    assert any("forbid-read" in reason for reason in decision.reasons)
    assert any("escalate-search" in reason for reason in decision.reasons)
    assert actions == ["gitea.search_code", "escalate"]


def test_a_deny_without_an_escalate_permit_stays_a_deny(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = policy_dir(
        '@id("forbid-read")\nforbid(principal, action == Action::"gitea.search_code", resource);'
    )
    engine = engine_for(directory, decision_log, schema_path=None)
    actions = count_cedar_actions(monkeypatch)

    decision = engine.decide(make_request())

    assert decision.verdict is Verdict.deny
    assert decision.policy_ids == ["forbid-read"]
    assert actions == ["gitea.search_code", "escalate"]


def test_a_forbid_that_matches_every_action_also_forbids_escalation(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """Cedar's forbid beats every permit, including the escalate permit."""
    directory = policy_dir(
        '@id("forbid-all")\nforbid(principal, action, resource);',
        '@id("escalate-search")\npermit(principal, action == Action::"escalate", resource);',
    )

    decision = engine_for(directory, decision_log, schema_path=None).decide(make_request())

    assert decision.verdict is Verdict.deny
    assert decision.policy_ids == ["forbid-all"]


def test_the_agent_maps_to_principal_with_owner_and_on_behalf_of(
    graph_db: Any, policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """The agent's owner is the graph's, the on-behalf-of is the verified sub."""
    directory = policy_dir(
        '@id("owns-and-acts")\npermit(principal, action == Action::"gitea.search_code", resource)\n'
        'when { principal.owner == Human::"h-alice" && principal.onBehalfOf == Human::"h-bob" };'
    )
    chain = Chain(
        sub="h-bob",
        act="triage-agent",
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
        '@id("wrong-human")\npermit(principal, action == Action::"gitea.search_code", resource)\n'
        'when { principal.onBehalfOf == Human::"h-alice" };'
    )
    chain = Chain(
        sub="h-bob",
        act="triage-agent",
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
        '@id("tool-and-justification")\n'
        'permit(principal, action == Action::"gitea.search_code", resource)\n'
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
        '@id("justified")\npermit(principal, action == Action::"gitea.search_code", resource)\n'
        "when { context.justificationValid };"
    )
    chain = Chain(
        sub="h-carol",
        act="orphan-agent",
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
        '@id("justified")\npermit(principal, action == Action::"gitea.search_code", resource)\n'
        "when { context.justificationValid };"
    )
    chain = Chain(
        sub="h-bob",
        act="support-agent",
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
        '@id("forbid-read")\nforbid(principal, action == Action::"gitea.search_code", resource);'
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
        '@id("escalate-search")\npermit(principal, action == Action::"escalate", resource);'
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


def test_an_erroring_policy_denies_and_does_not_escalate(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An evaluation error is not a deny a human can answer.

    cedarpy reports an evaluation error as `Decision.Deny` with diagnostics, not
    as `NoDecision`, so keying the escalate guard on the decision alone let an
    erroring policy escalate, and the error reached no field of the Decision.
    """
    directory = policy_dir(
        '@id("broken")\npermit(principal, action == Action::"gitea.search_code", resource)\n'
        "when { context.provenance.minTier > 3 };",
        '@id("escalate-any")\npermit(principal, action == Action::"escalate", resource);',
    )
    engine = engine_for(directory, decision_log, schema_path=None)
    actions = count_cedar_actions(monkeypatch)

    decision = engine.decide(make_request())

    assert decision.verdict is Verdict.deny, "an error must not reach a human as a question"
    assert actions == ["gitea.search_code"], "the escalate pass must not run for an error"
    assert any("error" in reason.lower() for reason in decision.reasons), decision.reasons


def test_an_error_is_recorded_even_when_a_permit_matched(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """A broken policy is invisible in the log if its error is dropped.

    Two permits, one of which errors and one of which matches, used to allow
    with no mention of the error.
    """
    directory = policy_dir(
        '@id("ok")\npermit(principal, action == Action::"gitea.search_code", resource)\n'
        'when { context.tool == "gitea.search_code" };',
        '@id("broken")\npermit(principal, action == Action::"gitea.search_code", resource)\n'
        "when { context.provenance.minTier > 3 };",
    )
    engine = engine_for(directory, decision_log, schema_path=None)

    decision = engine.decide(make_request())

    assert decision.verdict is Verdict.allow
    assert any("evaluation error" in reason for reason in decision.reasons), decision.reasons


def test_a_write_tool_cannot_be_authorized_as_a_read(
    graph_db: Any, policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """The action kind comes from the graph, not from the caller.

    A tool labelled with a cheaper kind would otherwise be authorized by that
    kind's permits. `gitea.create_issue_comment` is a write in the seed and the request
    here asks for a read.
    """
    directory = policy_dir(
        '@id("read-ok")\npermit(principal, action == Action::"gitea.search_code", resource);',
    )
    engine = engine_for(directory, decision_log, schema_path=None, graph=Graph(graph_db.path))

    # `gitea.create_issue_comment` is a write in the seed; the request claims it is a read.
    decision = engine.decide(
        make_request(tool="gitea.create_issue_comment", action_kind=ActionKind.read)
    )

    assert decision.verdict is Verdict.deny, "a write must not be authorized by a read permit"
    assert "graph" in " ".join(decision.reasons)


def test_an_unknown_resource_is_not_owned_by_the_requester(
    graph_db: Any, policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """A resource the graph has never heard of is nobody's, so ownership cannot match."""
    directory = policy_dir(
        '@id("owner-may-read")\n'
        'permit(principal, action == Action::"gitea.search_code", resource)\n'
        "when { resource.owner == principal.owner };",
    )
    engine = engine_for(directory, decision_log, schema_path=None, graph=Graph(graph_db.path))

    decision = engine.decide(make_request(resource="repo-nobody-has-ever-heard-of"))

    # An unknown resource is nobody's, so ownership cannot make it match.
    assert decision.verdict is Verdict.deny


def test_an_agent_the_graph_does_not_know_cannot_claim_ownership(
    chain: Chain, graph_db: Any, policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """An agent with no row has no owner, rather than the person who asked.

    `principal.owner == principal.onBehalfOf` is an ordinary shape for "this
    agent may act for its own owner". With the owner filled in from `sub`, an
    agent the graph has never heard of satisfied it.
    """
    directory = policy_dir(
        '@id("own-agent-read")\n'
        'permit(principal, action == Action::"gitea.search_code", resource)\n'
        "when { principal.owner == principal.onBehalfOf };",
    )
    engine = engine_for(directory, decision_log, schema_path=None, graph=Graph(graph_db.path))
    unknown_agent = Chain(
        sub=chain.sub,
        act="agent-ghost",
        task_id=chain.task_id,
        scopes=list(chain.scopes),
        groups=list(chain.groups),
        token_exp=chain.token_exp,
    )

    decision = engine.decide(make_request(chain=unknown_agent))

    # An unknown agent must not inherit the owner of whoever asked.
    assert decision.verdict is Verdict.deny


def test_an_escalate_permit_for_another_tool_does_not_escalate_this_one(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """The tool scope lives in `context.tool`, so it has to be pinned.

    The ticket's `Escalate::"<tool>"` does not parse, so the tool became a policy
    clause. Without a test, a W7 author who forgets the clause gets an
    all-tools escalate.
    """
    directory = policy_dir(
        '@id("forbid-read")\nforbid(principal, action == Action::"gitea.search_code", resource);',
        '@id("escalate-other")\npermit(principal, action == Action::"escalate", resource)\n'
        'when { context.tool == "gitea.get_file" };',
    )
    engine = engine_for(directory, decision_log, schema_path=None)

    decision = engine.decide(make_request())  # the tool is gitea.search

    assert decision.verdict is Verdict.deny, "an escalate permit for another tool must not match"
    assert decision.policy_ids == ["forbid-read"]


def test_a_decision_names_the_mode_that_produced_it(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """The grader has to attribute a line to an ablation from the record alone."""
    directory = policy_dir("permit(principal, action, resource);")
    engine = engine_for(directory, decision_log, schema_path=None)

    decision = engine.decide(make_request())

    assert decision.mode == "full"
    line = decision_log.read(decision.request.chain.task_id)[0]
    assert line.mode == "full"


def test_the_ticket_forbid_refuses_the_comment_exactly_as_written(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """W6's acceptance criterion 2, with the policy spelled the way it wrote it.

    The criterion names `Action::"gitea.create_issue_comment"` as the action. In
    the three-kind model that named an action no request carried, so the forbid
    was inert and the refusal came from the default deny instead. With one action
    per tool the tool is the action scope, and the reason the agent receives is
    the forbid's own.

    Run against the engine before the change, this policy set returned `allow`
    with `permit matched: permit-write`, which is the defect in one line.
    """
    directory = policy_dir(
        '@id("permit-write")\npermit(principal, action in Action::"write", resource);',
        '@id("forbid-comment")\nforbid(principal, action == '
        'Action::"gitea.create_issue_comment", resource);',
    )
    engine = engine_for(directory, decision_log)

    denied = engine.decide(
        make_request(tool="gitea.create_issue_comment", action_kind=ActionKind.write)
    )
    allowed = engine.decide(make_request(tool="gitea.commit_file", action_kind=ActionKind.write))

    assert denied.verdict is Verdict.deny
    assert denied.policy_ids == ["forbid-comment"], "the forbid fired, not the default deny"
    assert "forbid matched" in denied.reasons[0]
    assert allowed.verdict is Verdict.allow, "the forbid is scoped to one tool"


def test_a_kind_rule_reaches_every_tool_of_that_kind(
    policy_dir: Any, make_request: Any, decision_log: DecisionLog
) -> None:
    """`action in Action::"write"` is the membership the schema generates.

    A rule about a kind has to keep working, because that is how W7 writes the
    scope and taint rules: one rule per kind rather than one per tool.
    """
    directory = policy_dir(
        '@id("permit-write")\npermit(principal, action in Action::"write", resource);'
    )
    engine = engine_for(directory, decision_log)

    for tool in ("gitea.commit_file", "gitea.create_branch", "gitea.open_pull_request"):
        decision = engine.decide(make_request(tool=tool, action_kind=ActionKind.write))

        assert decision.verdict is Verdict.allow, tool

    read = engine.decide(make_request(tool="gitea.get_issue", action_kind=ActionKind.read))

    assert read.verdict is Verdict.deny, "a write permit does not reach a read tool"


def test_the_committed_schema_is_the_one_the_graph_generates(graph_db: Graph) -> None:
    """The committed file is generated, and this is what keeps it current.

    The schema is committed so a reader can see the action surface, and the
    engine generates it from the graph at load. A tool added to `infra/graph.yml`
    without regenerating the file would pass every policy test and fail on a
    deployment that was given the graph, so the two are compared here instead.
    """
    assert json.loads(DEFAULT_SCHEMA_PATH.read_text()) == schema_for(graph_db)
