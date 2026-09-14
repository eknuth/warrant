"""The W7 policy set: the shipped table, load-time validation, ids, and the smoke.

The table lives in `warrant/policy_cases.yml` and the harness that runs it in
`warrant/policy_test.py`. This module is the acceptance suite: it runs every
row against the shipped policy directory and the graph in `infra/graph.yml`,
checks that a policy the schema cannot validate stops the load, greps the Cedar
files for the `@id` annotations the decision log reads, and drives the honest
triage request set the W6 smoke ran so a policy regression shows up here.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from warrant.engine import (
    DEFAULT_SCHEMA_PATH,
    CedarEngine,
    PolicyValidationError,
)
from warrant.graph import Graph
from warrant.graph import load as load_graph
from warrant.log import DecisionLog
from warrant.models import ActionKind, AuthzRequest, Chain, Provenance, Source, Tier, Verdict
from warrant.policy_test import (
    PolicyCase,
    build_request,
    load_cases,
    run_case,
)

REPO = Path(__file__).resolve().parents[1]
POLICIES = REPO / "policies"
SEED = REPO / "infra" / "graph.yml"

# The request shape the four split cases share, built by the harness.
TASK_RULE_CASE = "split-task-honest-comment-off-target"
CONTENT_RULE_CASE = "split-content-injected-comment"


def policy_dir_for(path: Path, *policies: str) -> Path:
    """Write Cedar policies into `path` and return it, for a rule subset."""
    path.mkdir(parents=True, exist_ok=True)
    for index, text in enumerate(policies):
        (path / f"{index:02d}_test.cedar").write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def graph_db(tmp_path: Path) -> Any:
    with load_graph(SEED, tmp_path / "warrant.db") as opened:
        yield opened


@pytest.fixture
def engine(graph_db: Graph, decision_log: DecisionLog) -> CedarEngine:
    """The shipped policy set against the committed graph schema."""
    return CedarEngine(policies_dir=POLICIES, graph=graph_db, decision_log=decision_log)


# -- the table ---------------------------------------------------------------


def test_the_table_has_at_least_twenty_cases() -> None:
    assert len(load_cases()) >= 20


def test_the_table_has_two_cases_per_scenario_and_four_split_cases() -> None:
    """Every scenario has an attack shape and an honest twin, plus the split."""
    per_scenario = Counter(case.scenario for case in load_cases())

    for scenario in (str(number) for number in range(1, 9)):
        assert per_scenario[scenario] >= 2, f"scenario {scenario} has {per_scenario[scenario]}"
    assert per_scenario["split"] >= 4


@pytest.mark.parametrize("case", load_cases(), ids=lambda case: case.name)
def test_every_case_matches_its_expected_verdict_and_ids(
    case: PolicyCase, engine: CedarEngine
) -> None:
    result = run_case(case, engine)

    assert result.ok, result.failure()


# -- load-time validation ----------------------------------------------------


def test_the_shipped_policy_set_loads_and_validates(
    graph_db: Graph, decision_log: DecisionLog
) -> None:
    loaded = CedarEngine(policies_dir=POLICIES, graph=graph_db, decision_log=decision_log)

    assert [path.name for path in loaded.policy_files] == [
        "00-baseline.cedar",
        "10-orphan.cedar",
        "20-scope.cedar",
        "30-provenance.cedar",
        "40-exfil.cedar",
        "50-ownership.cedar",
        "90-escalate.cedar",
    ]


def test_a_policy_that_cannot_validate_is_refused_at_load(
    tmp_path: Path, decision_log: DecisionLog
) -> None:
    """An attribute the schema does not declare stops the load, not a decision."""
    directory = policy_dir_for(
        tmp_path / "policies",
        '@id("broken")\npermit(principal, action, resource)\nwhen { context.nope == 1 };',
    )

    with pytest.raises(PolicyValidationError):
        CedarEngine(policies_dir=directory, decision_log=decision_log)


def test_a_policy_that_names_an_unknown_action_is_refused_at_load(
    tmp_path: Path, decision_log: DecisionLog
) -> None:
    """The action surface is the graph's, so an absent tool name is a load error.

    This is why `40-exfil.cedar` names `mail.send`: the ticket wrote
    `mail.send_reply`, which no tool row declares, and a policy that names it
    would fail validation here rather than refuse anything.
    """
    directory = policy_dir_for(
        tmp_path / "policies",
        '@id("unknown")\npermit(principal, action == Action::"mail.send_reply", resource);',
    )

    with pytest.raises(PolicyValidationError, match="mail.send_reply"):
        CedarEngine(policies_dir=directory, decision_log=decision_log)


def test_the_committed_schema_is_used_by_default(tmp_path: Path, decision_log: DecisionLog) -> None:
    directory = policy_dir_for(
        tmp_path / "policies",
        '@id("ok")\npermit(principal, action == Action::"gitea.get_issue", resource);',
    )

    loaded = CedarEngine(policies_dir=directory, decision_log=decision_log)

    assert loaded.schema_path == DEFAULT_SCHEMA_PATH


# -- the annotations the decision log reads ----------------------------------

# `@id("...")` sits on the line before the rule it names, and each rule runs to
# the next semicolon. The engine reads the annotation as the policy id, so a
# forbid without one logs its own source text instead of a name a reader can
# look up.
_ID = re.compile(r'^@id\("([^"]+)"\)$')


def _policy_rules(text: str) -> list[tuple[str | None, str, str]]:
    """Every rule in one policy file as (annotation, keyword, rule text)."""
    lines = text.splitlines()
    rules: list[tuple[str | None, str, str]] = []
    pending: str | None = None
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        annotation = _ID.match(stripped)
        if annotation:
            pending = annotation.group(1)
            index += 1
            continue
        if stripped.startswith(("permit(", "forbid(")):
            keyword = stripped.split("(", 1)[0]
            chunk = [stripped]
            while not chunk[-1].rstrip().endswith(";"):
                index += 1
                chunk.append(lines[index].strip())
            rules.append((pending, keyword, " ".join(chunk)))
            pending = None
        index += 1
    return rules


def _policy_files() -> list[Path]:
    return sorted(POLICIES.glob("*.cedar"))


def test_every_forbid_carries_an_id() -> None:
    missing = [
        f"{path.name}: {rule_text[:70]}"
        for path in _policy_files()
        for annotation, keyword, rule_text in _policy_rules(path.read_text(encoding="utf-8"))
        if keyword == "forbid" and annotation is None
    ]

    assert not missing, missing


def test_every_escalate_permit_carries_an_id() -> None:
    """The engine returns the escalate permit's id as the reason for escalate."""
    missing = [
        f"{path.name}: {rule_text[:70]}"
        for path in _policy_files()
        for annotation, keyword, rule_text in _policy_rules(path.read_text(encoding="utf-8"))
        if keyword == "permit" and 'Action::"escalate"' in rule_text and annotation is None
    ]

    assert not missing, missing


def test_every_id_is_unique() -> None:
    ids = [
        annotation
        for path in _policy_files()
        for annotation, _keyword, _rule_text in _policy_rules(path.read_text(encoding="utf-8"))
        if annotation is not None
    ]

    assert len(ids) == len(set(ids)), sorted(id_ for id_ in ids if ids.count(id_) > 1)


def test_the_grep_finds_the_rules_it_is_meant_to_check() -> None:
    """A guard on the guard: a parser that found nothing would pass the above."""
    rules = [
        rule for path in _policy_files() for rule in _policy_rules(path.read_text(encoding="utf-8"))
    ]

    assert len([rule for rule in rules if rule[1] == "forbid"]) == 7
    assert len([rule for rule in rules if rule[1] == "permit"]) == 2


# -- the task rule against the content rule ----------------------------------


def test_the_content_rule_allows_what_the_task_rule_denies(
    graph_db: Graph, tmp_path: Path, decision_log: DecisionLog
) -> None:
    """The two provenance rules are separable, and the table says which is which.

    The split case has an external read and a write that leaves the named
    target, and no overlap with external text. Only the task rule can see it, so
    with the content rule alone the call is allowed and with the task rule alone
    it is denied. That is what "allowed under content, denied under task" means.
    """
    baseline = (POLICIES / "00-baseline.cedar").read_text(encoding="utf-8")
    content_rule = (
        '@id("tainted-content")\n'
        "forbid(principal, action, resource)\n"
        'when { (action in Action::"write" || action in Action::"send") &&\n'
        "context.provenance.overlapExternal };"
    )
    task_rule = (
        '@id("tainted-write")\n'
        "forbid(principal, action, resource)\n"
        'when { (action in Action::"write" || action in Action::"send") &&\n'
        "context.provenance.hasExternal && context.targetOutsideTask };"
    )
    case = next(case for case in load_cases() if case.name == TASK_RULE_CASE)
    request = build_request(case.request, case.name)

    content_only = CedarEngine(
        policies_dir=policy_dir_for(tmp_path / "content", baseline, content_rule),
        graph=graph_db,
        decision_log=decision_log,
    )
    task_only = CedarEngine(
        policies_dir=policy_dir_for(tmp_path / "task", baseline, task_rule),
        graph=graph_db,
        decision_log=decision_log,
    )

    allowed = content_only.decide(request)
    denied = task_only.decide(request)

    assert allowed.verdict is Verdict.allow, allowed.reasons
    assert denied.verdict is Verdict.deny
    assert denied.policy_ids == ["tainted-write"]


def test_the_content_rule_alone_denies_the_injected_comment(
    graph_db: Graph, tmp_path: Path, decision_log: DecisionLog
) -> None:
    """The mirror of the split: the task rule misses the on-target injection."""
    baseline = (POLICIES / "00-baseline.cedar").read_text(encoding="utf-8")
    content_rule = (
        '@id("tainted-content")\n'
        "forbid(principal, action, resource)\n"
        'when { (action in Action::"write" || action in Action::"send") &&\n'
        "context.provenance.overlapExternal };"
    )
    task_rule = (
        '@id("tainted-write")\n'
        "forbid(principal, action, resource)\n"
        'when { (action in Action::"write" || action in Action::"send") &&\n'
        "context.provenance.hasExternal && context.targetOutsideTask };"
    )
    case = next(case for case in load_cases() if case.name == CONTENT_RULE_CASE)
    request = build_request(case.request, case.name)

    content_only = CedarEngine(
        policies_dir=policy_dir_for(tmp_path / "content", baseline, content_rule),
        graph=graph_db,
        decision_log=decision_log,
    )
    task_only = CedarEngine(
        policies_dir=policy_dir_for(tmp_path / "task", baseline, task_rule),
        graph=graph_db,
        decision_log=decision_log,
    )

    denied = content_only.decide(request)
    missed = task_only.decide(request)

    assert denied.verdict is Verdict.deny
    assert denied.policy_ids == ["tainted-content"]
    assert missed.verdict is Verdict.allow, "the target rule cannot see this one"


# -- the human's entitlements ------------------------------------------------


def test_the_human_entitlement_not_the_agent_owner_decides(
    graph_db: Graph, tmp_path: Path, decision_log: DecisionLog
) -> None:
    """Ed's scope-collapse rule, isolated from the rest of the policy set.

    The permit reads only `context.onBehalfOf.entitledTools`. `triage-agent`
    holds `gitea.get_issue`, so a call by its owner is permitted. The same agent
    invoked by somebody else is not, because that person's entitlements come
    from the agents they own, not from the agent's owner.
    """
    directory = policy_dir_for(
        tmp_path / "policies",
        '@id("entitled")\npermit(principal, action, resource)\n'
        "when { context.onBehalfOf.entitledTools.contains(context.tool) };",
    )
    loaded = CedarEngine(policies_dir=directory, graph=graph_db, decision_log=decision_log)

    owner = loaded.decide(
        _request(
            sub="h-alice", act="triage-agent", tool="gitea.get_issue", resource="repo-acme-api"
        )
    )
    deputy = loaded.decide(
        _request(sub="h-bob", act="triage-agent", tool="gitea.get_issue", resource="repo-acme-api")
    )

    assert owner.verdict is Verdict.allow
    assert deputy.verdict is Verdict.deny, "the agent's owner is not the human in sub"


# -- the W6 smoke, at the engine ---------------------------------------------


def _request(
    *,
    sub: str,
    act: str,
    tool: str,
    resource: str,
    action_kind: ActionKind | None = None,
    provenance: Provenance | None = None,
    scopes: list[str] | None = None,
    groups: list[str] | None = None,
    **overrides: Any,
) -> AuthzRequest:
    chain = Chain(
        sub=sub,
        act=act,
        task_id="task-w6-smoke",
        scopes=scopes if scopes is not None else ["gitea:read", "gitea:write"],
        groups=groups if groups is not None else ["owners"],
        token_exp=datetime(2030, 1, 1, tzinfo=UTC),
    )
    data: dict[str, Any] = {
        "chain": chain,
        "tool": tool,
        "action_kind": action_kind or ActionKind.read,
        "resource": resource,
        "args_digest": "sha256:smoke",
        "provenance": provenance or Provenance(task_id=chain.task_id),
        "ts": datetime(2026, 9, 14, 12, 0, tzinfo=UTC),
    }
    data.update(overrides)
    return AuthzRequest.model_validate(data)


def test_the_honest_triage_smoke_is_allowed_under_the_shipped_set(
    graph_db: Graph, engine: CedarEngine
) -> None:
    """The W6 smoke's request set, at the engine, with no false denial.

    The task reads the issue queue, including one external comment, and then
    writes on the named target. Every call is in the triage agent's allowlist
    and in the token's scopes, so every verdict is allow. The live smoke run
    needs the stack and is not reproduced here.

    The external comment is deliberate: it makes the task read as tainted, and
    the honest flow has to survive that because the write stays on the target
    and carries none of the external text.
    """
    provenance = Provenance(
        task_id="task-w6-smoke",
        sources=[
            Source(
                system="gitea",
                kind="issue",
                id="issue-widgets-1",
                author="alice",
                author_tier=Tier.owner,
                digest="sha256:issue",
            ),
            Source(
                system="gitea",
                kind="issue_comment",
                id="comment-widgets-1",
                author="carol",
                author_tier=Tier.member,
                digest="sha256:comment",
            ),
            Source(
                system="gitea",
                kind="issue_comment",
                id="comment-stranger-1",
                author="mallory",
                author_tier=Tier.external,
                digest="sha256:external",
            ),
        ],
    )
    calls: list[tuple[str, ActionKind, str]] = [
        ("gitea.list_repos", ActionKind.read, "repo-acme-api"),
        ("gitea.list_issues", ActionKind.read, "repo-acme-api"),
        ("gitea.get_issue", ActionKind.read, "repo-acme-api"),
        ("gitea.get_file", ActionKind.read, "repo-acme-widgets"),
        ("gitea.search_code", ActionKind.read, "repo-acme-widgets"),
        ("gitea.create_issue_comment", ActionKind.write, "repo-acme-api"),
        ("gitea.create_branch", ActionKind.write, "repo-acme-api"),
        ("gitea.commit_file", ActionKind.write, "repo-acme-widgets"),
        ("gitea.open_pull_request", ActionKind.write, "repo-acme-api"),
    ]

    decisions = [
        engine.decide(
            _request(
                sub="h-alice",
                act="triage-agent",
                tool=tool,
                resource=resource,
                action_kind=kind,
                provenance=provenance,
                target_outside_task=False,
                overlap_external=False,
                args_touch_secret=False,
            )
        )
        for tool, kind, resource in calls
    ]

    denials = [
        (call, decision.verdict.value, decision.policy_ids, decision.reasons)
        for call, decision in zip(calls, decisions, strict=True)
        if decision.verdict is not Verdict.allow
    ]
    assert not denials, denials


def test_ownership_does_not_let_one_person_drive_anothers_agent(
    graph_db: Graph, tmp_path: Path, decision_log: DecisionLog
) -> None:
    """Ownership needs the same human to own the agent and the resource.

    The first version of the shipped baseline's ownership branch matched the
    resource owner alone, so one person could invoke another person's agent
    against their own property and reach a tool that agent's allowlist never
    carried. This is the confused deputy the policy set exists to refuse.

    Both halves are asserted: the shipped set refuses it, and a permit with the
    old shape allows it, so the test fails if the branch is ever widened back.
    """
    # `triage-agent` is alice's, and `mailbox-support` is bob's. Bob invokes
    # alice's agent against his own mailbox, reaching a tool that agent does not
    # hold.
    deputy = _request(
        sub="h-bob", act="triage-agent", tool="mail.search", resource="mailbox-support"
    )
    shipped = CedarEngine(policies_dir=POLICIES, graph=graph_db, decision_log=decision_log).decide(
        deputy
    )

    wide = policy_dir_for(
        tmp_path / "wide",
        '@id("wide")\npermit(principal, action, resource)\n'
        "when { resource.owner == context.onBehalfOf };",
    )
    old_shape = CedarEngine(policies_dir=wide, graph=graph_db, decision_log=decision_log).decide(
        deputy
    )

    assert shipped.verdict is Verdict.deny, "the shipped set refuses the deputy"
    assert old_shape.verdict is Verdict.allow, "the widened shape it replaced did not"
