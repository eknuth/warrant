"""The decision log: one line per decision, full request inlined, round-trippable."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from warrant.engine import CedarEngine
from warrant.log import DecisionLog, decisions_path
from warrant.models import AuthzRequest, Decision, Provenance, Source, Tier

MakeRequest = Callable[..., AuthzRequest]
MakePolicies = Callable[..., Path]


def make_engine(policy_dir: Path, decision_log: DecisionLog) -> CedarEngine:
    return CedarEngine(policies_dir=policy_dir, schema_path=None, decision_log=decision_log)


def test_two_decisions_are_two_lines_that_parse_back(
    policy_dir: MakePolicies,
    make_request: MakeRequest,
    decision_log: DecisionLog,
    tmp_path: Path,
) -> None:
    directory = policy_dir('@id("permit-all")\npermit(principal, action, resource);')
    engine = make_engine(directory, decision_log)

    written = [engine.decide(make_request()), engine.decide(make_request(tool="gitea.get_file"))]

    lines = decisions_path(tmp_path / "runs", "task-1").read_text().splitlines()
    assert len(lines) == 2
    parsed = [Decision.model_validate_json(line) for line in lines]
    assert [decision.verdict.value for decision in parsed] == ["allow", "allow"]
    assert [decision.request.tool for decision in parsed] == ["gitea.search_code", "gitea.get_file"]
    assert parsed == written


def test_a_decision_line_carries_the_full_chain_and_provenance(
    policy_dir: MakePolicies,
    make_request: MakeRequest,
    decision_log: DecisionLog,
    tmp_path: Path,
) -> None:
    directory = policy_dir('@id("permit-all")\npermit(principal, action, resource);')
    engine = make_engine(directory, decision_log)
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

    engine.decide(make_request(provenance=provenance))

    line = decisions_path(tmp_path / "runs", "task-1").read_text().splitlines()[0]
    parsed = Decision.model_validate_json(line)
    # Every field the acceptance criterion names is asserted, not only the easy
    # ones: a dropped digest or resource would parse back green while the grader
    # lost the ability to reconstruct the call.
    assert parsed.request.chain.sub == "h-alice"
    assert parsed.request.chain.act == "triage-agent"
    assert parsed.request.chain.task_id == "task-1"
    assert parsed.request.chain.scopes == ["read", "write"]
    assert parsed.request.chain.groups == ["engineering"]
    assert parsed.request.tool == "gitea.search_code"
    assert parsed.request.action_kind.value == "read"
    assert parsed.request.resource == "repo-acme-api"
    assert parsed.request.args_digest == "sha256:args"
    assert [source.id for source in parsed.request.provenance.sources] == ["m1"]
    assert [source.digest for source in parsed.request.provenance.sources] == ["d2"]
    assert parsed.request.provenance.min_tier is Tier.external
    assert parsed.request.provenance.has_external is True
    assert parsed.verdict.value == "allow"
    assert parsed.policy_ids == ["permit-all"]
    assert parsed.mode == "full"


def test_no_decision_embeds_a_newline(
    policy_dir: MakePolicies,
    make_request: MakeRequest,
    decision_log: DecisionLog,
    tmp_path: Path,
) -> None:
    directory = policy_dir(
        '@id("forbid-read")\nforbid(principal, action == Action::"gitea.search_code", resource);'
    )
    engine = make_engine(directory, decision_log)

    engine.decide(make_request())

    text = decisions_path(tmp_path / "runs", "task-1").read_text()
    assert text.count("\n") == 1
    assert text.endswith("\n")


def test_reading_an_unknown_task_is_empty(decision_log: DecisionLog) -> None:
    assert decision_log.read("never-seen") == []
