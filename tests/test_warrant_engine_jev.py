"""W24's engine rules: the derived write rule and the jev-only adapter.

The derived rule is deterministic and lives in the engine, so no policy file is
needed to exercise it. The `jev-only` engine is the whole decision, and these
tests pin the mapping and the fail-closed default.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from warrant.engine import DERIVED_POLICY_ID, CedarEngine, JevOnlyEngine
from warrant.log import DecisionLog
from warrant.models import ActionKind, Verdict


def engine_for(directory: Path, decision_log: DecisionLog, **kwargs: Any) -> CedarEngine:
    return CedarEngine(policies_dir=directory, decision_log=decision_log, **kwargs)


@pytest.fixture
def permit_all(policy_dir: Any) -> Path:
    return policy_dir('@id("permit-all")\npermit(principal, action, resource);')


def test_a_derived_write_is_refused(permit_all: Path, make_request: Any, decision_log: Any) -> None:
    request = make_request(action_kind=ActionKind.write, derived=True, tool="gitea.commit_file")

    decision = engine_for(permit_all, decision_log, schema_path=None).decide(request)

    assert decision.verdict is Verdict.deny
    assert decision.policy_ids == [DERIVED_POLICY_ID]


def test_a_derived_send_is_refused(permit_all: Path, make_request: Any, decision_log: Any) -> None:
    request = make_request(action_kind=ActionKind.send, derived=True, tool="mail.send_reply")

    decision = engine_for(permit_all, decision_log, schema_path=None).decide(request)

    assert decision.verdict is Verdict.deny
    assert decision.policy_ids == [DERIVED_POLICY_ID]


def test_a_derived_read_is_not_refused_by_the_derived_rule(
    permit_all: Path, make_request: Any, decision_log: Any
) -> None:
    """The rule is about writes; a read is not a candidate, so Cedar decides it."""
    request = make_request(action_kind=ActionKind.read, derived=True)

    decision = engine_for(permit_all, decision_log, schema_path=None).decide(request)

    assert decision.verdict is Verdict.allow
    assert decision.policy_ids == ["permit-all"]


def test_an_underived_write_is_left_to_cedar(
    permit_all: Path, make_request: Any, decision_log: Any
) -> None:
    request = make_request(action_kind=ActionKind.write, derived=False, tool="gitea.commit_file")

    decision = engine_for(permit_all, decision_log, schema_path=None).decide(request)

    assert decision.verdict is Verdict.allow


def test_jev_only_maps_each_choice(make_request: Any, decision_log: DecisionLog) -> None:
    engine = JevOnlyEngine(decision_log=decision_log)

    assert engine.evaluate(make_request(jev_choice="allow")).verdict is Verdict.allow
    assert engine.evaluate(make_request(jev_choice="deny")).verdict is Verdict.deny
    assert engine.evaluate(make_request(jev_choice="escalate")).verdict is Verdict.escalate


def test_jev_only_names_the_choice_as_its_policy(
    make_request: Any, decision_log: DecisionLog
) -> None:
    engine = JevOnlyEngine(decision_log=decision_log)

    decision = engine.evaluate(make_request(jev_choice="deny"))

    assert decision.policy_ids == ["jev-only:deny"]


def test_jev_only_fails_closed_without_a_choice(
    make_request: Any, decision_log: DecisionLog
) -> None:
    engine = JevOnlyEngine(decision_log=decision_log)

    decision = engine.evaluate(make_request(jev_choice=None))

    assert decision.verdict is Verdict.deny
    assert decision.policy_ids == ["jev-only:no-answer"]


def test_jev_only_appends_when_decided(make_request: Any, decision_log: DecisionLog) -> None:
    engine = JevOnlyEngine(decision_log=decision_log)

    engine.decide(make_request(jev_choice="allow"))

    decisions = decision_log.read("task-1")
    assert len(decisions) == 1
    assert decisions[0].verdict is Verdict.allow
