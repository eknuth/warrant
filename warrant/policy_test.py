"""Run the shipped Cedar policy set against a YAML table of request fixtures.

`tests/test_policies.py` is the acceptance suite; this module is the harness it
drives, and the one a person runs by hand:

    uv run python -m warrant.policy_test

A case is a request fixture plus the verdict and the policy ids it must produce.
The fixture names graph ids (`repo-acme-api`, `table-orders`, `mailbox-support`)
rather than the names a tool call carries, because the engine decides on the id
and this harness builds an `AuthzRequest` directly rather than through the
gateway's name resolution.

An omitted field takes the deny-safe default on `AuthzRequest` or the fixed
default here, so a case only writes what it is about. The four taint and target
fields are W11's, and W7's cases set them directly, which is what lets one table
pin the task rule against the content rule: the same request is one field apart.
"""

from __future__ import annotations

import argparse
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from warrant.engine import CedarEngine
from warrant.graph import load as load_graph
from warrant.log import DecisionLog
from warrant.models import (
    ActionKind,
    AuthzRequest,
    Chain,
    Decision,
    Provenance,
    Source,
    Tier,
)

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES_PATH = PACKAGE_ROOT / "warrant" / "policy_cases.yml"
DEFAULT_SEED = PACKAGE_ROOT / "infra" / "graph.yml"
DEFAULT_POLICIES_DIR = PACKAGE_ROOT / "policies"

# The timestamp every request is evaluated at unless a case overrides it. It is
# fixed so the table's verdicts do not move with the wall clock, and it sits
# before the support agent's justification expires.
DEFAULT_TS = "2026-09-14T12:00:00Z"
DEFAULT_TOKEN_EXP = "2030-01-01T00:00:00Z"
DEFAULT_TASK_ID = "task-policy"
DEFAULT_ARGS_DIGEST = "sha256:args"

# A decision whose reasons carry one of these did not come from a policy, so a
# row may not pass on it whatever the verdict says.
EVALUATION_FAILURE_MARKERS = ("could not be evaluated", "evaluation error")


class CaseFormatError(ValueError):
    """A case in the table that the harness cannot run."""


@dataclass(frozen=True)
class PolicyCase:
    """One row of the table: a request fixture and the decision it must produce."""

    name: str
    scenario: str
    kind: str
    description: str
    request: Mapping[str, Any]
    verdict: str
    ids: tuple[str, ...]


@dataclass(frozen=True)
class CaseResult:
    """One case with the decision the engine actually returned."""

    case: PolicyCase
    decision: Decision

    @property
    def ok(self) -> bool:
        # The ids are compared as a set. Cedar reports the policies that matched
        # as a set, and the engine sorts them for the log, so a case states which
        # ids must be there and not the order they happened to come back in.
        #
        # An evaluation error is a failure even when the verdict and the ids are
        # what the row expects. A request the schema cannot parse denies with no
        # policy id at all, so a row expecting `deny []` would pass on a typo
        # that never reached a policy.
        if self.decision.reasons and any(
            marker in reason
            for reason in self.decision.reasons
            for marker in EVALUATION_FAILURE_MARKERS
        ):
            return False
        return self.decision.verdict.value == self.case.verdict and sorted(
            self.decision.policy_ids
        ) == sorted(self.case.ids)

    def failure(self) -> str:
        return (
            f"{self.case.name}: expected {self.case.verdict} {list(self.case.ids)}, "
            f"got {self.decision.verdict.value} {list(self.decision.policy_ids)}"
            + (f" with reasons {list(self.decision.reasons)}" if self.decision.reasons else "")
        )


def _time(value: Any, field: str, case_name: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise CaseFormatError(f"{case_name}: {field} must be an ISO timestamp, got {value!r}")
    if parsed.tzinfo is None:
        raise CaseFormatError(f"{case_name}: {field} must carry a timezone")
    return parsed


def _sources(raw: Any, case_name: str) -> list[Source]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise CaseFormatError(f"{case_name}: provenance.sources must be a list")
    sources: list[Source] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise CaseFormatError(f"{case_name}: source {index} is not a mapping")
        data = dict(entry)
        try:
            data["author_tier"] = Tier(data["author_tier"])
        except KeyError as error:
            raise CaseFormatError(f"{case_name}: source {index} has no author_tier") from error
        except ValueError as error:
            raise CaseFormatError(f"{case_name}: source {index} has an unknown tier") from error
        sources.append(Source.model_validate(data))
    return sources


def build_request(fixture: Mapping[str, Any], case_name: str = "case") -> AuthzRequest:
    """Build the `AuthzRequest` one case's fixture describes.

    The chain and the provenance are built here rather than declared in full in
    every case, so a row reads as the call it makes and the fields it turns on.
    """
    provenance_raw = fixture.get("provenance") or {}
    if not isinstance(provenance_raw, Mapping):
        raise CaseFormatError(f"{case_name}: provenance must be a mapping")
    task_id = str(fixture.get("task_id", DEFAULT_TASK_ID))
    chain = Chain(
        sub=str(fixture["sub"]),
        act=str(fixture["act"]),
        task_id=task_id,
        scopes=[str(scope) for scope in fixture.get("scopes", [])],
        groups=[str(group) for group in fixture.get("groups", [])],
        token_exp=_time(fixture.get("token_exp", DEFAULT_TOKEN_EXP), "token_exp", case_name),
        incident_id=(str(fixture["incident_id"]) if fixture.get("incident_id") else None),
    )
    provenance = Provenance(
        task_id=task_id, sources=_sources(provenance_raw.get("sources"), case_name)
    )
    data: dict[str, Any] = {
        "chain": chain,
        "tool": str(fixture["tool"]),
        "action_kind": ActionKind(fixture["action_kind"]),
        "resource": str(fixture["resource"]),
        "args_digest": str(fixture.get("args_digest", DEFAULT_ARGS_DIGEST)),
        "provenance": provenance,
        "ts": _time(fixture.get("ts", DEFAULT_TS), "ts", case_name),
        "overlap_sources": {str(source) for source in fixture.get("overlap_sources", [])},
        "overlap_external": bool(fixture.get("overlap_external", False)),
        "args_touch_secret": bool(fixture.get("args_touch_secret", False)),
        "target_outside_task": bool(fixture.get("target_outside_task", False)),
    }
    return AuthzRequest.model_validate(data)


def load_cases(path: Path | str = DEFAULT_CASES_PATH) -> list[PolicyCase]:
    """Load and check the table. A malformed case fails here, by name."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping) or "cases" not in data:
        raise CaseFormatError(f"{path} does not hold a `cases:` list")
    cases: list[PolicyCase] = []
    seen: set[str] = set()
    for index, raw in enumerate(data["cases"]):
        if not isinstance(raw, Mapping):
            raise CaseFormatError(f"{path}: case {index} is not a mapping")
        try:
            name = str(raw["name"])
        except KeyError as error:
            raise CaseFormatError(f"{path}: case {index} has no name") from error
        if name in seen:
            raise CaseFormatError(f"{path}: case {name!r} is declared twice")
        seen.add(name)
        for field in ("request", "expect"):
            if field not in raw:
                raise CaseFormatError(f"{path}: case {name!r} has no {field!r}")
        expect = raw["expect"]
        if not isinstance(expect, Mapping) or "verdict" not in expect:
            raise CaseFormatError(f"{path}: case {name!r} has no expected verdict")
        cases.append(
            PolicyCase(
                name=name,
                scenario=str(raw.get("scenario", "")),
                kind=str(raw.get("kind", "")),
                description=str(raw.get("description", "")),
                request=dict(raw["request"]),
                verdict=str(expect["verdict"]),
                ids=tuple(str(policy_id) for policy_id in expect.get("ids", [])),
            )
        )
    return cases


def run_case(case: PolicyCase, engine: CedarEngine) -> CaseResult:
    """Evaluate one case and pair the decision with it."""
    decision = engine.decide(build_request(case.request, case.name))
    return CaseResult(case=case, decision=decision)


def run_cases(cases: list[PolicyCase], engine: CedarEngine) -> list[CaseResult]:
    return [run_case(case, engine) for case in cases]


def main(argv: list[str] | None = None) -> int:
    """Run the table against the graph in `infra/graph.yml` and report."""
    parser = argparse.ArgumentParser(prog="warrant.policy_test")
    parser.add_argument("--cases", default=str(DEFAULT_CASES_PATH))
    parser.add_argument("--policies", default=str(DEFAULT_POLICIES_DIR))
    parser.add_argument("--seed", default=str(DEFAULT_SEED))
    args = parser.parse_args(argv)

    cases = load_cases(args.cases)
    with tempfile.TemporaryDirectory() as tmp:
        with load_graph(args.seed, Path(tmp) / "warrant.db") as graph:
            engine = CedarEngine(
                policies_dir=args.policies,
                graph=graph,
                decision_log=DecisionLog(Path(tmp) / "runs"),
            )
            results = run_cases(cases, engine)

    failures = [result for result in results if not result.ok]
    for result in results:
        marker = "ok  " if result.ok else "FAIL"
        print(f"{marker} {result.case.name}")
    print(f"{len(results) - len(failures)}/{len(results)} cases passed")
    for result in failures:
        print(result.failure())
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
