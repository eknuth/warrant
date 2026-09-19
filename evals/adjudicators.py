"""Compare the two adjudicators on the same escalations, across repeats.

    uv run python -m evals.adjudicators --run evals/results/w26-jev/.../run \
        --repeats 3

The inputs are a recorded run's own escalate decision lines. Each line carries
the `AuthzRequest` the gateway decided, so the case is reconstructed from the
record and not from a scenario file, and both adjudicators answer exactly the
same request, ledger, subject, and reasons. The subject is fetched from the
running stack with Warrant's own credential, the same fetch the gateway makes.

The table reports, per adjudicator and repeat: the decision, the time box, the
citation and whether it is valid against the ledger, whether the time box is a
value the grant store accepts, whether the decision agrees with the scenario's
truth, the wall latency, the tokens, and the Jev dollar cost. The DeepSeek cost
is left blank because no per-token price for that route is recorded in this
tree, and a blank is honest where a made-up rate would not be.

This is a comparison harness, not a grader. `evals/grade.py` stays the one
scorer of a run, and this module never writes a grade.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean

from warrant.adjudicator import (
    Adjudication,
    AdjudicatorClient,
    EscalationAdjudicator,
    JevAdjudicator,
    subject_key,
)
from warrant.jev import JevClient
from warrant.models import AdjudicationDecision, AuthzRequest, Decision, Verdict
from warrant.subjects import SubjectDoc, SubjectRef, fetch_subject, subject_ref

DECISIONS_NAME = "decisions.jsonl"
METADATA_NAME = "metadata.json"

Fetcher = Callable[[SubjectRef], Awaitable[SubjectDoc | None]]


@dataclass(frozen=True)
class EscalationCase:
    """One escalation, reconstructed from a recorded decision line."""

    label: str
    request: AuthzRequest
    subject: SubjectDoc
    expect: str | None
    """The decision the scenario's truth expects, or None when it names none."""


@dataclass(frozen=True)
class Measurement:
    """One adjudicator's answer to one case on one repeat."""

    case: str
    adjudicator: str
    repeat: int
    decision: str
    time_box_minutes: int | None
    cited_sources: tuple[str, ...]
    cited_subject: str
    citation_valid: bool
    time_box_ok: bool
    agreement: bool | None
    latency_ms: float
    input_tokens: int
    output_tokens: int
    cost_usd: float | None
    reason: str


def decision_name(adjudication: Adjudication) -> str:
    """The decision an attempt reached, with a missing verdict read as a defer."""
    if adjudication.verdict is None:
        return AdjudicationDecision.defer.value
    return adjudication.verdict.decision.value


def citation_valid(case: EscalationCase, adjudication: Adjudication) -> bool:
    """Whether the accepted citation rests on the task's own ledger and subject.

    A defer decides nothing, so it has no citation to check and is taken as it
    is, the same rule `warrant.adjudicator.validate` applies. An approval or a
    denial must name at least one source the ledger holds and the task's own
    subject.
    """
    if adjudication.verdict is None:
        return False
    if adjudication.verdict.decision is AdjudicationDecision.defer:
        return True
    ledger_ids = {source.id for source in case.request.provenance.sources}
    cited = [item for item in adjudication.verdict.cited_sources if item in ledger_ids]
    if not cited:
        return False
    return subject_key(adjudication.verdict.cited_subject) == subject_key(case.subject.id)


def time_box_ok(adjudication: Adjudication) -> bool:
    """Whether an approval carries a time box the grant store accepts."""
    if adjudication.verdict is None:
        return True
    if adjudication.verdict.decision is not AdjudicationDecision.approve:
        return True
    box = adjudication.verdict.time_box_minutes
    return box is not None and 1 <= box <= 60


def measure(
    case: EscalationCase,
    adjudicator: str,
    repeat: int,
    attempt: Adjudication,
) -> Measurement:
    """Reduce one attempt to the row the table prints."""
    verdict = attempt.verdict
    return Measurement(
        case=case.label,
        adjudicator=adjudicator,
        repeat=repeat,
        decision=decision_name(attempt),
        time_box_minutes=verdict.time_box_minutes if verdict is not None else None,
        cited_sources=tuple(verdict.cited_sources) if verdict is not None else (),
        cited_subject=verdict.cited_subject if verdict is not None else "",
        citation_valid=citation_valid(case, attempt),
        time_box_ok=time_box_ok(attempt),
        agreement=((decision_name(attempt) == case.expect) if case.expect is not None else None),
        latency_ms=attempt.latency_ms,
        input_tokens=attempt.input_tokens,
        output_tokens=attempt.output_tokens,
        cost_usd=attempt.cost_usd,
        reason=attempt.reason,
    )


async def compare_cases(
    cases: Sequence[EscalationCase],
    *,
    adjudicators: Sequence[tuple[str, AdjudicatorClient]],
    repeats: int,
) -> list[Measurement]:
    """Run every case through every adjudicator `repeats` times."""
    rows: list[Measurement] = []
    for case in cases:
        for name, adjudicator in adjudicators:
            for repeat in range(1, repeats + 1):
                attempt = await adjudicator.review(
                    case.request, case.request.provenance, case.subject, reasons=()
                )
                rows.append(measure(case, name, repeat, attempt))
    return rows


# -- loading the cases -------------------------------------------------------


def _scenario_id(run_dir: Path) -> str:
    path = Path(run_dir) / METADATA_NAME
    if not path.exists():
        return ""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(data.get("scenario_id") or "") if isinstance(data, dict) else ""


def _run_root(run_dir: Path) -> Path:
    """The directory holding the task records, given a run root or a cell root."""
    run_dir = Path(run_dir)
    nested = run_dir / "run"
    if (nested / METADATA_NAME).exists() or list(nested.glob(f"*/{DECISIONS_NAME}")):
        return nested
    return run_dir


def _task_dirs(run_dir: Path) -> list[Path]:
    run_dir = Path(run_dir)
    if (run_dir / DECISIONS_NAME).exists():
        return [run_dir]
    return sorted(path.parent for path in run_dir.glob(f"*/{DECISIONS_NAME}"))


def _expected(scenario: object, tool: str) -> str | None:
    """The decision the scenario's truth expects, or None when it names none.

    An escalation the truth allows is the one path this names: the scenario's
    expected disposition is `escalate`, and the adjudicator's job on that path is
    the approval a time box makes real. Every other case has no expected answer
    here and is reported as `n/a`.
    """
    truth = getattr(scenario, "truth", None)
    if truth is None or not getattr(truth, "escalation_allowed", False):
        return None
    if getattr(truth, "expected_disposition", {}).get(tool) == "escalate":
        return AdjudicationDecision.approve.value
    return None


async def load_cases(
    run_dir: Path,
    *,
    fetcher: Fetcher = fetch_subject,
) -> list[EscalationCase]:
    """Every distinct escalation in one recorded run, with its fetched subject.

    A call that escalated twice is one case: the inputs are the same call, and a
    second pass through the same adjudicators would only repeat the answer.
    """
    root = _run_root(run_dir)
    scenario_id = _scenario_id(root)
    scenario = None
    if scenario_id:
        try:
            from gen.schema import load_scenario

            scenario = load_scenario(scenario_id)
        except (FileNotFoundError, ValueError):
            scenario = None
    cases: list[EscalationCase] = []
    seen: set[tuple[str, str]] = set()
    for directory in _task_dirs(root):
        for line in (directory / DECISIONS_NAME).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            decision = Decision.model_validate_json(line)
            if decision.verdict is not Verdict.escalate:
                continue
            request = decision.request
            key = (request.chain.task_id, request.tool)
            if key in seen:
                continue
            seen.add(key)
            ref = subject_ref(request.provenance)
            if ref is None:
                continue
            subject = await fetcher(ref)
            if subject is None:
                continue
            cases.append(
                EscalationCase(
                    label=f"{scenario_id} {request.chain.task_id} {request.tool}".strip(),
                    request=request,
                    subject=subject,
                    expect=_expected(scenario, request.tool),
                )
            )
    return cases


# -- the report --------------------------------------------------------------


def _cost_text(value: float | None) -> str:
    return "" if value is None else f"${value:.6f}"


def _rate(values: Sequence[bool]) -> str:
    if not values:
        return "n/a"
    return f"{sum(1 for value in values if value)}/{len(values)}"


def render(rows: Sequence[Measurement]) -> str:
    """The side-by-side markdown table and the per-adjudicator summary."""
    lines = [
        "| case | adjudicator | repeat | decision | time box | cited | citation valid | "
        "time box ok | agreement | latency ms | input tok | output tok | cost |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        agreement = "n/a" if row.agreement is None else str(row.agreement)
        lines.append(
            f"| {row.case} | {row.adjudicator} | {row.repeat} | {row.decision} | "
            f"{row.time_box_minutes if row.time_box_minutes is not None else ''} | "
            f"{', '.join(row.cited_sources)} | "
            f"{'yes' if row.citation_valid else 'no'} | "
            f"{'yes' if row.time_box_ok else 'no'} | {agreement} | {row.latency_ms:.1f} | "
            f"{row.input_tokens} | {row.output_tokens} | {_cost_text(row.cost_usd)} |"
        )
    lines.append("")
    lines.append(
        "| adjudicator | answers | citation valid | time box ok | agreement | "
        "mean latency ms | input tok | cost |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    names = []
    for row in rows:
        if row.adjudicator not in names:
            names.append(row.adjudicator)
    for name in names:
        group = [row for row in rows if row.adjudicator == name]
        cost = sum(row.cost_usd or 0.0 for row in group)
        agreements = [row.agreement for row in group if row.agreement is not None]
        cost_text = f"${cost:.6f}" if any(row.cost_usd is not None for row in group) else ""
        lines.append(
            f"| {name} | {len(group)} | "
            f"{_rate([row.citation_valid for row in group])} | "
            f"{_rate([row.time_box_ok for row in group])} | "
            f"{_rate([bool(value) for value in agreements])} | "
            f"{fmean([row.latency_ms for row in group]):.1f} | "
            f"{sum(row.input_tokens for row in group)} | {cost_text} |"
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evals.adjudicators",
        description="Compare the two adjudicators on the escalations one run recorded.",
    )
    parser.add_argument("--run", type=Path, required=True, help="a recorded run directory")
    parser.add_argument("--repeats", type=int, default=3, help="repeats per case per adjudicator")
    parser.add_argument("--json", action="store_true", help="print the rows as JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.repeats < 1:
        print("--repeats must be at least 1", file=sys.stderr)
        return 2
    cases = asyncio.run(load_cases(args.run))
    if not cases:
        print(f"no escalation in {args.run}", file=sys.stderr)
        return 2
    adjudicators = [
        ("deepseek", EscalationAdjudicator()),
        ("jev", JevAdjudicator(client=JevClient())),
    ]
    rows = asyncio.run(compare_cases(cases, adjudicators=adjudicators, repeats=args.repeats))
    if args.json:
        print(json.dumps([row.__dict__ for row in rows], indent=2, default=str))
    else:
        print(render(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
