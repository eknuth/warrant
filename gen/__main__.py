"""The scenario CLI: `seed`, `reset`, and `verify`.

    uv run python -m gen seed 08-quiet-control
    uv run python -m gen reset
    uv run python -m gen verify 08-quiet-control

`--all` runs every scenario file on disk, which is what the fixtures timing
criterion measures. `seed` prints each scenario's elapsed seconds and the total,
so the number in a report can be checked by running the command.
"""

from __future__ import annotations

import argparse
import sys

from .schema import load_all, load_scenario
from .seed import reset, seed, seed_all
from .verify import render, verify, verify_all


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gen",
        description="Seed, reset, and verify the Warrant scenarios.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    seed_parser = sub.add_parser("seed", help="reset, then seed one scenario (or --all)")
    seed_parser.add_argument("scenario_id", nargs="?")
    seed_parser.add_argument("--all", action="store_true", help="seed every scenario file")

    reset_parser = sub.add_parser("reset", help="drop what a scenario owns")
    reset_parser.add_argument(
        "scenario_id",
        nargs="?",
        help="a scenario id, to reload its graph rows too; omitted loads the shipped graph",
    )

    verify_parser = sub.add_parser("verify", help="read one scenario back (or --all)")
    verify_parser.add_argument("scenario_id", nargs="?")
    verify_parser.add_argument("--all", action="store_true", help="verify every scenario file")
    return parser


def _require_target(scenario_id: str | None, everything: bool) -> None:
    if bool(scenario_id) == bool(everything):
        raise SystemExit("name one scenario id or pass --all")


def _run_seed(scenario_id: str | None, everything: bool) -> int:
    _require_target(scenario_id, everything)
    if everything:
        reports = seed_all(load_all())
        for report in reports:
            print(f"seeded {report.scenario_id} in {report.elapsed_s:.2f}s")
        total = sum(report.elapsed_s for report in reports)
        print(f"seeded {len(reports)} scenarios in {total:.2f}s")
        return 0
    assert scenario_id is not None
    report = seed(load_scenario(scenario_id))
    print(f"seeded {report.scenario_id} in {report.elapsed_s:.2f}s")
    return 0


def _run_verify(scenario_id: str | None, everything: bool) -> int:
    _require_target(scenario_id, everything)
    if everything:
        reports = verify_all(load_all())
    else:
        assert scenario_id is not None
        reports = [verify(load_scenario(scenario_id))]
    for report in reports:
        print(render(report))
    return 0 if all(report.ok for report in reports) else 1


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "seed":
        return _run_seed(args.scenario_id, args.all)
    if args.command == "verify":
        return _run_verify(args.scenario_id, args.all)
    scenario = load_scenario(args.scenario_id) if args.scenario_id else None
    reset(scenario)
    print(f"reset {'scenario ' + scenario.id if scenario else 'the stack'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
