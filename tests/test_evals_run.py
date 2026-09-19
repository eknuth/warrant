"""The eval runner's plumbing, tested without a model and without compose.

The cells that need the compose stack are the integration tests W15 runs by
hand; these tests cover the parts a matrix depends on and that a live run would
only exercise slowly: the argument parsing, the cell layout, the dry-run
synthetic grade, the ablation switch's health confirmation, the retry that turns
a provider failure into an error cell, and the header chain `no-exchange` sends.
"""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from agents.loop import no_exchange_headers
from agents.task import Task
from evals import run as run_module
from evals.ablations import ABLATION_NAMES, parse_ablations
from evals.grade import Grade, write_grade
from evals.run import (
    Cell,
    ComposeSwitcher,
    HealthError,
    RunnerError,
    dry_cell,
    jev_totals,
    parse_adjudicator,
    parse_models,
    parse_scenarios,
    regrade_column,
    run_cell,
    run_matrix,
    safe_model_dir,
    task_groups,
    validate_column,
)
from gen.schema import load_scenario
from warrant.config import Mode, chain_from_headers
from warrant.models import ActionKind, AuthzRequest, Chain, Decision, JevCall, Provenance, Verdict

REPO = Path(__file__).resolve().parents[1]
PARKED_HOOK = REPO / ".dsh" / "hooks" / "block_parked_column.py"
PROMPTS = REPO / "agents" / "prompts"


# -- arguments and paths ----------------------------------------------------


def test_parse_scenarios_accepts_all_numbers_and_full_ids() -> None:
    assert parse_scenarios("all") == parse_scenarios(None)
    assert parse_scenarios("08") == ["08-quiet-control"]
    assert parse_scenarios("08,01") == ["08-quiet-control", "01-issue-injection"]
    assert parse_scenarios("08-quiet-control") == ["08-quiet-control"]


def test_parse_scenarios_refuses_an_unknown_name() -> None:
    with pytest.raises(RunnerError):
        parse_scenarios("99")


def test_parse_models_defaults_and_splits() -> None:
    assert parse_models(None) == ["deepseek:deepseek-flash@off"]
    assert parse_models("a,b") == ["a", "b"]


def test_parse_adjudicator_defaults_and_refuses_an_unknown_name() -> None:
    assert parse_adjudicator(None) == "deepseek"
    assert parse_adjudicator("jev") == "jev"
    with pytest.raises(RunnerError, match="unknown adjudicator"):
        parse_adjudicator("other")


def test_validate_column_is_one_component() -> None:
    assert validate_column("smoke", dry_run=False) == "smoke"
    assert validate_column(None, dry_run=True) == "dry-run"
    with pytest.raises(RunnerError):
        validate_column(None, dry_run=False)
    with pytest.raises(RunnerError):
        validate_column("a/b", dry_run=False)
    with pytest.raises(RunnerError):
        validate_column("..", dry_run=False)


def test_safe_model_dir_replaces_path_characters() -> None:
    assert safe_model_dir("deepseek:deepseek-flash@off") == "deepseek_deepseek-flash_off"
    assert "/" not in safe_model_dir("a/b")


def test_cell_layout_is_column_ablation_model_scenario_repeat(tmp_path: Path) -> None:
    cell = Cell(
        column="smoke",
        ablation=parse_ablations("task-taint")[0],
        model="deepseek:deepseek-flash@off",
        scenario_id="08-quiet-control",
        repeat=2,
    )

    assert cell.root(tmp_path) == (
        tmp_path / "smoke" / "task-taint" / "deepseek_deepseek-flash_off" / "08-quiet-control" / "2"
    )


def test_parse_ablations_keeps_the_report_order() -> None:
    names = [ablation.name for ablation in parse_ablations("prompt-only,full")]

    assert names == ["full", "prompt-only"]


def parked_hook() -> Any:
    spec = importlib.util.spec_from_file_location("parked", PARKED_HOOK)
    assert spec and spec.loader
    hook = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hook)
    return hook


def test_ablations_match_the_parked_column_hook() -> None:
    """The hook's live names mirror the runner's, or it blocks the wrong moves."""
    assert tuple(parked_hook().CONFIGS) == ABLATION_NAMES


def test_providers_match_the_parked_column_hook() -> None:
    """The hook's provider names mirror the route table, so a column is live."""
    from agents.providers import ROUTES

    assert tuple(parked_hook().PROVIDERS) == tuple(sorted(ROUTES))


def test_each_ablation_names_its_mode_and_taint() -> None:
    """The acceptance values, pinned so a name cannot drift from its setting."""
    from evals.ablations import ABLATIONS

    assert (ABLATIONS["full"].mode, ABLATIONS["full"].taint) == ("full", "both")
    assert (ABLATIONS["task-taint"].mode, ABLATIONS["task-taint"].taint) == ("full", "task")
    assert (ABLATIONS["content-taint"].mode, ABLATIONS["content-taint"].taint) == (
        "full",
        "content",
    )
    assert (ABLATIONS["jev"].mode, ABLATIONS["jev"].taint) == ("full", "jev")
    assert (ABLATIONS["cascade"].mode, ABLATIONS["cascade"].taint) == ("cascade", "both")
    assert (ABLATIONS["jev-only"].mode, ABLATIONS["jev-only"].taint) == ("jev-only", "both")
    assert ABLATIONS["no-provenance"].mode == "no-provenance"
    assert ABLATIONS["no-exchange"].mode == "no-exchange"
    assert ABLATIONS["prompt-only"].mode == "prompt-only"
    assert ABLATIONS["prompt-only"].hardened_prompt is True
    assert ABLATIONS["full"].hardened_prompt is False


# -- the hardened prompt ----------------------------------------------------


def test_hardened_prompts_are_the_shipped_prompt_plus_the_ignore_section() -> None:
    for kind in ("triage", "support"):
        base = (PROMPTS / f"{kind}.md").read_text(encoding="utf-8")
        hardened = (PROMPTS / f"{kind}.hardened.md").read_text(encoding="utf-8")
        assert hardened.startswith(base)
        assert "What to ignore" in hardened[len(base) :]


# -- the header chain -------------------------------------------------------


def test_no_exchange_headers_carry_the_chain_and_the_incident() -> None:
    task = Task(
        kind="support",
        subject="ticket:42",
        user="alice",
        task_id="task-1",
        agent="incident-agent",
        scopes=["incident_id:INC-42"],
        mode="no-exchange",
        human_id="h-alice",
        groups=["owners"],
        incident_id="INC-42",
    )

    headers = no_exchange_headers(task, "incident-agent")

    assert headers["X-Warrant-Sub"] == "h-alice"
    assert headers["X-Warrant-Act"] == "incident-agent"
    assert headers["X-Warrant-Task-Id"] == "task-1"
    assert headers["X-Warrant-Incident-Id"] == "INC-42"
    assert headers["X-Warrant-Groups"] == "owners"


def test_a_header_chain_records_its_source() -> None:
    chain = chain_from_headers(
        {
            "X-Warrant-Sub": "h-alice",
            "X-Warrant-Act": "triage-agent",
            "X-Warrant-Task-Id": "task-1",
            "X-Warrant-Token-Exp": "4102444800",
        },
        mode=Mode.no_exchange,
    )

    assert chain.source == "header"


# -- grouping ---------------------------------------------------------------


def test_task_groups_put_a_concurrent_group_together_and_the_rest_alone() -> None:
    scenario = load_scenario("07-session-confusion")
    groups = task_groups(scenario.tasks)
    assert [len(group) for group in groups] == [2]

    quiet = load_scenario("08-quiet-control")
    assert [len(group) for group in task_groups(quiet.tasks)] == [1, 1, 1]


# -- the dry run ------------------------------------------------------------


def test_dry_run_writes_the_layout_and_a_grade(tmp_path: Path, monkeypatch: Any) -> None:
    """The acceptance layout, with a synthetic no-op and no model at all."""
    seeded: list[str] = []
    monkeypatch.setattr(run_module, "seed", lambda scenario: seeded.append(scenario.id))
    scenario = load_scenario("08-quiet-control")
    cell = Cell(
        column="dry-run",
        ablation=parse_ablations("full")[0],
        model="deepseek:deepseek-flash@off",
        scenario_id="08-quiet-control",
        repeat=1,
    )

    result = dry_cell(cell, scenario, results_dir=tmp_path)

    root = cell.root(tmp_path)
    assert seeded == ["08-quiet-control"]
    assert result.status == "ok"
    assert (root / "grade.json").is_file()
    assert (root / "state.json").is_file()
    assert (root / "meta.json").is_file()
    assert (root / "run" / "metadata.json").is_file()
    grade = Grade.model_validate_json((root / "grade.json").read_text(encoding="utf-8"))
    assert grade.held is True
    assert grade.ablation == "full"
    assert grade.repeat == 1


def test_regrade_rescores_a_stored_cell_without_a_model(tmp_path: Path, monkeypatch: Any) -> None:
    """A grader change rescoring from the stored run spends nothing."""
    monkeypatch.setattr(run_module, "seed", lambda scenario: None)
    scenario = load_scenario("08-quiet-control")
    cell = Cell(
        column="dry-run",
        ablation=parse_ablations("full")[0],
        model="deepseek:deepseek-flash@off",
        scenario_id="08-quiet-control",
        repeat=1,
    )
    dry_cell(cell, scenario, results_dir=tmp_path)

    results = regrade_column(tmp_path, "dry-run")

    assert len(results) == 1
    assert results[0].grade is not None
    assert results[0].grade.held is True
    assert (tmp_path / "dry-run" / "report.md").is_file()


# -- the switch and the retry ----------------------------------------------


def test_jev_totals_sum_the_calls_on_the_decision_lines(tmp_path: Path) -> None:
    run_dir = tmp_path / "run" / "task-1"
    run_dir.mkdir(parents=True)
    chain = Chain(
        sub="h-alice",
        act="triage-agent",
        task_id="task-1",
        token_exp=datetime(2030, 1, 1, tzinfo=UTC),
    )
    request = AuthzRequest(
        chain=chain,
        tool="gitea.create_issue_comment",
        action_kind=ActionKind.write,
        resource="repo-acme-widgets",
        args_digest="sha256:args",
        provenance=Provenance(task_id="task-1"),
        ts=datetime.now(UTC),
        jev_calls=[
            JevCall(
                rule="derived",
                model="jev-1",
                latency_ms=10.0,
                input_tokens=100,
                output_tokens=5,
                cost_usd=0.0000042,
                probability=0.9,
            ),
            JevCall(
                rule="derived",
                model="jev-1",
                latency_ms=30.0,
                input_tokens=200,
                output_tokens=5,
                cost_usd=0.0000084,
                probability=0.1,
                error="boom",
            ),
        ],
    )
    decision = Decision(verdict=Verdict.deny, request=request, mode="jev")
    escalation_request = AuthzRequest(
        chain=chain,
        tool="gitea.create_issue_comment",
        action_kind=ActionKind.write,
        resource="repo-acme-widgets",
        args_digest="sha256:other",
        provenance=Provenance(task_id="task-1"),
        ts=datetime.now(UTC),
    )
    escalation = Decision(
        verdict=Verdict.escalate,
        request=escalation_request,
        mode="full",
        adjudicator_calls=[
            JevCall(
                rule="adjudicate",
                model="jev-1",
                latency_ms=20.0,
                input_tokens=400,
                output_tokens=4,
                cost_usd=0.0000168,
                choice="approve",
            )
        ],
    )
    (run_dir / "decisions.jsonl").write_text(
        decision.model_dump_json() + "\n" + escalation.model_dump_json() + "\n",
        encoding="utf-8",
    )

    totals = jev_totals(tmp_path / "run")

    assert totals["calls"] == 3
    assert totals["rules"] == {"derived": 2, "adjudicate": 1}
    assert totals["errors"] == 1
    assert totals["input_tokens"] == 700
    assert totals["output_tokens"] == 14
    assert totals["cost_usd"] == pytest.approx(0.0000294)
    assert totals["mean_latency_ms"] == pytest.approx(20.0)


class FakeSwitcher:
    """A switcher that records what it was asked for and answers immediately."""

    def __init__(self) -> None:
        self.applied: list[tuple[str, str]] = []
        self.closed = False

    def build(self) -> None:
        return None

    def apply(self, ablation: Any, *, container_runs_dir: str) -> dict[str, str]:
        self.applied.append((ablation.name, container_runs_dir))
        return {"mode": ablation.mode, "taint": ablation.taint}

    def close(self) -> None:
        self.closed = True


def test_compose_switcher_waits_for_healthz(monkeypatch: Any) -> None:
    """The confirmed mode is what `/healthz` reports, not what was requested."""
    payload = {"status": "ok", "mode": "no-exchange", "taint": "both"}
    switcher = ComposeSwitcher(health_url="http://gateway.test/healthz", timeout_s=5.0)

    class Client:
        def __enter__(self) -> Client:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def get(self, url: str, timeout: float) -> Any:
            return _Response(payload)

    switcher.client_factory = Client  # type: ignore[assignment]
    ablation = parse_ablations("no-exchange")[0]

    confirmed = switcher.wait_for(ablation)

    assert confirmed["mode"] == "no-exchange"


def test_the_override_carries_the_ablation_and_the_cell_run_root(tmp_path: Path) -> None:
    """The per-cell override is what switches the mode and the record root."""
    switcher = ComposeSwitcher(results_dir=tmp_path)
    text = switcher.override_text(
        parse_ablations("no-exchange")[0],
        container_runs_dir="/app/evals/results/smoke/no-exchange/run",
    )
    document = yaml.safe_load(text)
    warrant = document["services"]["warrant"]

    assert warrant["environment"]["WARRANT_MODE"] == "no-exchange"
    assert warrant["environment"]["TAINT"] == "both"
    assert warrant["environment"]["ADJUDICATOR"] == "deepseek"
    assert warrant["environment"]["WARRANT_RUNS_DIR"] == "/app/evals/results/smoke/no-exchange/run"
    assert warrant["environment"]["WARRANT_OIDC_ISSUER"].startswith("http://localhost")
    assert any("/app/evals/results" in volume for volume in warrant["volumes"])


def test_the_override_selects_the_jev_adjudicator(tmp_path: Path) -> None:
    switcher = ComposeSwitcher(results_dir=tmp_path, adjudicator="jev")
    text = switcher.override_text(
        parse_ablations("full")[0],
        container_runs_dir="/app/evals/results/w26/jev/run",
    )
    document = yaml.safe_load(text)

    assert document["services"]["warrant"]["environment"]["ADJUDICATOR"] == "jev"


def test_compose_switcher_waits_for_the_confirmed_adjudicator() -> None:
    payload = {"status": "ok", "mode": "full", "taint": "both", "adjudicator": "deepseek"}
    switcher = ComposeSwitcher(
        health_url="http://gateway.test/healthz", timeout_s=0.1, adjudicator="jev"
    )

    class Client:
        def __enter__(self) -> Client:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def get(self, url: str, timeout: float) -> Any:
            return _Response(payload)

    switcher.client_factory = Client  # type: ignore[assignment]

    with pytest.raises(HealthError):
        switcher.wait_for(parse_ablations("full")[0])


def test_compose_switcher_raises_when_the_mode_never_matches() -> None:
    payload = {"status": "ok", "mode": "full", "taint": "both"}
    switcher = ComposeSwitcher(health_url="http://gateway.test/healthz", timeout_s=0.1)

    class Client:
        def __enter__(self) -> Client:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def get(self, url: str, timeout: float) -> Any:
            return _Response(payload)

    switcher.client_factory = Client  # type: ignore[assignment]

    with pytest.raises(HealthError):
        switcher.wait_for(parse_ablations("no-exchange")[0])


class _Response:
    def __init__(self, payload: dict[str, str]) -> None:
        self._payload = payload

    def json(self) -> dict[str, str]:
        return self._payload


def test_a_provider_error_retries_once_then_records_an_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    seeds: list[str] = []
    monkeypatch.setattr(run_module, "seed", lambda scenario: seeds.append(scenario.id))

    def explode(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(run_module, "run_tasks_sync", explode)
    scenario = load_scenario("08-quiet-control")
    cell = Cell(
        column="smoke",
        ablation=parse_ablations("full")[0],
        model="deepseek:deepseek-flash@off",
        scenario_id="08-quiet-control",
        repeat=1,
    )

    result = run_cell(
        cell,
        scenario,
        switcher=FakeSwitcher(),
        provider=object(),  # type: ignore[arg-type]
        results_dir=tmp_path,
        settings=object(),  # type: ignore[arg-type]
        mcp_url=None,
    )

    assert result.status == "error"
    assert len(seeds) == 2, "the cell has to retry once from a fresh seed"
    assert "provider exploded" in result.error
    assert "provider exploded" in result.meta["traceback"]
    assert not (cell.root(tmp_path) / "grade.json").exists()


def test_the_matrix_continues_after_an_error_cell(tmp_path: Path, monkeypatch: Any) -> None:
    calls: list[str] = []

    def fake_run_cell(cell: Cell, scenario: Any, **kwargs: Any) -> Any:
        calls.append(cell.scenario_id)
        status = "error" if len(calls) == 1 else "ok"
        return run_module.CellResult(
            cell=cell, status=status, error="boom" if status == "error" else ""
        )

    monkeypatch.setattr(run_module, "run_cell", fake_run_cell)
    switcher = FakeSwitcher()

    results = run_matrix(
        scenarios=["08-quiet-control", "01-issue-injection"],
        ablations=parse_ablations("full"),
        models=["deepseek:deepseek-flash@off"],
        repeats=1,
        column="smoke",
        results_dir=tmp_path,
        switcher=switcher,
        provider_factory=lambda spec: object(),  # type: ignore[arg-type,return-value]
        build=False,
    )

    assert calls == ["08-quiet-control", "01-issue-injection"]
    assert [result.status for result in results] == ["error", "ok"]
    assert switcher.closed is True


def test_a_graded_cell_is_skipped_unless_forced(tmp_path: Path, monkeypatch: Any) -> None:
    """The column resumes by default: a grade.json is the marker, force reruns."""
    calls: list[str] = []

    def fake_run_cell(cell: Cell, scenario: Any, **kwargs: Any) -> Any:
        calls.append(cell.scenario_id)
        return run_module.CellResult(cell=cell, status="ok")

    monkeypatch.setattr(run_module, "run_cell", fake_run_cell)
    cell = Cell(
        column="smoke",
        ablation=parse_ablations("full")[0],
        model="qwen-local:qwen3.8:27b@off",
        scenario_id="08-quiet-control",
        repeat=1,
    )
    write_grade(
        Grade(
            scenario_id=cell.scenario_id,
            ablation="full",
            model=cell.model,
            repeat=1,
            score=2,
            held=True,
        ),
        cell.root(tmp_path) / "grade.json",
    )

    def run(*, force: bool) -> list[Any]:
        return run_matrix(
            scenarios=["08-quiet-control"],
            ablations=parse_ablations("full"),
            models=[cell.model],
            repeats=1,
            column="smoke",
            results_dir=tmp_path,
            switcher=FakeSwitcher(),
            provider_factory=lambda spec: object(),  # type: ignore[arg-type,return-value]
            force=force,
            build=False,
        )

    assert run(force=False) == []
    assert calls == []
    assert len(run(force=True)) == 1
    assert calls == ["08-quiet-control"]


def test_meta_json_records_the_confirmed_mode(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(run_module, "seed", lambda scenario: None)
    monkeypatch.setattr(run_module, "run_tasks_sync", lambda *a, **k: [])
    monkeypatch.setattr(run_module, "live_state", lambda scenario: run_module.State())
    monkeypatch.setattr(
        run_module,
        "grade",
        lambda scenario, run_dir, state=None, wall_s=None: Grade(
            scenario_id=scenario.id, score=2, held=True, repeat=1, wall_s=wall_s
        ),
    )
    scenario = load_scenario("08-quiet-control")
    cell = Cell(
        column="smoke",
        ablation=parse_ablations("no-exchange")[0],
        model="deepseek:deepseek-flash@off",
        scenario_id="08-quiet-control",
        repeat=1,
    )

    result = run_cell(
        cell,
        scenario,
        switcher=FakeSwitcher(),
        provider=object(),  # type: ignore[arg-type]
        results_dir=tmp_path,
        settings=object(),  # type: ignore[arg-type]
        mcp_url=None,
    )

    assert result.status == "ok"
    meta = json.loads((cell.root(tmp_path) / "meta.json").read_text(encoding="utf-8"))
    assert meta["confirmed_mode"] == "no-exchange"
    assert meta["confirmed_taint"] == "both"
    assert meta["adjudicator"] == "deepseek"
    assert meta["status"] == "ok"
    assert meta["elapsed_s"] >= 0
    grade = json.loads((cell.root(tmp_path) / "grade.json").read_text(encoding="utf-8"))
    assert grade["wall_s"] is not None
    assert grade["wall_s"] >= 0
