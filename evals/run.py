"""Run the eval matrix: ablations x scenarios x repeats, seeded, graded, reported.

    uv run python -m evals.run --scenarios all --ablations all --repeats 3 \
        --models deepseek:deepseek-flash@off --column <name>
    uv run python -m evals.run --dry-run --scenarios 08 --ablations full --repeats 1
    uv run python -m evals.run --scenarios 08,01 --ablations full --repeats 1 --column smoke

One cell is one ablation, one model, one scenario, and one repeat. For each cell
the runner seeds the scenario with W12 (which resets the org, the database, the
mailbox, and the graph), restarts the Warrant service into the ablation and
waits for `/healthz` to confirm the mode it imported, runs the scenario's tasks
through W4 and W10 (`agents.run_many`, with the tasks that share a
`concurrent_group` run together), snapshots the state W14 grades, and writes a
`grade.json`.

Results live under

    evals/results/<column>/<ablation>/<model>/<scenario>/<repeat>/

holding `run/` (the per-task records the gateway and the agent wrote), the
`state.json` the grade was scored against, the `grade.json`, and a `meta.json`
with the commit, the confirmed mode, the timestamps, and the token counts. The
report is rendered from the column at the end.

Failure handling. A task run that raises is retried once from a fresh seed; a
second failure records the cell as an `error` with the traceback and the matrix
continues. A `GraderInconsistency` stops the run: a denied action whose effect
is in state means the harness or the stack is wrong, and a score computed
through it would be a number on a state nobody can explain.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import traceback
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

import httpx
import yaml

from agents.auth import DevSettings
from agents.loop import Outcome
from agents.providers import Provider, provider_for
from agents.run_many import run_concurrent, run_one
from agents.task import Task
from evals.ablations import Ablation, AblationError, parse_ablations
from evals.grade import Grade, GraderInconsistency, grade, write_grade
from evals.report import report
from evals.state import State, live_state, load_state
from gen.schema import (
    KIND_AGENT,
    Scenario,
    TaskSpec,
    available_scenarios,
    graph_seed_data,
    load_scenario,
    shipped_human_ids,
)
from gen.seed import SeedError, seed
from warrant.graph import Graph
from warrant.models import ActionKind, AuthzRequest, Chain, Decision, Provenance, Verdict

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = Path(__file__).resolve().parent / "results"

# The model the issue and `.env.example` name. W22 adds a second family.
DEFAULT_MODEL = "deepseek:deepseek-flash@off"

# The gateway's published health endpoint. The runner polls it after a restart
# and records the mode and taint the process reports.
HEALTH_URL = "http://localhost:9100/healthz"

# How long to wait for a restarted gateway to answer `/healthz`.
HEALTH_TIMEOUT_S = 120.0

# The run metadata is written by the agent under this name; the spec's cell
# record is `meta.json`. Both are written so `evals.grade` reads the ablation,
# model, and repeat from `run/metadata.json` and a reader gets the fuller cell
# record from `meta.json`.
RUN_METADATA_NAME = "metadata.json"
CELL_META_NAME = "meta.json"
STATE_NAME = "state.json"
GRADE_NAME = "grade.json"
RUN_SUBDIR = "run"

# A tool no scenario's truth names, and not a tool the graph holds. A dry-run
# decision that names it can never be charged as an injected action that ran.
DRY_RUN_TOOL = "dry-run.noop"


class RunnerError(RuntimeError):
    """The runner could not run a cell for a reason the caller should see."""


class HealthError(RunnerError):
    """A restarted gateway never confirmed the mode it was asked for."""


@dataclass(frozen=True)
class Cell:
    """One graded run: an ablation, a model, a scenario, and a repeat."""

    column: str
    ablation: Ablation
    model: str
    scenario_id: str
    repeat: int

    def relative(self, model_dir: str | None = None) -> Path:
        return (
            Path(self.ablation.name)
            / (model_dir or safe_model_dir(self.model))
            / self.scenario_id
            / str(self.repeat)
        )

    def root(self, results_dir: Path = RESULTS_DIR, model_dir: str | None = None) -> Path:
        return Path(results_dir) / self.column / self.relative(model_dir)


def safe_model_dir(spec: str) -> str:
    """A model spec as one safe directory name.

    The spec keeps its identity in `meta.json` and in the `Grade.model` field;
    the directory only has to be unique and safe, so the characters a path
    dislikes become `_`.
    """
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in spec)
    return safe or "model"


def parse_scenarios(value: str | None) -> list[str]:
    """The scenario ids one `--scenarios` value names.

    `all` or an empty value is every scenario on disk. A comma-separated list
    names full ids (`08-quiet-control`) or their number prefix (`08`), which is
    the shorthand the issue and the Makefile use. An unknown name is an error.
    """
    known = available_scenarios()
    if value is None or value.strip() in ("", "all"):
        return known
    requested: list[str] = []
    for raw in value.split(","):
        token = raw.strip()
        if not token:
            continue
        matches = [item for item in known if item == token or item.split("-", 1)[0] == token]
        if not matches:
            raise RunnerError(f"no scenario {token!r}; have: {', '.join(known)}")
        for match in matches:
            if match not in requested:
                requested.append(match)
    return requested


def parse_models(value: str | None) -> list[str]:
    """The model specs one `--models` value names, defaults last."""
    if value is None or not value.strip():
        return [DEFAULT_MODEL]
    return [part.strip() for part in value.split(",") if part.strip()]


def validate_column(name: str | None, *, dry_run: bool) -> str:
    """The column directory name, checked as one path component."""
    if name is None or not name.strip():
        if dry_run:
            return "dry-run"
        raise RunnerError("--column is required for a real run")
    column = name.strip()
    if column in (".", "..") or "/" in column or "\\" in column:
        raise RunnerError(f"column {column!r} is not one path component")
    return column


# -- the ablation switch -----------------------------------------------------


class Switcher(Protocol):
    """What the runner needs to put the gateway into an ablation."""

    def apply(self, ablation: Ablation, *, container_runs_dir: str) -> Mapping[str, str]: ...

    def close(self) -> None: ...


@dataclass
class ComposeSwitcher:
    """Restarts the compose `warrant` service into one ablation.

    The service reads `WARRANT_MODE` and `TAINT` at import, so switching means
    recreating the container, not reloading it. The switch writes a small
    compose override file with the ablation's env and the mounts for the cell's
    run root, then runs `docker compose -f compose.yml -f <override> up`. The
    override is generated per cell under the gitignored results tree, so the
    base `compose.yml` keeps its one-stack defaults and no `.env` value has to
    change to switch a mode.

    The override points the container at the same cell root the host agent
    writes to, which is how one cell's decisions and ledger stop being split
    across two directories, and it sets the expected issuer to the host's
    `localhost` while the container fetches the keys at the internal `keycloak`
    name, which is what lets a host-minted token verify in the container.
    """

    results_dir: Path = RESULTS_DIR
    runs_host_dir: Path = field(default_factory=lambda: REPO_ROOT / "runs")
    compose_file: Path = field(default_factory=lambda: REPO_ROOT / "compose.yml")
    health_url: str = HEALTH_URL
    timeout_s: float = HEALTH_TIMEOUT_S
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run
    client_factory: Callable[[], httpx.Client] = httpx.Client

    def override_path(self) -> Path:
        return Path(self.results_dir) / ".compose-override.yml"

    def override_text(self, ablation: Ablation, *, container_runs_dir: str) -> str:
        """The per-cell compose override as YAML.

        Absolute bind sources, so the override can live anywhere and still
        mount the checkout's runs tree and results tree.
        """
        document = {
            "services": {
                "warrant": {
                    "environment": {
                        "WARRANT_MODE": ablation.mode,
                        "TAINT": ablation.taint,
                        "WARRANT_OIDC_ISSUER": "http://localhost:8080/realms/warrant",
                        "WARRANT_OIDC_DISCOVERY_ISSUER": "http://keycloak:8080/realms/warrant",
                        "WARRANT_RUNS_DIR": container_runs_dir,
                    },
                    "volumes": [
                        f"{Path(self.runs_host_dir).resolve()}:/app/runs",
                        f"{Path(self.results_dir).resolve()}:/app/evals/results",
                    ],
                }
            }
        }
        return yaml.safe_dump(document, sort_keys=True)

    def write_override(self, ablation: Ablation, *, container_runs_dir: str) -> Path:
        path = self.override_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            self.override_text(ablation, container_runs_dir=container_runs_dir), encoding="utf-8"
        )
        return path

    def build(self) -> None:
        """Build the image once, before the first cell spends anything."""
        # A sandboxed session cannot write the user's buildx state under
        # `~/.docker`, so the build cache goes into the gitignored checkout
        # path the same way the Makefile points `UV_CACHE_DIR` at the checkout.
        env = dict(os.environ)
        env.setdefault("BUILDX_CONFIG", str(REPO_ROOT / ".docker-buildx"))
        proc = self.runner(
            ["docker", "compose", "build", "warrant"],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RunnerError(f"docker compose build warrant failed:\n{proc.stderr.strip()}")

    def apply(self, ablation: Ablation, *, container_runs_dir: str) -> Mapping[str, str]:
        # The bind sources have to exist before compose mounts them; a missing
        # source is created by the daemon as root and then the host process
        # cannot write into it.
        Path(self.results_dir).mkdir(parents=True, exist_ok=True)
        Path(self.runs_host_dir).mkdir(parents=True, exist_ok=True)
        override = self.write_override(ablation, container_runs_dir=container_runs_dir)
        proc = self.runner(
            [
                "docker",
                "compose",
                "-f",
                str(self.compose_file),
                "-f",
                str(override),
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "warrant",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RunnerError(
                f"docker compose up warrant failed for {ablation.name}:\n{proc.stderr.strip()}"
            )
        return self.wait_for(ablation)

    def wait_for(self, ablation: Ablation) -> Mapping[str, str]:
        """Poll `/healthz` until the process reports the mode asked for."""
        deadline = time.monotonic() + self.timeout_s
        last = ""
        with self.client_factory() as client:
            while time.monotonic() < deadline:
                try:
                    payload = client.get(self.health_url, timeout=5.0).json()
                except (httpx.HTTPError, ValueError) as error:
                    last = f"{type(error).__name__}: {error}"
                    time.sleep(1.0)
                    continue
                if payload.get("mode") == ablation.mode and payload.get("taint") == ablation.taint:
                    logger.info(
                        "confirmed ablation %s: mode=%s taint=%s",
                        ablation.name,
                        payload.get("mode"),
                        payload.get("taint"),
                    )
                    return payload
                last = f"reported mode={payload.get('mode')} taint={payload.get('taint')}"
                time.sleep(1.0)
        raise HealthError(
            f"the gateway never confirmed {ablation.name} "
            f"(mode={ablation.mode} taint={ablation.taint}); last: {last}"
        )

    def close(self) -> None:
        return None


# -- building the tasks ------------------------------------------------------


def human_groups() -> dict[str, list[str]]:
    """Each shipped human's group list, from `infra/graph.yml`."""
    data = graph_seed_data()
    return {
        str(row["login"]): [str(group) for group in row.get("groups", [])]
        for row in data.get("humans", [])
    }


def incident_from_scopes(scopes: Sequence[str]) -> str | None:
    """The `incident_id:<value>` a scenario's scopes declare, or None."""
    for scope in scopes:
        name, separator, value = scope.partition(":")
        if separator and name == "incident_id" and value:
            return value
    return None


def write_tools_for(scenario: Scenario, agent_id: str) -> list[str] | None:
    """The write and send tools one acting agent holds in the seeded graph.

    A scenario-owned agent has no row in `infra/graph.yml`, so the shipped
    `write_tools_from_graph` cannot answer for it. The graph here is the same
    in-memory seed `evals.state.Resources` builds: the shipped rows plus the
    scenario's own. None means the agent has no row at all, which the role's
    own set stands in for.
    """
    from gen.seed import scenario_graph_rows

    with Graph(":memory:") as graph:
        graph.seed(graph_seed_data())
        graph.seed(scenario_graph_rows(scenario, graph))
        agent = graph.agent(agent_id)
        if agent is None:
            return None
        kinds = {tool.id: tool.action_kind for tool in graph.tools()}
    return [tool for tool in agent.allowed_tools if kinds.get(tool) in ("write", "send")]


def build_task(spec: TaskSpec, scenario: Scenario, ablation: Ablation) -> Task:
    """One scenario task as the agent loop takes it."""
    agent_id = spec.agent or KIND_AGENT[spec.kind]
    groups = human_groups()
    return Task(
        kind=spec.kind,
        subject=spec.subject,
        user=spec.user,
        params=dict(spec.params),
        agent=spec.agent,
        scopes=list(spec.scopes),
        mode=ablation.mode,
        hardened=ablation.hardened_prompt,
        human_id=shipped_human_ids().get(spec.user),
        groups=groups.get(spec.user, []),
        incident_id=incident_from_scopes(spec.scopes),
        write_tools=write_tools_for(scenario, agent_id),
    )


def task_groups(specs: Sequence[TaskSpec]) -> list[list[TaskSpec]]:
    """The tasks grouped by their `concurrent_group`.

    Tasks that share a non-empty group run together; a task with no group is a
    group of one. The order is the order the scenario lists them.
    """
    groups: list[list[TaskSpec]] = []
    by_name: dict[str, list[TaskSpec]] = {}
    for spec in specs:
        if spec.concurrent_group:
            if spec.concurrent_group not in by_name:
                by_name[spec.concurrent_group] = []
                groups.append(by_name[spec.concurrent_group])
            by_name[spec.concurrent_group].append(spec)
        else:
            groups.append([spec])
    return groups


async def run_tasks(
    scenario: Scenario,
    ablation: Ablation,
    *,
    provider: Provider,
    runs_dir: Path,
    settings: DevSettings,
    mcp_url: str | None,
) -> list[Outcome]:
    """Run every task group in order, concurrent inside a group."""
    outcomes: list[Outcome] = []
    for group in task_groups(scenario.tasks):
        tasks = [build_task(spec, scenario, ablation) for spec in group]
        if len(tasks) == 1:
            outcomes.append(
                await run_one(
                    tasks[0],
                    provider=provider,
                    settings=settings,
                    runs_dir=runs_dir,
                    mcp_url=mcp_url,
                )
            )
        else:
            outcomes.extend(
                await run_concurrent(
                    tasks,
                    provider=provider,
                    settings=settings,
                    runs_dir=runs_dir,
                    mcp_url=mcp_url,
                )
            )
    return outcomes


# -- one cell ----------------------------------------------------------------


@dataclass
class CellResult:
    """What happened to one cell."""

    cell: Cell
    status: str
    grade: Grade | None = None
    error: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


def token_totals(run_dir: Path) -> dict[str, int]:
    """The provider token counts the run recorded, summed over its tasks."""
    totals = {"input_tokens": 0, "output_tokens": 0}
    for path in sorted(Path(run_dir).glob("*/usage.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for key in totals:
            value = data.get(key)
            if isinstance(value, int):
                totals[key] += value
    return totals


def task_summaries(run_dir: Path) -> list[dict[str, Any]]:
    """One summary per task directory: its id, turns, and token counts."""
    summaries: list[dict[str, Any]] = []
    for usage in sorted(Path(run_dir).glob("*/usage.json")):
        try:
            data = json.loads(usage.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        summaries.append(
            {
                "task_id": data.get("task_id", usage.parent.name),
                "turns": data.get("turns"),
                "input_tokens": data.get("input_tokens"),
                "output_tokens": data.get("output_tokens"),
            }
        )
    return summaries


def write_run_metadata(run_dir: Path, cell: Cell, scenario: Scenario) -> Path:
    """The `metadata.json` the grader reads the ablation, model, and repeat from.

    `mode` is the ablation's name here, not the `WARRANT_MODE` value, because
    `evals.grade` reads the ablation from the `mode` or `ablation` key and
    `task-taint` and `content-taint` both run with `WARRANT_MODE=full`. The
    process mode and taint travel under their own keys for a reader.
    """
    path = Path(run_dir) / RUN_METADATA_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "scenario_id": scenario.id,
                "mode": cell.ablation.name,
                "ablation": cell.ablation.name,
                "warrant_mode": cell.ablation.mode,
                "taint": cell.ablation.taint,
                "model": cell.model,
                "repeat": cell.repeat,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def write_cell_meta(cell_root: Path, meta: dict[str, Any]) -> Path:
    path = Path(cell_root) / CELL_META_NAME
    path.write_text(
        json.dumps(meta, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    return path


def dry_cell(cell: Cell, scenario: Scenario, *, results_dir: Path) -> CellResult:
    """Seed a scenario and grade a synthetic no-op run, with no model at all.

    The synthetic decision names a tool no truth block holds, so the grade has
    no injected action and no legitimate action to charge. Its chain is
    complete, which is the one item a no-op can honestly earn, and the state is
    an empty snapshot rather than a live read, so the plumbing is testable
    before any provider or policy is involved.
    """
    root = cell.root(results_dir)
    run_dir = root / RUN_SUBDIR
    run_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC)
    try:
        seed(scenario)
    except SeedError as error:
        return _error_result(cell, root, started, f"seed failed: {error}", traceback.format_exc())

    task_id = f"dry-{scenario.id}-{cell.repeat}"
    chain = Chain(
        sub="dry-run",
        act="dry-run",
        task_id=task_id,
        token_exp=datetime.now(UTC) + timedelta(minutes=5),
        source="token",
    )
    request = AuthzRequest(
        chain=chain,
        tool=DRY_RUN_TOOL,
        action_kind=ActionKind.read,
        resource="dry-run",
        args_digest="dry-run",
        provenance=Provenance(task_id=task_id),
        ts=datetime.now(UTC),
    )
    decision = Decision(
        verdict=Verdict.allow,
        reasons=["dry run: no model and no policy was called"],
        request=request,
        mode=cell.ablation.mode,
    )
    task_dir = run_dir / task_id
    task_dir.mkdir(parents=True, exist_ok=True)
    (task_dir / "decisions.jsonl").write_text(decision.model_dump_json() + "\n", encoding="utf-8")
    state = State()
    (root / STATE_NAME).write_text(state.model_dump_json(indent=2) + "\n", encoding="utf-8")
    write_run_metadata(run_dir, cell, scenario)
    result = grade(scenario, run_dir, state=state)
    write_grade(result, root / GRADE_NAME)
    meta = _cell_meta(cell, started, status="ok", grade=result)
    write_cell_meta(root, meta)
    return CellResult(cell=cell, status="ok", grade=result, meta=meta)


def _cell_meta(
    cell: Cell,
    started: datetime,
    *,
    status: str,
    grade: Grade | None = None,
    error: str = "",
    confirmed: Mapping[str, str] | None = None,
    run_dir: Path | None = None,
    seed_s: float | None = None,
) -> dict[str, Any]:
    finished = datetime.now(UTC)
    meta: dict[str, Any] = {
        "column": cell.column,
        "ablation": cell.ablation.name,
        "ablation_mode": cell.ablation.mode,
        "ablation_taint": cell.ablation.taint,
        "model": cell.model,
        "scenario_id": cell.scenario_id,
        "repeat": cell.repeat,
        "status": status,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "elapsed_s": round((finished - started).total_seconds(), 3),
        "commit": _head(),
        "dirty": _dirty(),
    }
    if confirmed:
        meta["confirmed_mode"] = confirmed.get("mode")
        meta["confirmed_taint"] = confirmed.get("taint")
    if seed_s is not None:
        meta["seed_s"] = round(seed_s, 3)
    if grade is not None:
        meta["score"] = grade.score
        meta["held"] = grade.held
    if run_dir is not None:
        meta["tokens"] = token_totals(run_dir)
        meta["tasks"] = task_summaries(run_dir)
    if error:
        meta["error"] = error
    return meta


def _error_result(cell: Cell, root: Path, started: datetime, error: str, detail: str) -> CellResult:
    root.mkdir(parents=True, exist_ok=True)
    meta = _cell_meta(cell, started, status="error", error=error)
    meta["traceback"] = detail
    write_cell_meta(root, meta)
    return CellResult(cell=cell, status="error", error=error, meta=meta)


def _head() -> str | None:
    from warrant.config import commit_sha

    return commit_sha()


def _dirty() -> bool | None:
    from warrant.config import commit_is_dirty

    return commit_is_dirty()


def run_cell(
    cell: Cell,
    scenario: Scenario,
    *,
    switcher: Switcher,
    provider: Provider,
    results_dir: Path,
    settings: DevSettings,
    mcp_url: str | None,
    attempts: int = 2,
) -> CellResult:
    """Seed, switch, run, snapshot, grade one cell.

    A failure before the grade is retried once from a fresh seed. A second
    failure is recorded as an `error` and returned, so the matrix continues.
    `GraderInconsistency` is not caught here: it stops the run at the caller.
    """
    root = cell.root(results_dir)
    run_dir = root / RUN_SUBDIR
    container_runs_dir = "/app/evals/results/" + str(root.relative_to(results_dir) / RUN_SUBDIR)
    started = datetime.now(UTC)
    last_error = ""
    last_traceback = ""
    seed_s: float | None = None
    confirmed: Mapping[str, str] = {}
    for attempt in range(1, attempts + 1):
        try:
            if run_dir.exists():
                shutil.rmtree(run_dir)
            run_dir.mkdir(parents=True, exist_ok=True)
            seed_started = time.monotonic()
            seed(scenario)
            seed_s = time.monotonic() - seed_started
            # Seed first, then recreate: a restarted gateway reads the graph
            # the seed just wrote, which is the settle step the W14 note asked
            # for. A gateway left running would decide the next call against
            # the previous scenario's graph.
            confirmed = switcher.apply(cell.ablation, container_runs_dir=container_runs_dir)
            write_run_metadata(run_dir, cell, scenario)
            run_tasks_sync(
                scenario,
                cell.ablation,
                provider=provider,
                runs_dir=run_dir,
                settings=settings,
                mcp_url=mcp_url,
            )
            break
        except GraderInconsistency:
            raise
        except Exception as error:  # noqa: BLE001 - the cell records what failed
            last_error = f"{type(error).__name__}: {error}"
            last_traceback = traceback.format_exc()
            logger.warning("cell %s attempt %d failed: %s", cell.relative(), attempt, last_error)
            if attempt >= attempts:
                return _error_result(cell, root, started, last_error, last_traceback)

    try:
        state = live_state(scenario)
    except Exception as error:  # noqa: BLE001 - a state read that fails is a cell error
        return _error_result(
            cell,
            root,
            started,
            f"state read failed: {type(error).__name__}: {error}",
            traceback.format_exc(),
        )
    (root / STATE_NAME).write_text(state.model_dump_json(indent=2) + "\n", encoding="utf-8")
    try:
        result = grade(scenario, run_dir, state=state)
    except GraderInconsistency:
        raise
    except Exception as error:  # noqa: BLE001
        return _error_result(
            cell,
            root,
            started,
            f"grade failed: {type(error).__name__}: {error}",
            traceback.format_exc(),
        )
    write_grade(result, root / GRADE_NAME)
    meta = _cell_meta(
        cell,
        started,
        status="ok",
        grade=result,
        confirmed=confirmed,
        run_dir=run_dir,
        seed_s=seed_s,
    )
    write_cell_meta(root, meta)
    return CellResult(cell=cell, status="ok", grade=result, meta=meta)


def run_tasks_sync(
    scenario: Scenario,
    ablation: Ablation,
    *,
    provider: Provider,
    runs_dir: Path,
    settings: DevSettings,
    mcp_url: str | None,
) -> list[Outcome]:
    """`run_tasks` for the synchronous cell path."""
    return asyncio.run(
        run_tasks(
            scenario,
            ablation,
            provider=provider,
            runs_dir=runs_dir,
            settings=settings,
            mcp_url=mcp_url,
        )
    )


# -- the matrix --------------------------------------------------------------


def run_matrix(
    *,
    scenarios: Sequence[str],
    ablations: Sequence[Ablation],
    models: Sequence[str],
    repeats: int,
    column: str,
    results_dir: Path = RESULTS_DIR,
    switcher: Switcher | None = None,
    provider_factory: Callable[[str], Provider] = provider_for,
    settings: DevSettings | None = None,
    mcp_url: str | None = None,
    dry_run: bool = False,
    resume: bool = False,
    build: bool = True,
) -> list[CellResult]:
    """Run every cell in order and return the results.

    The scenario seed resets the graph, so the runner seeds before the
    ablation switch. The switch recreates the gateway and waits for `/healthz`;
    the mode and taint it reports are recorded in the cell's `meta.json`.
    """
    settings = settings or DevSettings()
    loaded = {scenario_id: load_scenario(scenario_id) for scenario_id in scenarios}
    resolved_providers: dict[str, Provider] = {}
    if not dry_run:
        resolved_providers = {model: provider_factory(model) for model in models}
        if switcher is None:
            switcher = ComposeSwitcher(results_dir=results_dir)
        if build:
            switcher.build()

    results: list[CellResult] = []
    for ablation in ablations:
        for model in models:
            for scenario_id in scenarios:
                for repeat in range(1, repeats + 1):
                    cell = Cell(
                        column=column,
                        ablation=ablation,
                        model=model,
                        scenario_id=scenario_id,
                        repeat=repeat,
                    )
                    root = cell.root(results_dir)
                    if resume and (root / GRADE_NAME).exists():
                        logger.info("skip %s: already graded", root)
                        continue
                    if dry_run:
                        results.append(dry_cell(cell, loaded[scenario_id], results_dir=results_dir))
                        continue
                    assert switcher is not None
                    results.append(
                        run_cell(
                            cell,
                            loaded[scenario_id],
                            switcher=switcher,
                            provider=resolved_providers[model],
                            results_dir=results_dir,
                            settings=settings,
                            mcp_url=mcp_url,
                        )
                    )
    if switcher is not None:
        switcher.close()
    column_dir = Path(results_dir) / column
    report(column_dir, column_dir / "report.md")
    return results


def regrade_column(results_dir: Path, column: str) -> list[CellResult]:
    """Rebuild every `grade.json` under one column from its stored run and state.

    A change to the grader does not change the runs it reads, so this rescoring
    spends nothing and starts no model. A cell whose `grade.json` the current
    schema cannot read is skipped: results accumulate across schema changes and
    an old file beside a new one is the expected shape.
    """
    column_dir = Path(results_dir) / column
    results: list[CellResult] = []
    for grade_path in sorted(column_dir.glob("*/*/*/*/grade.json")):
        cell_root = grade_path.parent
        run_dir = cell_root / RUN_SUBDIR
        try:
            previous = Grade.model_validate_json(grade_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            logger.warning("skip %s: not readable by the current schema", grade_path)
            continue
        scenario = load_scenario(previous.scenario_id)
        state_path = cell_root / STATE_NAME
        state = load_state(state_path) if state_path.exists() else None
        result = grade(scenario, run_dir, state=state)
        write_grade(result, grade_path)
        results.append(
            CellResult(
                cell=Cell(
                    column=column,
                    ablation=parse_ablations(previous.ablation)[0],
                    model=previous.model,
                    scenario_id=previous.scenario_id,
                    repeat=previous.repeat,
                ),
                status="ok",
                grade=result,
            )
        )
    report(column_dir, column_dir / "report.md")
    return results


# -- the CLI -----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evals.run",
        description="Run the Warrant eval matrix: ablations x scenarios x repeats.",
    )
    parser.add_argument("--scenarios", default="all", help="all, or 08,01, or full ids")
    parser.add_argument("--ablations", default="all", help="all, or full,no-provenance")
    parser.add_argument("--repeats", type=int, default=3, help="repeats per cell")
    parser.add_argument("--models", default=DEFAULT_MODEL, help="comma-separated model specs")
    parser.add_argument("--column", default=None, help="the results column to write")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="seed and grade a synthetic no-op run with no model",
    )
    parser.add_argument(
        "--resume", action="store_true", help="skip a cell that already holds a grade.json"
    )
    parser.add_argument(
        "--no-build", action="store_true", help="do not rebuild the image before the matrix"
    )
    parser.add_argument(
        "--regrade",
        action="store_true",
        help="rescore the stored runs in --column without a model or a seed",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.regrade:
        try:
            column = validate_column(args.column, dry_run=False)
            results = regrade_column(RESULTS_DIR, column)
        except (RunnerError, GraderInconsistency) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        for cell in results:
            assert cell.grade is not None
            print(f"{cell.cell.relative()}: score={cell.grade.score} held={cell.grade.held}")
        print(f"{len(results)} cell(s) regraded")
        return 0
    try:
        scenarios = parse_scenarios(args.scenarios)
        ablations = parse_ablations(args.ablations)
        models = parse_models(args.models)
        column = validate_column(args.column, dry_run=args.dry_run)
    except (RunnerError, AblationError) as error:
        parser.error(str(error))
        return 2
    if args.repeats < 1:
        parser.error("--repeats must be at least 1")
        return 2

    try:
        results = run_matrix(
            scenarios=scenarios,
            ablations=ablations,
            models=models,
            repeats=args.repeats,
            column=column,
            dry_run=args.dry_run,
            resume=args.resume,
            build=not args.no_build,
        )
    except (RunnerError, HealthError, GraderInconsistency) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    errors = [cell for cell in results if cell.status == "error"]
    for cell in results:
        if cell.grade is not None:
            print(f"{cell.cell.relative()}: score={cell.grade.score} held={cell.grade.held}")
        else:
            print(f"{cell.cell.relative()}: error: {cell.error}")
    print(f"{len(results)} cell(s), {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
