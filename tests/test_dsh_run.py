"""The headless runner: its import bootstrap, its `--cwd`, and its run record.

`scripts/dsh_run.py` is not a package module, so it is loaded by path. The
record test drives `main` with a fake SDK instead of a real provider.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[1]
RUNNER = REPO / "scripts" / "dsh_run.py"


def load_runner() -> Any:
    spec = importlib.util.spec_from_file_location("dsh_run", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["dsh_run"] = module
    spec.loader.exec_module(module)
    return module


def test_runner_help_runs_from_another_cwd_without_pythonpath(tmp_path: Path) -> None:
    """The import bootstrap, exercised the way the acceptance command does.

    `package = false` means `warrant` is importable only because the runner adds
    the repository root itself. Without that, this subprocess fails with
    `ModuleNotFoundError` before argparse can print help.
    """
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, str(RUNNER), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )

    assert proc.returncode == 0, proc.stderr
    assert "--cwd" in proc.stdout


def test_runner_cwd_defaults_to_the_repo_root_and_accepts_another() -> None:
    runner = load_runner()

    default = runner.parse_args(["prompt"])
    elsewhere = runner.parse_args(["--cwd", "/somewhere", "prompt"])

    assert Path(default.cwd).resolve() == REPO
    assert elsewhere.cwd == "/somewhere"


def test_record_target_keeps_an_existing_record_from_a_failed_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = load_runner()
    monkeypatch.setattr(runner, "RUNS_DIR", tmp_path)

    assert runner.record_target("s", failed=False) == tmp_path / "s.json"
    assert runner.record_target("s", failed=True) == tmp_path / "s.json"

    (tmp_path / "s.json").write_text("{}\n")

    assert runner.record_target("s", failed=False) == tmp_path / "s.json"
    assert runner.record_target("s", failed=True) != tmp_path / "s.json"


def test_session_id_cannot_climb_out_of_the_runs_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A session id names a file, not a path.

    `--session ../../x` made `record_target` return a path above the runs
    directory, and the record is written on a failed run too, so the escape was
    reachable even when the runtime rejected the id.
    """
    runner = load_runner()
    monkeypatch.setattr(runner, "RUNS_DIR", tmp_path / "runs" / "dsh")

    with pytest.raises(ValueError):
        runner.record_target("../../escaped", failed=True)

    with pytest.raises(SystemExit) as exit_info:
        runner.main(["--session", "../../escaped", "hello"])
    capsys.readouterr()

    assert exit_info.value.code == 2
    assert not (tmp_path / "escaped.json").exists()
    assert not (tmp_path / "runs" / "dsh").exists()


class _FakeHarness:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs

    def __enter__(self) -> _FakeHarness:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def run(self, prompt: str, *, session_id: str | None = None) -> Any:
        raise RuntimeError("session already exists")


def _install_fake_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType("deepseek_harness")

    class SdkProtocolError(Exception):
        pass

    module.DeepSeekHarness = _FakeHarness
    module.SdkProtocolError = SdkProtocolError
    monkeypatch.setitem(sys.modules, "deepseek_harness", module)


def test_failed_run_does_not_overwrite_a_good_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A reused session id fails; the good cost file has to survive it."""
    runner = load_runner()
    monkeypatch.setattr(runner, "RUNS_DIR", tmp_path)
    good = tmp_path / "w23.json"
    good.write_text(json.dumps({"session_id": "w23", "exit_code": 0, "usage": {"totalTokens": 7}}))
    _install_fake_sdk(monkeypatch)
    dsh_home = tmp_path / "dsh-home"
    dsh_home.mkdir()

    code = runner.main(
        ["--session", "w23", "--dsh-bin", "/usr/bin/true", "--dsh-home", str(dsh_home), "hello"]
    )
    capsys.readouterr()

    assert code == 1
    assert json.loads(good.read_text()) == {
        "session_id": "w23",
        "exit_code": 0,
        "usage": {"totalTokens": 7},
    }
    failures = sorted(tmp_path.glob("w23.failed-*.json"))
    assert len(failures) == 1
    written = json.loads(failures[0].read_text())
    assert written["exit_code"] == 1
    assert "session already exists" in written["error"]
