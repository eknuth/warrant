"""The four ported hooks, driven the way the hook bridge drives them.

Each test feeds a hook a payload with the same shape the bridge builds:
`tool_name`, `tool_input`, `cwd`, `hook_event_name`. A hook that exits 2 blocks
the tool call with its stderr as the model-visible reason; anything else lets
the call through. The tests run the hooks as subprocesses rather than importing
them, because the exit code and the stream split are the contract.
"""

from __future__ import annotations

import json
import os
import random
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
HOOKS = REPO / ".dsh" / "hooks"

SECRETS = HOOKS / "block_secrets.py"
DOUBLE = HOOKS / "block_double_emit.py"
PARKED = HOOKS / "block_parked_column.py"
LINT = HOOKS / "lint_after_commit.py"

ALL_HOOKS = [SECRETS, DOUBLE, PARKED, LINT]

HOOK_TIMEOUT_S = 30


def random_key(*, lowercase: bool = True) -> str:
    """A key-shaped suffix assembled at run time.

    Anything key-shaped written literally in this file would be a finding for
    the hook under test, and this file is committed, so every fixture of that
    shape is built here instead.
    """
    alphabet = (
        string.ascii_lowercase + string.digits
        if lowercase
        else string.ascii_uppercase + string.digits
    )
    return "".join(random.choice(alphabet) for _ in range(24))


# One generator per key shape the hook treats as a key, keyed by the label the
# hook reports. A generator that stops matching its pattern fails the test
# rather than silently passing.
KEY_SAMPLES: dict[str, object] = {
    "a key with a prefix reserved for keys": lambda: "sk-ant-" + random_key(),
    "an ingest key": lambda: "hcaik_" + random_key(),
    "a management key": lambda: "hcamk_" + random_key(),
    "an AWS access key id": lambda: "AKIA" + random_key(lowercase=False)[:16],
    "a Linear API key": lambda: "lin_api_" + random_key(),
}

# The fixture below is assigned to a name that does not end in KEY, TOKEN,
# SECRET, or PASSWORD, because the hook treats such an assignment as a finding
# no matter what the value is, and this file is committed.
SHAPED_KEY_SAMPLE = KEY_SAMPLES["a key with a prefix reserved for keys"]()

VENDOR_PREFIXES = (
    "sk-ant-",
    "hcaik_",
    "hcamk_",
    "AKIA",
    "lin_api_",
)


def run_hook(
    hook: Path, payload: object, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run one hook with `payload` on stdin, exactly as the bridge does."""
    stdin = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(
        [sys.executable, str(hook)],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=HOOK_TIMEOUT_S,
        env=env,
    )


def bash_payload(command: str, cwd: Path) -> dict[str, object]:
    return {
        "session_id": "test-session",
        "transcript_path": "",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": command, "description": "test command"},
        "tool_use_id": "call-1",
    }


def git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=30)


def init_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    git(["init", "-q"], path)
    git(["config", "user.name", "Hook Test"], path)
    git(["config", "user.email", "hook-test@example.invalid"], path)


# --- block_secrets ---------------------------------------------------------


def test_secrets_blocks_git_add_of_env_file(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / ".env").write_text("DEEPSEEK_API_KEY=real-value-here\n")
    (tmp_path / ".env.example").write_text("DEEPSEEK_API_KEY=<your-key>\n")

    proc = run_hook(SECRETS, bash_payload("git add .env", tmp_path))

    assert proc.returncode == 2
    assert ".env" in proc.stderr
    assert "real-value-here" not in proc.stderr
    assert proc.stdout == ""


def test_secrets_blocks_commit_that_stages_env(tmp_path: Path) -> None:
    """The acceptance shape: a commit that would carry `.env` never lands."""
    init_repo(tmp_path)
    (tmp_path / ".env").write_text("DEEPSEEK_API_KEY=real-value-here\n")
    (tmp_path / ".env.example").write_text("DEEPSEEK_API_KEY=<your-key>\n")
    # Stage directly with git, below the hook, then let the hook judge the commit.
    git(["add", "-f", ".env"], tmp_path)

    proc = run_hook(SECRETS, bash_payload("git commit -m 'add config'", tmp_path))

    assert proc.returncode == 2
    assert "commit blocked" in proc.stderr
    assert ".env" in proc.stderr
    assert "real-value-here" not in proc.stderr


def test_secrets_blocks_key_shaped_added_line(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "config.py").write_text(f"API_KEY = '{SHAPED_KEY_SAMPLE}'\n")
    (tmp_path / ".env.example").write_text("DEEPSEEK_API_KEY=<your-key>\n")
    git(["add", "config.py"], tmp_path)

    proc = run_hook(SECRETS, bash_payload("git commit -m 'config'", tmp_path))

    assert proc.returncode == 2
    assert "config.py" in proc.stderr
    assert SHAPED_KEY_SAMPLE not in proc.stderr, "the reason must never carry the value"


@pytest.mark.parametrize("label", sorted(KEY_SAMPLES))
def test_secrets_every_key_pattern_fires(label: str) -> None:
    """Each shape the hook treats as a key blocks a commit that adds one.

    The samples are built at run time so no key-shaped literal is committed
    here. That is the point of the shape: this file is part of the tree the
    hook scans, and a literal fixture in it blocks the project's own commits.
    """
    value = KEY_SAMPLES[label]()  # type: ignore[operator]
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        init_repo(root)
        (root / ".env.example").write_text("DEEPSEEK_API_KEY=<your-key>\n")
        (root / "config.py").write_text(f"TOKEN = '{value}'\n")
        git(["add", "config.py"], root)

        proc = run_hook(SECRETS, bash_payload("git commit -m 'config'", root))

    assert proc.returncode == 2, f"{label}: {value}"
    assert label in proc.stderr
    assert value not in proc.stderr


def test_secrets_patterns_cover_the_prefixes_they_name() -> None:
    """The hook's patterns and this file's samples name the same prefixes."""
    source = SECRETS.read_text()
    for prefix in VENDOR_PREFIXES:
        assert prefix in source, prefix


def test_secrets_passes_placeholder_in_env_example(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / ".env.example").write_text(
        "DEEPSEEK_API_KEY=<your-deepseek-api-key>\nLINEAR_API_KEY=<your-linear-api-key>\n"
    )
    git(["add", ".env.example"], tmp_path)

    proc = run_hook(SECRETS, bash_payload("git commit -m 'example'", tmp_path))

    assert proc.returncode == 0
    assert proc.stderr == ""


def test_secrets_passes_a_commit_that_adds_nothing_sensitive(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "notes.md").write_text("no secrets here\n")
    git(["add", "notes.md"], tmp_path)

    proc = run_hook(SECRETS, bash_payload("git commit -m 'notes'", tmp_path))

    assert proc.returncode == 0


def test_secrets_passes_a_non_git_command(tmp_path: Path) -> None:
    proc = run_hook(SECRETS, bash_payload("ls -la", tmp_path))

    assert proc.returncode == 0
    assert proc.stderr == ""


def test_secrets_passes_an_unrelated_tool(tmp_path: Path) -> None:
    payload = bash_payload("git add .env", tmp_path)
    payload["tool_name"] = "write"

    proc = run_hook(SECRETS, payload)

    assert proc.returncode == 0


def test_secrets_ignores_a_heredoc_body(tmp_path: Path) -> None:
    """Text after `<<` is a document, not shell, so a quoted example passes."""
    proc = run_hook(
        SECRETS,
        bash_payload(f"cat <<'EOF' > notes.md\n{SHAPED_KEY_SAMPLE}\nEOF", tmp_path),
    )

    assert proc.returncode == 0


def test_secrets_reads_the_repo_the_command_names(tmp_path: Path) -> None:
    """The block is about the repository the commit lands in, not the shell's.

    A `git -C <path> commit` sends the diff to `<path>`, so a hook that only
    reads the payload `cwd` judges a different tree. Both halves are asserted:
    the offending repo blocks, and a clean repo with the same file names and a
    clean staged diff passes.
    """
    offending = tmp_path / "offending"
    clean = tmp_path / "clean"
    for root in (offending, clean):
        init_repo(root)
        (root / ".env.example").write_text("DEEPSEEK_API_KEY=<your-key>\n")
        (root / "config.py").write_text("VALUE = 1\n")
        git(["add", ".env.example", "config.py"], root)

    (offending / "config.py").write_text(f"VALUE = '{SHAPED_KEY_SAMPLE}'\n")
    git(["add", "config.py"], offending)

    elsewhere = tmp_path / "elsewhere"
    init_repo(elsewhere)
    (elsewhere / "notes.md").write_text("unrelated\n")
    git(["add", "notes.md"], elsewhere)

    blocked = run_hook(
        SECRETS,
        bash_payload(f"git -C {offending} commit -m 'config'", elsewhere),
    )
    allowed = run_hook(
        SECRETS,
        bash_payload(f"git -C {clean} commit -m 'config'", elsewhere),
    )

    assert blocked.returncode == 2, "the named repo's staged key must block"
    assert "config.py" in blocked.stderr
    assert allowed.returncode == 0, "the named repo's clean diff must pass"
    assert allowed.stderr == ""


def test_secrets_follows_cd_before_the_commit(tmp_path: Path) -> None:
    """`cd <path> && git commit` commits in `<path>`, so the hook reads it."""
    offending = tmp_path / "offending"
    init_repo(offending)
    (offending / ".env.example").write_text("DEEPSEEK_API_KEY=<your-key>\n")
    (offending / "config.py").write_text(f"VALUE = '{SHAPED_KEY_SAMPLE}'\n")
    git(["add", ".env.example", "config.py"], offending)

    proc = run_hook(
        SECRETS,
        bash_payload(f"cd {offending} && git commit -m 'config'", tmp_path),
    )

    assert proc.returncode == 2
    assert "config.py" in proc.stderr


def test_secrets_passes_the_staged_w0_diff(tmp_path: Path) -> None:
    """The whole point of the criterion: this repository's own content passes.

    The tree is copied into a fresh repository and staged, then the hook judges
    the commit the project will actually make. A key-shaped literal anywhere in
    the tracked files fails this, which is how the fixture problem in this very
    test file was found.
    """
    repo = tmp_path / "w0"
    init_repo(repo)
    tracked = subprocess.run(
        ["git", "-C", str(REPO), "ls-files"],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    ).stdout.split()
    for name in tracked:
        source = REPO / name
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    (repo / ".env.example").write_text((REPO / ".env.example").read_text())
    git(["add", "-f", "-A"], repo)
    assert git(["diff", "--cached", "--name-only"], repo).stdout.strip(), "nothing staged"

    proc = run_hook(SECRETS, bash_payload("git commit -m 'W0'", repo))

    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""


# --- block_double_emit -----------------------------------------------------


def test_double_run_blocks_when_a_run_is_already_going(tmp_path: Path) -> None:
    """A running process whose command line matches the pattern blocks a new run.

    The marker carries its own name so `pgrep -f` finds it: a bare `sleep 30`
    has no `30` in its command line, so it cannot be addressed by pid.
    """
    marker = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)", "warrant-run-marker"]
    )
    env = {**os.environ, "WARRANT_RUN_PATTERN": "warrant-run-marker"}
    try:
        time.sleep(0.3)
        proc = run_hook(
            DOUBLE,
            bash_payload(
                "uv run python scripts/dsh_run.py --effort low --session t 'print(1)'", tmp_path
            ),
            env=env,
        )
    finally:
        marker.kill()
        marker.wait(timeout=10)

    assert proc.returncode == 2
    assert "already running" in proc.stderr
    assert str(marker.pid) in proc.stderr


def test_double_run_passes_when_nothing_is_running(tmp_path: Path) -> None:
    proc = run_hook(
        DOUBLE,
        bash_payload(
            "uv run python scripts/dsh_run.py --effort low --session t 'print(1)'", tmp_path
        ),
    )

    assert proc.returncode == 0
    assert proc.stderr == ""


def test_double_run_ignores_a_mention_inside_a_commit_message(tmp_path: Path) -> None:
    proc = run_hook(
        DOUBLE,
        bash_payload("git commit -m 'run scripts/dsh_run.py later'", tmp_path),
    )

    assert proc.returncode == 0


def test_double_run_passes_an_unrelated_python_command(tmp_path: Path) -> None:
    proc = run_hook(DOUBLE, bash_payload("uv run python -m pytest tests", tmp_path))

    assert proc.returncode == 0


# --- block_parked_column ---------------------------------------------------


def test_parked_column_passes_four_levels_deep(tmp_path: Path) -> None:
    results = tmp_path / "evals" / "results"
    (results / "full" / "scenario" / "1").mkdir(parents=True)
    (results / "full" / "scenario" / "1" / "grade.json").write_text("{}")

    proc = run_hook(
        PARKED,
        bash_payload(
            "mkdir -p evals/results/r18-pass && mv evals/results/full evals/results/r18-pass",
            tmp_path,
        ),
    )

    assert proc.returncode == 0
    assert proc.stderr == ""


def test_parked_column_blocks_three_levels_deep(tmp_path: Path) -> None:
    """A column renamed to `evals/results/<park>` leaves cells three levels down
    beneath a name no runner writes, which the report adds to the live column
    whose `config` field its cells carry."""
    results = tmp_path / "evals" / "results"
    (results / "r18-pass" / "scenario" / "1").mkdir(parents=True)
    (results / "r18-pass" / "scenario" / "1" / "grade.json").write_text("{}")

    proc = run_hook(
        PARKED,
        bash_payload("mv evals/results/r18-pass evals/results/park", tmp_path),
    )

    assert proc.returncode == 2
    assert "three levels" in proc.stderr


def test_parked_column_passes_commands_that_do_not_touch_results(tmp_path: Path) -> None:
    proc = run_hook(PARKED, bash_payload("mv src/a.py src/b.py", tmp_path))

    assert proc.returncode == 0


# --- lint_after_commit -----------------------------------------------------


def test_lint_hook_skips_when_the_makefile_has_no_lint_target(tmp_path: Path) -> None:
    """A Makefile without a `lint` target is not a red lint.

    W0 ships `make dsh-profile` only, so `make lint` exits non-zero with "No rule
    to make target". Every W0 commit would then be reported as red lint. The
    hook has to tell "there is no lint here" apart from "lint failed".
    """
    init_repo(tmp_path)
    (tmp_path / "Makefile").write_text("dsh-profile:\n\t@true\n")
    payload = bash_payload("git commit -m 'x'", tmp_path)
    payload["hook_event_name"] = "PostToolUse"

    proc = run_hook(LINT, payload)

    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""


def test_lint_hook_passes_when_there_is_no_makefile(tmp_path: Path) -> None:
    init_repo(tmp_path)
    payload = bash_payload("git commit -m 'x'", tmp_path)
    payload["hook_event_name"] = "PostToolUse"

    proc = run_hook(LINT, payload)

    assert proc.returncode == 0


def test_lint_hook_ignores_a_repo_with_no_commits_and_no_makefile(tmp_path: Path) -> None:
    """A fresh repository has no resolvable HEAD. The hook must not fall back to
    a different checkout's Makefile, which is what a configured project dir
    would give it, and must not report red lint for a project with no lint."""
    init_repo(tmp_path)
    (tmp_path / "notes.md").write_text("first\n")
    git(["add", "notes.md"], tmp_path)

    proc = run_hook(LINT, bash_payload("git commit -m 'first'", tmp_path))

    assert proc.returncode == 0
    assert proc.stderr == ""


def test_lint_hook_reports_red_lint(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "Makefile").write_text("lint:\n\t@echo 'lint is red' >&2; exit 1\n")
    payload = bash_payload("git commit -m 'x'", tmp_path)
    payload["hook_event_name"] = "PostToolUse"

    proc = run_hook(LINT, payload)

    assert proc.returncode == 2
    assert "lint is red" in proc.stderr


def test_lint_hook_passes_a_green_lint(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "Makefile").write_text("lint:\n\t@true\n")
    payload = bash_payload("git commit -m 'x'", tmp_path)
    payload["hook_event_name"] = "PostToolUse"

    proc = run_hook(LINT, payload)

    assert proc.returncode == 0


def test_lint_hook_passes_a_non_commit_command(tmp_path: Path) -> None:
    proc = run_hook(LINT, bash_payload("git status", tmp_path))

    assert proc.returncode == 0


# --- every hook -----------------------------------------------------------


@pytest.mark.parametrize("hook", ALL_HOOKS, ids=lambda p: Path(p).stem)
def test_hook_exits_zero_on_garbage_stdin(hook: Path) -> None:
    """A hook that fails closed would block every bash call, so it must not."""
    proc = run_hook(hook, "not json at all")

    assert proc.returncode == 0
    assert proc.stderr == ""


@pytest.mark.parametrize("hook", ALL_HOOKS, ids=lambda p: Path(p).stem)
def test_hook_reads_stdin_without_printing_to_stdout(hook: Path) -> None:
    """stdout belongs to the session; a hook that writes there corrupts it."""
    proc = run_hook(hook, bash_payload("ls", Path.cwd()))

    assert proc.stdout == ""


# --- the hook config ------------------------------------------------------


def load_hook_config() -> dict[str, list[dict[str, object]]]:
    return json.loads((REPO / ".dsh" / "hooks.json").read_text())


def test_hook_config_wires_every_hook_to_a_matcher() -> None:
    config = load_hook_config()

    assert set(config) == {"PreToolUse", "PostToolUse"}
    pre = config["PreToolUse"][0]
    post = config["PostToolUse"][0]
    assert pre["matcher"] == "bash", "the harness tool is named bash, not Bash"
    assert post["matcher"] == "bash"

    commands = [h["command"] for h in pre["hooks"]]
    commands += [h["command"] for h in post["hooks"]]
    for name in ("block_secrets", "block_double_emit", "block_parked_column", "lint_after_commit"):
        assert any(name in command for command in commands), name


def test_hook_config_commands_point_at_files_that_exist() -> None:
    """Every command names a script under .dsh/hooks, and every one is present.

    The command resolves the directory from the shell's own working directory,
    which the bridge sets to the session workspace, so this asserts the two
    halves agree rather than that a particular absolute path is spelled out.
    """
    config = load_hook_config()
    hooks = [h for groups in config.values() for group in groups for h in group["hooks"]]

    assert hooks
    for hook in hooks:
        command = str(hook["command"])
        assert "$PWD/.dsh/hooks/" in command, command
        target = command.split("$PWD/")[1].split('"')[0]
        assert (REPO / target).is_file(), target


def run_configured_command(
    command: str, payload: dict[str, object], cwd: Path
) -> subprocess.CompletedProcess[str]:
    """Run one hooks.json command through the shell, as the bridge does.

    `cwd` rather than a `PWD` environment override: bash sets `PWD` itself at
    startup, so an inherited value is ignored and would make a test that points
    the command at a scratch tree silently test the real checkout instead.
    """
    return subprocess.run(
        ["bash", "-c", command],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=HOOK_TIMEOUT_S,
        cwd=cwd,
    )


def configured_commands() -> list[str]:
    config = load_hook_config()
    return [
        str(h["command"]) for groups in config.values() for group in groups for h in group["hooks"]
    ]


def test_hook_config_runs_its_script_when_the_script_is_there() -> None:
    command = next(c for c in configured_commands() if "block_secrets" in c)

    proc = run_configured_command(command, bash_payload("ls -la", REPO), REPO)

    assert proc.returncode == 0, proc.stderr


def test_hook_config_fails_closed_when_the_script_is_missing(tmp_path: Path) -> None:
    """A missing hook script must refuse the call, not wave it through.

    The guard used to be `[ -f "$F" ] && python3 "$F"`, which exits 0 when the
    file is absent, so a session rooted somewhere other than this checkout ran no
    hooks at all and every block became a pass with nothing in the log to say so.
    """
    for command in configured_commands():
        proc = run_configured_command(command, bash_payload("git status", tmp_path), tmp_path)

        assert proc.returncode == 2, command
        assert proc.stdout == ""
        assert "hook missing:" in proc.stderr
        assert ".dsh/hooks/" in proc.stderr


def test_hook_config_sets_a_timeout_inside_the_bridge_cap() -> None:
    config = load_hook_config()
    hooks = [h for groups in config.values() for group in groups for h in group["hooks"]]

    for hook in hooks:
        assert 0 < int(hook["timeout"]) <= 90
