"""The four ported hooks, driven the way the hook bridge drives them.

Each test feeds a hook a payload with the same shape the bridge builds:
`tool_name`, `tool_input`, `cwd`, `hook_event_name`. A hook that exits 2 blocks
the tool call with its stderr as the model-visible reason; anything else lets
the call through. The tests run the hooks as subprocesses rather than importing
them, because the exit code and the stream split are the contract.
"""

from __future__ import annotations

import importlib.util
import json
import os
import random
import re
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
HOOKS = REPO / ".dsh" / "hooks"
PROFILE = REPO / "infra" / "dsh" / "core.patch.yml"

SECRETS = HOOKS / "block_secrets.py"
DOUBLE = HOOKS / "block_double_emit.py"
PARKED = HOOKS / "block_parked_column.py"
LINT = HOOKS / "lint_after_commit.py"
GUARD = HOOKS / "guard_merge.py"

ALL_HOOKS = [SECRETS, DOUBLE, PARKED, LINT, GUARD]

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

# A value that looks like a real credential rather than a placeholder, built at
# run time so no secret-shaped literal is committed. Used to prove that editing
# `.env.example` cannot widen the secrets hook's allowlist.
REAL_SHAPED_VALUE = "Real" + random_key() + "Token"

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


def _load(hook: Path) -> Any:
    """Import a hook module by path, for the tests that call a predicate directly.

    The hooks are run as subprocesses everywhere else, because the exit code and
    the stream split are the contract. The target-listing predicate is the one
    case where reading the parsed result beats reading an exit code: the failure
    it guards against is a listing whose layout changed, and that shows up as a
    wrong answer to a question, not as a wrong exit code.
    """
    spec = importlib.util.spec_from_file_location(hook.stem, hook)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def test_secrets_is_not_bypassed_by_a_real_value_in_env_example(tmp_path: Path) -> None:
    """`.env.example` is committed, so it cannot be its own allowlist.

    The allowlist used to be every line of that file. Anyone could add a real
    credential to it and then commit the same line anywhere, which is a guard
    defeated by editing the file it guards. Only bracket-shaped placeholder
    values are admitted now.
    """
    init_repo(tmp_path)
    (tmp_path / ".env.example").write_text(
        "DEEPSEEK_API_KEY=<your-deepseek-api-key>\nGITEA_ADMIN_TOKEN=<your-gitea-admin-token>\n"
    )
    token_line = f"GITEA_ADMIN_TOKEN={REAL_SHAPED_VALUE}"
    # The attacker edits the file the guard reads, then commits the value.
    with (tmp_path / ".env.example").open("a") as handle:
        handle.write(token_line + "\n")
    (tmp_path / "cfg.py").write_text(f"GITEA_ADMIN_TOKEN={REAL_SHAPED_VALUE}\n")
    git(["add", "-f", ".env.example", "cfg.py"], tmp_path)

    proc = run_hook(SECRETS, bash_payload("git commit -m 'config'", tmp_path))

    assert proc.returncode == 2, "a real value in .env.example must not be an allowlist entry"
    assert ".env.example" in proc.stderr, "the real value is a finding in the example file itself"
    assert "cfg.py" in proc.stderr, "and in any other file that repeats it"
    assert REAL_SHAPED_VALUE not in proc.stderr


def test_secrets_passes_a_bracketed_placeholder_that_is_also_in_env_example(tmp_path: Path) -> None:
    """The intended path still works: a placeholder line from the example passes."""
    init_repo(tmp_path)
    line = "DEEPSEEK_API_KEY=<your-deepseek-api-key>"
    (tmp_path / ".env.example").write_text(line + "\n")
    (tmp_path / "docs.md").write_text(f"Copy this line into .env:\n\n    {line}\n")
    git(["add", "docs.md"], tmp_path)

    proc = run_hook(SECRETS, bash_payload("git commit -m 'docs'", tmp_path))

    assert proc.returncode == 0, proc.stderr


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


def test_secrets_blocks_a_real_value_under_a_credential_shaped_name(tmp_path: Path) -> None:
    """A key-shaped name with a real value is refused whatever the value looks like."""
    init_repo(tmp_path)
    (tmp_path / ".env.example").write_text("POSTGRES_PASSWORD=<your-postgres-password>\n")
    (tmp_path / "cfg.py").write_text(f"POSTGRES_PASSWORD={REAL_SHAPED_VALUE}\n")
    git(["add", "cfg.py"], tmp_path)

    proc = run_hook(SECRETS, bash_payload("git commit -m 'config'", tmp_path))

    assert proc.returncode == 2
    assert "cfg.py" in proc.stderr
    assert REAL_SHAPED_VALUE not in proc.stderr


def test_secrets_misses_a_credential_under_a_name_without_a_credential_suffix(
    tmp_path: Path,
) -> None:
    """The known gap, pinned so a fix has to change this test.

    `WARRANT_DB_DSN='postgres://user:password@host/db'` carries a live password
    and the hook lets it through, because the assignment rule keys on the name
    and the value matches no key pattern. Closing it means either a DSN-shaped
    pattern or a check that does not depend on the name at all.
    """
    init_repo(tmp_path)
    value = f"postgres://warrant:{REAL_SHAPED_VALUE}@localhost:5432/warrant"
    (tmp_path / "cfg.py").write_text(f"WARRANT_DB_DSN='{value}'\n")
    git(["add", "cfg.py"], tmp_path)

    proc = run_hook(SECRETS, bash_payload("git commit -m 'config'", tmp_path))

    assert proc.returncode == 0, "if the hook now catches this, update this test and the docs"


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


def test_double_run_blocks_the_eval_runner_with_no_emit_flag(tmp_path: Path) -> None:
    """W15's runner is a run, even though it has no `--emit` flag.

    The ported Receipts hook only recognized `-m evals.run` when `--emit` was
    present, so every Warrant eval run was invisible to the guard.
    """
    marker = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)", "warrant-eval-marker"]
    )
    env = {**os.environ, "WARRANT_RUN_PATTERN": "warrant-eval-marker"}
    try:
        time.sleep(0.3)
        proc = run_hook(
            DOUBLE,
            bash_payload("uv run python -m evals.run --scenarios 08 --ablations full", tmp_path),
            env=env,
        )
    finally:
        marker.kill()
        marker.wait(timeout=10)

    assert proc.returncode == 2
    assert "already running" in proc.stderr


def test_double_run_passes_when_nothing_is_running(tmp_path: Path) -> None:
    proc = run_hook(
        DOUBLE,
        bash_payload(
            "uv run python scripts/dsh_run.py --effort low --session t 'print(1)'", tmp_path
        ),
    )

    assert proc.returncode == 0
    assert proc.stderr == ""


def test_double_run_passes_when_only_a_shell_mentions_the_runner(tmp_path: Path) -> None:
    """A shell whose argv names the runner is not a running runner.

    The default pattern matches any command line naming `scripts/dsh_run.py`, so
    a shell that merely mentions the file counted as a run and refused the next
    one. Only a process shaped like a run may block.
    """
    marker = subprocess.Popen(["bash", "-c", "sleep 30; : scripts/dsh_run.py"])
    try:
        time.sleep(0.3)
        proc = run_hook(
            DOUBLE,
            bash_payload(
                "uv run python scripts/dsh_run.py --effort low --session t 'print(1)'", tmp_path
            ),
        )
    finally:
        marker.kill()
        marker.wait(timeout=10)

    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""


def test_double_run_blocks_a_runner_shaped_process_by_default(tmp_path: Path) -> None:
    """A real runner process blocks with no pattern override.

    The process runs a script named `dsh_run.py`, so it has the shape the default
    scan looks for even though no marker pattern is set.
    """
    script = tmp_path / "scripts" / "dsh_run.py"
    script.parent.mkdir()
    script.write_text("import time\ntime.sleep(30)\n")
    marker = subprocess.Popen([sys.executable, str(script)])
    try:
        time.sleep(0.3)
        proc = run_hook(
            DOUBLE,
            bash_payload(
                "uv run python scripts/dsh_run.py --effort low --session t 'print(1)'", tmp_path
            ),
        )
    finally:
        marker.kill()
        marker.wait(timeout=10)

    assert proc.returncode == 2
    assert "already running" in proc.stderr
    assert str(marker.pid) in proc.stderr


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


def test_lint_hook_reads_the_target_listing_this_make_prints() -> None:
    """The lint hook must find this repository's `lint` target.

    If the target listing is misread, the hook decides there is no lint target
    and skips the check, which looks exactly like a passing lint. Asserting the
    predicate directly is what tells "green" apart from "not checked".
    """
    lint_hook = _load(LINT)

    assert lint_hook.lint_target_exists(REPO)


# --- guard_merge -----------------------------------------------------------

MERGE = "gh pr merge 9 --merge --delete-branch"
GREEN_MAKEFILE = "test:\n\t@true\nlint:\n\t@true\n"


def green_repo(path: Path, makefile: str = GREEN_MAKEFILE) -> None:
    """A repository whose tip contains `origin/main` and whose tree is clean.

    `origin/main` is a ref in this repository rather than a remote, because the
    hook asks a question about refs (`merge-base --is-ancestor`), not about the
    network. It points at the tip, after every commit here.
    """
    init_repo(path)
    (path / "README.md").write_text("green\n")
    (path / "Makefile").write_text(makefile)
    git(["add", "README.md", "Makefile"], path)
    git(["commit", "-q", "-m", "base"], path)
    git(["update-ref", "refs/remotes/origin/main", "HEAD"], path)


def test_guard_blocks_a_red_test_target(tmp_path: Path) -> None:
    green_repo(tmp_path, "test:\n\t@echo 'two failed' >&2; exit 1\nlint:\n\t@true\n")

    proc = run_hook(GUARD, bash_payload(MERGE, tmp_path))

    assert proc.returncode == 2
    assert "make test" in proc.stderr
    assert "two failed" in proc.stderr, "the failing output is what tells the caller what broke"
    assert proc.stdout == ""


def test_guard_blocks_a_red_lint_target(tmp_path: Path) -> None:
    green_repo(tmp_path, "test:\n\t@true\nlint:\n\t@echo 'ruff is red' >&2; exit 1\n")

    proc = run_hook(GUARD, bash_payload(MERGE, tmp_path))

    assert proc.returncode == 2
    assert "make lint" in proc.stderr
    assert "ruff is red" in proc.stderr


def test_guard_blocks_when_the_test_target_is_missing(tmp_path: Path) -> None:
    """A target it cannot run is not a pass. This is the fail-closed half."""
    green_repo(tmp_path, "lint:\n\t@true\n")

    proc = run_hook(GUARD, bash_payload(MERGE, tmp_path))

    assert proc.returncode == 2
    assert "there is no `test` target" in proc.stderr


def test_guard_blocks_a_behind_branch(tmp_path: Path) -> None:
    """`origin/main` not being an ancestor is the rebase-owed case.

    A separate branch plays `main`: `origin/main` points at a commit this branch
    does not contain, which is what a branch that owes a rebase looks like from
    here. The tree stays clean, so the ancestry check is the only thing that can
    refuse it.
    """
    green_repo(tmp_path)
    here = git(["symbolic-ref", "--short", "HEAD"], tmp_path).stdout.strip()
    git(["checkout", "-q", "-b", "remote-main"], tmp_path)
    (tmp_path / "remote.txt").write_text("a commit on main this branch lacks\n")
    git(["add", "remote.txt"], tmp_path)
    git(["commit", "-q", "-m", "on main"], tmp_path)
    git(["update-ref", "refs/remotes/origin/main", "HEAD"], tmp_path)
    git(["checkout", "-q", here], tmp_path)
    git(["branch", "-q", "-D", "remote-main"], tmp_path)

    proc = run_hook(GUARD, bash_payload(MERGE, tmp_path))

    assert proc.returncode == 2
    assert "not an ancestor" in proc.stderr
    assert "rebase" in proc.stderr


def test_guard_blocks_when_there_is_no_origin_main(tmp_path: Path) -> None:
    green_repo(tmp_path)
    git(["update-ref", "-d", "refs/remotes/origin/main"], tmp_path)

    proc = run_hook(GUARD, bash_payload(MERGE, tmp_path))

    assert proc.returncode == 2
    assert "no `origin/main`" in proc.stderr
    assert "fetch" in proc.stderr


def test_guard_blocks_a_dirty_tree(tmp_path: Path) -> None:
    green_repo(tmp_path)
    (tmp_path / "README.md").write_text("edited but not committed\n")

    proc = run_hook(GUARD, bash_payload(MERGE, tmp_path))

    assert proc.returncode == 2
    assert "not clean" in proc.stderr
    assert "README.md" in proc.stderr


def test_guard_blocks_an_untracked_file(tmp_path: Path) -> None:
    """`git status --porcelain` reports untracked files, so they count as dirty."""
    green_repo(tmp_path)
    (tmp_path / "notes.txt").write_text("scratch\n")

    proc = run_hook(GUARD, bash_payload(MERGE, tmp_path))

    assert proc.returncode == 2
    assert "notes.txt" in proc.stderr


def test_guard_blocks_when_the_directory_is_not_a_repository(tmp_path: Path) -> None:
    proc = run_hook(GUARD, bash_payload(MERGE, tmp_path))

    assert proc.returncode == 2
    assert "no git repository" in proc.stderr


def test_guard_passes_a_green_current_clean_branch(tmp_path: Path) -> None:
    green_repo(tmp_path)

    proc = run_hook(GUARD, bash_payload(MERGE, tmp_path))

    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    assert proc.stdout == ""


def test_guard_follows_cd_to_the_repository_it_judges(tmp_path: Path) -> None:
    """The checks belong to the repository the merge lands in, not the shell's."""
    green_repo(tmp_path)
    elsewhere = tmp_path.parent / f"{tmp_path.name}-elsewhere"
    init_repo(elsewhere)

    blocked = run_hook(GUARD, bash_payload(f"cd {tmp_path} && {MERGE}", elsewhere))
    allowed = run_hook(GUARD, bash_payload(MERGE, elsewhere))

    assert blocked.returncode == 0, blocked.stderr
    assert allowed.returncode == 2, "the empty directory has nothing to merge"


def test_guard_reads_the_target_listing_this_make_prints() -> None:
    """The annotation is not always on its own line.

    This make joins the target line with the first comment
    (`test: #  Phony target ...`), so a fixed short window that starts after the
    target line misses `File has been updated` and reports a target that exists
    as missing. That would refuse every merge on this build. Asserting the
    predicate directly, not just the end-to-end refusal, is what keeps a
    formatting change from turning the guard into a wall.
    """
    guards = _load(GUARD)

    assert guards.make_target_exists(REPO, "test")
    assert guards.make_target_exists(REPO, "lint")
    assert not guards.make_target_exists(REPO, "no-such-target-here")


def test_guard_passes_commands_that_are_not_a_merge(tmp_path: Path) -> None:
    """Viewing a pull request, or asking for help, lands nothing."""
    green_repo(tmp_path)
    for command in ("gh pr view 9", "gh pr merge --help", "git merge main", "gh pr list"):
        proc = run_hook(GUARD, bash_payload(command, tmp_path))

        assert proc.returncode == 0, f"{command}: {proc.stderr}"


def test_guard_passes_a_merge_inside_a_heredoc(tmp_path: Path) -> None:
    """A document is not a command, so a quoted example is not a merge."""
    green_repo(tmp_path)

    proc = run_hook(GUARD, bash_payload(f"cat <<'EOF' > notes.md\n{MERGE}\nEOF", tmp_path))

    assert proc.returncode == 0, proc.stderr


def clean_repo(path: Path) -> None:
    """A one-commit repository whose tip is `origin/main` and whose tree is dry.

    The stand-in tests need the ancestry and cleanliness checks to pass, and
    they need a tree that is not this checkout, which carries the branch's own
    uncommitted work while the tests run.
    """
    init_repo(path)
    (path / "README.md").write_text("base\n")
    git(["add", "README.md"], path)
    git(["commit", "-q", "-m", "base"], path)
    git(["update-ref", "refs/remotes/origin/main", "HEAD"], path)


def stub_makefile(directory: Path, recipe: str) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "Makefile").write_text(recipe)
    return str(directory / "Makefile")


def test_guard_runs_both_targets_in_order(tmp_path: Path) -> None:
    """The guard runs `make test` then `make lint`, through a real `make`.

    The stand-in Makefile makes the second target fail unless the first one ran,
    so a guard that skipped `test` or ran them in the other order fails here.
    The repository is a one-commit scratch repo, so the ancestry and cleanliness
    checks pass and the make step is the thing under test.
    """
    repo = tmp_path / "repo"
    clean_repo(repo)
    makefile = stub_makefile(
        tmp_path / "stub",
        "test:\n\t@printf ran-test > marker.txt\nlint:\n\t@grep -q ran-test marker.txt\n",
    )
    env = {**os.environ, "DSH_GUARD_MAKEFILE": makefile}

    proc = run_hook(GUARD, bash_payload(MERGE, repo), env=env)

    assert proc.returncode == 0, proc.stderr


def test_guard_reports_the_failing_target_from_the_stand_in(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    clean_repo(repo)
    makefile = stub_makefile(
        tmp_path / "stub", "test:\n\t@true\nlint:\n\t@echo 'lint is red' >&2; exit 1\n"
    )
    env = {**os.environ, "DSH_GUARD_MAKEFILE": makefile}

    proc = run_hook(GUARD, bash_payload(MERGE, repo), env=env)

    assert proc.returncode == 2
    assert "make lint" in proc.stderr
    assert "lint is red" in proc.stderr


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
    for name in (
        "block_secrets",
        "block_double_emit",
        "block_parked_column",
        "lint_after_commit",
        "guard_merge",
    ):
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
    """Every per-hook timeout fits the bridge default the profile installs.

    The cap is read from `infra/dsh/core.patch.yml` rather than written here, so
    a longer suite raises one number in the profile and the hooks that name a
    per-hook timeout are checked against the new value. The old hardcoded 90
    seconds was the cap the merge guard outgrew: the suite now runs past it, so
    the profile raises the default and `.dsh/hooks.json` raises the guard with
    it.
    """
    cap_s = bridge_timeout_ms() // 1000
    config = load_hook_config()
    hooks = [h for groups in config.values() for group in groups for h in group["hooks"]]

    assert cap_s > 0
    for hook in hooks:
        assert 0 < int(hook["timeout"]) <= cap_s


def bridge_timeout_ms() -> int:
    """The bridge's default hook timeout in milliseconds, from the profile.

    A regex rather than a YAML load: the profile carries a `!!js` tag the
    standard loader refuses, and the one scalar this needs is on a line of its
    own.
    """
    match = re.search(r"^\s*defaultTimeoutMs:\s*(\d+)", PROFILE.read_text(encoding="utf-8"), re.M)
    if match is None:
        raise AssertionError(f"{PROFILE} names no defaultTimeoutMs")
    return int(match.group(1))
