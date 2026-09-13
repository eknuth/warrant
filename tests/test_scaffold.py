"""The W1 scaffold, held to what it promises the later issues.

Every check here is one a reviewer would otherwise run by hand: the packages
import, `.env.example` names every variable the stack reads and carries no
value, compose.yml publishes Keycloak on 8080 and takes its password from
`.env`, the Makefile has the targets AGENTS.md names, and `.gitignore` covers
the paths that must not be committed.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]

ENV_NAMES = [
    "KEYCLOAK_ADMIN_PASSWORD",
    "GITEA_ADMIN_TOKEN",
    "POSTGRES_PASSWORD",
    "DEEPSEEK_API_KEY",
    "WARRANT_MODEL",
    "ADJUDICATOR_MODEL",
]

# The names the secrets hook treats as credentials: these and only these have
# to be angle-bracket placeholders, because a real value would be a value.
CREDENTIAL_NAMES = [name for name in ENV_NAMES if name.endswith(("KEY", "TOKEN", "PASSWORD"))]

MAKE_TARGETS = ["install", "lint", "test", "up", "down", "reset", "dsh-profile"]

IGNORED_PATHS = [".env", ".venv/", "evals/results/grade.json", "__pycache__/x.pyc"]

PACKAGES = ["warrant", "servers", "agents", "gen", "evals"]


def env_example() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (REPO / ".env.example").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition("=")
        values[name] = value
    return values


def test_the_packages_import() -> None:
    """The project is not installed, so this also proves the root is on sys.path."""
    import agents
    import evals
    import gen
    import servers
    import warrant

    for module in (warrant, servers, agents, gen, evals):
        assert module.__doc__, module.__name__


def test_env_example_names_every_variable_the_stack_reads() -> None:
    values = env_example()

    assert set(ENV_NAMES) <= set(values)


def test_env_example_credentials_are_angle_bracket_placeholders() -> None:
    values = env_example()

    for name in CREDENTIAL_NAMES:
        assert values[name].startswith("<") and values[name].endswith(">"), name


def test_env_example_has_no_empty_or_commented_out_variable() -> None:
    """A name with no value reads as "not needed", which is not what it means."""
    for line in (REPO / ".env.example").read_text().splitlines():
        if line and not line.startswith("#"):
            assert "=" in line and line.split("=", 1)[1], line


def test_compose_publishes_keycloak_on_8080() -> None:
    keycloak = yaml.safe_load((REPO / "compose.yml").read_text())["services"]["keycloak"]

    assert "8080:8080" in keycloak["ports"]
    assert "start-dev" in keycloak["command"]


def test_compose_takes_the_keycloak_password_from_env() -> None:
    """`:?` is the point: a missing variable stops `up`, it does not default."""
    environment = yaml.safe_load((REPO / "compose.yml").read_text())["services"]["keycloak"][
        "environment"
    ]

    assert "${KEYCLOAK_ADMIN_PASSWORD:?" in environment["KC_BOOTSTRAP_ADMIN_PASSWORD"]


def test_compose_ships_keycloak_only_and_stubs_the_rest() -> None:
    text = (REPO / "compose.yml").read_text()

    assert set(yaml.safe_load(text)["services"]) == {"keycloak"}
    for later in ("gitea", "postgres", "mailpit"):
        assert f"#  {later}:" in text, later


def test_makefile_has_the_documented_targets() -> None:
    text = (REPO / "Makefile").read_text()

    for target in MAKE_TARGETS:
        assert f"\n{target}:" in text, target


def test_make_reset_drops_the_volumes_before_starting_again() -> None:
    body = (REPO / "Makefile").read_text().split("\nreset:", 1)[1].split("\n\n", 1)[0]

    assert body.index("down -v") < body.index("up -d")


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_gitignore_covers_the_paths_that_must_not_be_committed() -> None:
    if (
        subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
        ).returncode
        != 0
    ):
        pytest.skip("not a git checkout")

    for path in IGNORED_PATHS:
        ignored = subprocess.run(
            ["git", "-C", str(REPO), "check-ignore", "-q", path],
            capture_output=True,
        )
        assert ignored.returncode == 0, f"{path} is not ignored"


def test_readme_states_the_argument_and_that_it_is_unfinished() -> None:
    text = (REPO / "README.md").read_text()

    assert "work in progress" in text.lower()
