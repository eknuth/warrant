"""The W1 scaffold, held to what it promises the later issues.

Every check here is one a reviewer would otherwise run by hand: the five
packages import, `.env.example` names exactly the variables the stack reads and
carries no live value, compose.yml publishes Keycloak on 8080 and takes its
password from `.env`, every Makefile target runs the command it promises, and
`.gitignore` covers the paths that must not be committed.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]

ENV_NAMES = (
    "KEYCLOAK_ADMIN_PASSWORD",
    "WARRANT_USER_PASSWORD",
    "WARRANT_AGENT_CLIENT_SECRET",
    "GITEA_ADMIN_TOKEN",
    "GITEA_URL",
    "FORGE",
    "POSTGRES_PASSWORD",
    "DEEPSEEK_API_KEY",
    "LINEAR_API_KEY",
    "WARRANT_MODEL",
    "ADJUDICATOR_MODEL",
)

# Written out rather than derived from ENV_NAMES. The secrets hook decides what
# counts as a credential with the same suffix rule, so a list computed that way
# cannot fail when the rule is what is wrong. A name that carries a live secret
# and does not end in KEY, TOKEN, SECRET, or PASSWORD is the gap in the hook, and
# tests/hooks/test_port.py pins the hook half of it.
CREDENTIAL_NAMES = (
    "KEYCLOAK_ADMIN_PASSWORD",
    "WARRANT_USER_PASSWORD",
    "WARRANT_AGENT_CLIENT_SECRET",
    "GITEA_ADMIN_TOKEN",
    "POSTGRES_PASSWORD",
    "DEEPSEEK_API_KEY",
    "LINEAR_API_KEY",
)

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


def test_env_example_names_exactly_the_variables_the_stack_reads() -> None:
    """Set equality, not containment: a stale name is also a defect.

    Containment would pass with an empty list on one side, and with a name that
    later services no longer read.
    """
    values = env_example()

    assert set(ENV_NAMES) == set(values)


def test_env_example_covers_every_variable_compose_reads() -> None:
    """Every `${NAME}` in compose.yml, commented stubs included, has a line."""
    text = (REPO / "compose.yml").read_text()
    referenced = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", text))

    assert referenced, "compose.yml interpolates no variables, which cannot be right"
    for name in referenced:
        assert name in env_example(), name


def test_env_example_credentials_are_angle_bracket_placeholders() -> None:
    values = env_example()

    assert CREDENTIAL_NAMES, "the credential list is empty, so this asserts nothing"
    for name in CREDENTIAL_NAMES:
        assert values[name].startswith("<") and values[name].endswith(">"), name


def test_credential_names_match_the_names_that_look_like_credentials() -> None:
    """The hand-written list and the naming convention agree.

    A new credential-shaped name in `.env.example` that is missing from the list
    fails here, which is the check that a derived list could not make.
    """
    suffixes = ("KEY", "TOKEN", "SECRET", "PASSWORD")
    derived = {name for name in env_example() if name.endswith(suffixes)}

    assert derived == set(CREDENTIAL_NAMES)


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


def test_compose_ships_keycloak_and_gitea_and_stubs_the_rest() -> None:
    """W3 uncommented Gitea; postgres and mailpit are still stubs."""
    text = (REPO / "compose.yml").read_text()

    assert set(yaml.safe_load(text)["services"]) == {"keycloak", "gitea"}
    for later in ("postgres", "mailpit"):
        assert f"#  {later}:" in text, later


def makefile_recipe(target: str) -> str:
    """The recipe lines of one target, without the other targets' bodies."""
    body = (REPO / "Makefile").read_text().split(f"\n{target}:", 1)[1]
    lines = [line for line in body.splitlines() if line.strip()]
    return "\n".join(line for line in lines if line.startswith("\t"))


def test_makefile_targets_run_the_commands_they_promise() -> None:
    """The recipe, not just the target name: an empty target still committed."""
    assert "uv sync" in makefile_recipe("install")
    assert "ruff check" in makefile_recipe("lint")
    assert "ruff format --check" in makefile_recipe("lint")
    assert "pytest" in makefile_recipe("test")
    assert "docker compose up -d" in makefile_recipe("up")
    assert "docker compose down" in makefile_recipe("down")
    assert "install-profile.sh" in makefile_recipe("dsh-profile")


def test_makefile_has_every_documented_target() -> None:
    text = (REPO / "Makefile").read_text()

    for target in MAKE_TARGETS:
        assert f"\n{target}:" in text, target


def test_make_reset_drops_the_volumes_before_starting_again() -> None:
    body = makefile_recipe("reset")

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
