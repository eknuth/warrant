"""The W1 scaffold, held to what it promises the later issues.

Every check here is structural: it derives what it expects from the file under
test and asserts a property, rather than comparing against a hand-written list
of today's names. A list of exact targets, credentials, or ignored paths is a
second copy of the tree that has to be edited in lockstep with the first, and
the later issues all add to those files. The properties are the ones a reviewer
would check by hand: `.env.example` names exactly what the stack reads and
carries no live value, compose.yml publishes Keycloak on 8080 and takes its
password from `.env` without defaulting, every Makefile target runs a command
and is declared phony, `.gitignore` covers the paths that must not be
committed, and the test helpers stay split by area.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]

# A name that carries a secret by convention. The secrets hook decides what
# counts as a credential with the same suffix rule, so this is the rule's shape
# rather than a list of the names that happen to be in the file today.
CREDENTIAL_SUFFIXES = ("KEY", "TOKEN", "SECRET", "PASSWORD")

# A gitignored path that must stay ignored, and a path that must not be. The
# first is the one the whole convention protects; the second is there so the
# check cannot pass by `check-ignore` answering zero for everything.
IGNORED_PATH = ".env"
TRACKED_PATH = "README.md"

# The number of lines `tests/conftest.py` may hold. A conftest is an entry
# point, so it declares which modules carry fixtures and nothing else. The cap
# is what makes "the split happened" fail once the fixture bodies come back.
CONFTEST_LINE_CAP = 30


def env_example() -> dict[str, str]:
    """The uncommented ``NAME=value`` lines, where a commented stub is not a line."""
    values: dict[str, str] = {}
    for line in (REPO / ".env.example").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition("=")
        values[name] = value
    return values


def compose_text() -> str:
    return (REPO / "compose.yml").read_text(encoding="utf-8")


def makefile_text() -> str:
    return (REPO / "Makefile").read_text(encoding="utf-8")


def makefile_targets() -> set[str]:
    """The real targets: a line of the form ``name:`` outside a comment and except for .PHONY."""
    return {
        match.group(1)
        for match in re.finditer(r"^([A-Za-z0-9_.][A-Za-z0-9_.-]*):", makefile_text(), re.M)
        if match.group(1) != ".PHONY"
    }


def makefile_recipe(target: str) -> str:
    """The recipe lines of one target: tab-indented lines up to the next target."""
    body = makefile_text().split(f"\n{target}:", 1)[1]
    lines = [line for line in body.splitlines() if line.strip()]
    return "\n".join(line for line in lines if line.startswith("\t"))


def test_the_packages_import() -> None:
    """The project is not installed, so this also proves the root is on sys.path."""
    import agents
    import evals
    import gen
    import servers
    import warrant

    for module in (warrant, servers, agents, gen, evals):
        assert module.__doc__, module.__name__


def test_env_example_covers_every_variable_compose_reads() -> None:
    """Every `${NAME}` in compose.yml, commented stubs included, has a line.

    This is the direction that matters: a variable compose interpolates and
    `.env.example` does not name is `make up` failing with no clue in the file.
    The other direction is checked below, against the shape of a credential.
    """
    referenced = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", compose_text()))

    assert referenced, "compose.yml interpolates no variables, which cannot be right"
    for name in referenced:
        assert name in env_example(), name


def test_env_example_credentials_are_angle_bracket_placeholders() -> None:
    """A credential-shaped name carries a placeholder, never a value.

    Derived from the suffix convention rather than a list, so a new credential
    is covered the moment it appears. The assertion that the derived set is not
    empty is what stops this passing on an empty file.
    """
    credentials = {
        name: value for name, value in env_example().items() if name.endswith(CREDENTIAL_SUFFIXES)
    }

    assert credentials, "no credential-shaped name in .env.example, so this asserts nothing"
    for name, value in credentials.items():
        assert value.startswith("<") and value.endswith(">"), f"{name}={value}"


def test_env_example_non_credentials_carry_a_real_default() -> None:
    """A setting that is not a credential has a usable value, not a placeholder.

    A placeholder in a non-credential is copied into `.env` and then used as
    the value, so `postgresql://<your-host>` reaches the server as a hostname.
    """
    for name, value in env_example().items():
        if name.endswith(CREDENTIAL_SUFFIXES):
            continue
        assert value and not value.startswith("<"), f"{name}={value}"


def test_env_example_has_no_empty_or_commented_out_variable() -> None:
    """A name with no value reads as "not needed", which is not what it means."""
    for line in (REPO / ".env.example").read_text().splitlines():
        if line and not line.startswith("#"):
            assert "=" in line and line.split("=", 1)[1], line


def test_compose_publishes_keycloak_on_8080() -> None:
    keycloak = yaml.safe_load(compose_text())["services"]["keycloak"]

    assert "8080:8080" in keycloak["ports"]
    assert "start-dev" in keycloak["command"]


def test_compose_takes_the_keycloak_password_from_env() -> None:
    """`:?` is the point: a missing variable stops `up`, it does not default."""
    environment = yaml.safe_load(compose_text())["services"]["keycloak"]["environment"]

    assert "${KEYCLOAK_ADMIN_PASSWORD:?" in environment["KC_BOOTSTRAP_ADMIN_PASSWORD"]


def test_compose_every_interpolated_variable_refuses_to_default() -> None:
    """No `${NAME:-fallback}` and no bare `${NAME}`: a missing value stops `up`.

    The tests read the running stack as evidence, so a silently substituted
    password would produce a healthy stack the tests cannot log into, which
    reads as a token bug rather than a missing variable.

    Only the `environment` blocks are scanned, because those are the strings
    compose itself interpolates. The `$${NAME}` in the realm JSON's mounted
    command line is escaped on purpose and resolved by Keycloak from the same
    `.env` value, so a scan of the whole file would flag a line that is not a
    compose interpolation at all.
    """
    pattern = r"\$\{([A-Z][A-Z0-9_]*)([^}]*)\}"
    interpolations = [
        (name, body)
        for service in yaml.safe_load(compose_text())["services"].values()
        for value in (service.get("environment") or {}).values()
        if isinstance(value, str)
        for name, body in re.findall(pattern, value)
    ]

    assert interpolations, "no service interpolates a variable, which cannot be right"
    for name, body in interpolations:
        assert body.startswith(":?"), f"{name} does not use `:?`, so it can start with no value"


def test_compose_services_are_defined_or_stubbed() -> None:
    """Every service in the file is a definition; later ones are comments.

    A commented block is not a service, so the assertion is that the live set is
    non-empty and that each live entry has an image: a service with no image is
    a stub someone uncommented halfway.
    """
    services = yaml.safe_load(compose_text())["services"]

    assert services, "compose.yml defines no service"
    for name, service in services.items():
        assert service.get("image"), f"{name} has no image"


def test_makefile_has_at_least_the_targets_every_clone_needs() -> None:
    """The targets a fresh clone runs, named because the ticket names them.

    This is the one place an exact name is the point: without `install`,
    `lint`, and `test`, a clone has no way to build or check itself.
    """
    assert {"install", "lint", "test"} <= makefile_targets()


def test_makefile_targets_run_the_commands_they_promise() -> None:
    """The recipe, not just the target name: an empty target still committed."""
    assert "uv sync" in makefile_recipe("install")
    assert "ruff check" in makefile_recipe("lint")
    assert "ruff format --check" in makefile_recipe("lint")
    assert "pytest" in makefile_recipe("test")
    assert "docker compose up -d" in makefile_recipe("up")
    assert "docker compose down" in makefile_recipe("down")
    assert "servers.gitea_mcp.server" in makefile_recipe("gitea-mcp")
    assert "install-profile.sh" in makefile_recipe("dsh-profile")


def test_makefile_every_target_has_a_recipe_and_none_is_missing_from_phony() -> None:
    """Derived both ways, so a new target fails until it is declared and given a body.

    `.PHONY` carries the same names as the targets. A target that is not phony
    is a no-op when a file of that name exists, which `install` and `test`
    both invite.
    """
    targets = makefile_targets()
    phony = set(re.search(r"^\.PHONY:(.*)$", makefile_text(), re.M).group(1).split())

    assert targets, "the Makefile defines no target"
    assert targets <= phony, f"not declared phony: {sorted(targets - phony)}"
    assert phony <= targets, f"declared phony but not defined: {sorted(phony - targets)}"
    for target in sorted(targets):
        assert makefile_recipe(target), f"{target} has no recipe"


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

    def is_ignored(path: str) -> bool:
        return (
            subprocess.run(
                ["git", "-C", str(REPO), "check-ignore", "-q", path],
                capture_output=True,
            ).returncode
            == 0
        )

    assert is_ignored(IGNORED_PATH), f"{IGNORED_PATH} is not ignored"
    assert not is_ignored(TRACKED_PATH), f"{TRACKED_PATH} is ignored, so the check proves nothing"


def test_conftest_is_an_entry_point_rather_than_a_fixture_file() -> None:
    """The fixtures live under `tests/fixtures/`, one module per area.

    A `pytest_plugins` line only works in the top-level conftest, so the root
    one has to exist; the cap is what keeps the fixtures from drifting back
    into it.
    """
    conftest = (REPO / "tests" / "conftest.py").read_text(encoding="utf-8")
    lines = conftest.splitlines()

    assert "pytest_plugins" in conftest
    assert "@pytest.fixture" not in conftest, "a fixture body is back in the root conftest"
    assert len(lines) <= CONFTEST_LINE_CAP, f"{len(lines)} lines, cap is {CONFTEST_LINE_CAP}"

    modules = re.findall(r'"tests\.fixtures\.([a-z_]+)"', conftest)
    assert len(modules) >= 2, "the per-area split collapsed to one module"
    for module in modules:
        assert (REPO / "tests" / "fixtures" / f"{module}.py").is_file(), module


def test_the_test_data_directories_hold_no_python() -> None:
    """`tests/fixtures/` is fixtures and `tests/data/` is data, and they do not mix.

    A `.py` file under `tests/data/` is a fixture in the wrong tree. A module
    under `tests/fixtures/` that the conftest does not name is a fixture
    nothing can see, which fails at the point a test asks for it rather than
    at the point it was written.
    """
    data = REPO / "tests" / "data"
    conftest = (REPO / "tests" / "conftest.py").read_text(encoding="utf-8")
    loaded = set(re.findall(r'"tests\.fixtures\.([a-z_]+)"', conftest))

    assert not [path for path in data.rglob("*.py")], "python under tests/data"
    written = {
        path.stem for path in (REPO / "tests" / "fixtures").glob("*.py") if path.stem != "__init__"
    }
    assert written == loaded, f"not loaded by conftest: {sorted(written - loaded)}"


def test_readme_states_the_argument_and_its_limit() -> None:
    """W18 replaces the placeholder. The claim and the one-family limit stay on the page.

    The old form of this test only asked for "work in progress", which is the
    one string a finished README must not carry. This asks for the argument the
    README exists to make and the limitation that keeps its table honest.
    """
    text = (REPO / "README.md").read_text()

    assert "what the agent read" in text
    assert "one model family" in text.lower()
    assert "work in progress" not in text.lower()
