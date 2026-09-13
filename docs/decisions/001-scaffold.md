# 001. The W1 scaffold

Date: 2026-09-13. Status: accepted.

## Decision

W1 fills in the tree around what W0 landed: a `uv` project with the dependencies the later issues
name, a compose skeleton with Keycloak and commented stubs for gitea, postgres, and mailpit, the
`install`, `lint`, `test`, `up`, `down`, and `reset` targets in the Makefile, `.env.example`, and
`LICENSE`. The packages under `warrant/`, `servers/`, `agents/`, `gen/`, and `evals/` are
docstring-only placeholders, so the import paths exist before the code that fills them does.
`tests/test_scaffold.py` holds the scaffold itself to these promises, which is what a reviewer would
otherwise check by hand.

## Choices worth naming

`package = false` stays, and `pythonpath = ["."]` in `[tool.pytest.ini_options]` replaces what an
installed package would have given. Every command in this repository runs from the checkout with
`uv run python -m <module>`, so nothing needs a wheel, and building one would mean listing five
top-level packages in the hatch config for no gain. The cost is that a test has to run under pytest
for the repository root to be importable.

`.python-version` pins 3.12. `requires-python = ">=3.12"` lets `uv` take the newest interpreter on
the machine, which is 3.14 here, and the project's Python is 3.12. The file is how that stays true
on a clean clone. It is not in the issue's tree and is the one file added beyond it.

`.env.example` carries real defaults for `WARRANT_MODEL` and `ADJUDICATOR_MODEL` and angle-bracket
placeholders for the four credentials. The secrets hook inspects names ending in `KEY`, `TOKEN`,
`SECRET`, or `PASSWORD`, so a model name is not something it has an opinion about, and a placeholder
in its place would be copied into `.env` and then used as a model name.

`compose.yml` takes the Keycloak password as `${KEYCLOAK_ADMIN_PASSWORD:?...}`. A default would let
`make up` start a service with a password nobody chose, and the failure names the variable to add.
The image is pinned to `26.7.3` and uses the `KC_BOOTSTRAP_ADMIN_*` names, which is what 26.x reads;
`KEYCLOAK_ADMIN` and `KEYCLOAK_ADMIN_PASSWORD`, which most published snippets still show, are
ignored from 26.0 on.

`.gitignore` ignores `evals/results/` as a directory rather than with a keep-file, because git
cannot re-include a file whose parent directory is excluded. The runner (W14) creates the directory.

`ruff format` and `ruff check --fix` touched `.dsh/hooks/block_secrets.py`, `scripts/dsh_run.py`, and
`tests/hooks/test_port.py`. W0 shipped no lint target, so those files had never been run through the
formatter. The changes are line wrapping and the `datetime.UTC` alias, and the hook tests are what
says the hooks still behave the same.

## Consequences

`make lint` covers the hooks and the runner, so a change to a hook is formatted and linted like the
rest of the tree. `make up` needs `KEYCLOAK_ADMIN_PASSWORD` in `.env`, and the admin console is then
at `http://localhost:8080` on the master realm. Realm configuration is W2's.
