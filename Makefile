# Warrant. Every target runs from a checkout of this repository.

.PHONY: install lint test up down reset dsh-profile

# Create or refresh .venv from pyproject.toml and uv.lock. `uv sync` is also
# what a clean clone runs first; there is no other install step.
install:
	uv sync

# `ruff check` reports the errors, `ruff format --check` the drift. Neither
# rewrites a file: the post-commit hook and Ed both read this as a verdict.
lint:
	uv run ruff check .
	uv run ruff format --check .

test:
	uv run pytest

# The local stack. compose.yml reads every credential from .env in this
# directory, so a missing one stops `up` with the variable's name rather than
# starting a service with the wrong password.
#
# `--wait` blocks until the healthcheck passes. Without it the command returns
# while the JVM is still starting and the realm import has not finished, so
# anything run straight after `make reset` races the import.
up:
	docker compose up -d --wait

down:
	docker compose down

# `-v` drops the named volumes, so this brings the stack back empty: an empty
# Keycloak realm store, and later an empty database and mailbox.
reset:
	docker compose down -v
	docker compose up -d --wait

# Install the dsh profiles from infra/dsh/ into $DSH_HOME (default ~/.dsh).
# Reproducible and idempotent; see infra/dsh/install-profile.sh.
dsh-profile:
	bash infra/dsh/install-profile.sh
