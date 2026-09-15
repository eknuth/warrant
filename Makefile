# Warrant. Every target runs from a checkout of this repository.

# uv keeps its cache under `$UV_CACHE_DIR`, which defaults to `~/.cache/uv`. A
# checkout that cannot write there, which is what a sandboxed session is, fails
# every target that shells out to uv before it runs anything. Two of those are
# the project's own checks: the merge guard's `make test` and the post-commit
# lint hook. A checkout-local cache keeps the build self-contained, and a caller
# that sets `UV_CACHE_DIR` still wins over this default.
UV_CACHE_DIR ?= $(CURDIR)/.uv-cache
export UV_CACHE_DIR

.PHONY: install lint test up down reset gitea-mcp postgres-mcp mail-mcp dsh-profile worktree worktree-clean

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

# The Gitea MCP resource server on :9101. The agent connects to this, so it has
# to be running for a triage run; W4's acceptance command omits it, which is why
# the target exists rather than a line in that command. Foreground on purpose:
# a run that serves requests should be visible, and Ctrl-C stops it.
gitea-mcp:
	uv run python -m servers.gitea_mcp.server

# The postgres MCP resource server on :9102. Same shape as `gitea-mcp`: the
# agent reaches this, so it has to be running for a support run. It reads the
# support database the `postgres` compose service serves.
postgres-mcp:
	uv run python -m servers.postgres_mcp.server

# The mail MCP resource server on :9103. Same shape again: it sends through the
# compose Mailpit and reads it back. Foreground for the same reason.
mail-mcp:
	uv run python -m servers.mail_mcp.server

# Install the dsh profiles from infra/dsh/ into $DSH_HOME (default ~/.dsh).
# Reproducible and idempotent; see infra/dsh/install-profile.sh.
dsh-profile:
	bash infra/dsh/install-profile.sh

# A second checkout for verifying a pull request, for an eval run pinned to a
# commit, or for the recording. Not for building a second issue in parallel:
# one issue branch is open at a time (AGENTS.md, Rules).
#
# It goes inside this checkout, under `.worktrees/`, because that is the one
# place the session's write sandbox allows. `.env` and `.linear.toml` are
# symlinked from the main checkout rather than copied, so a worktree cannot
# drift from its credentials and neither file exists twice. `scripts/repo_root.sh`
# is what finds the main checkout when this runs from inside a worktree.
worktree:
	@if [ -z "$(NAME)" ] || [ -z "$(REF)" ]; then \
		echo "usage: make worktree REF=<ref> NAME=<name>" >&2; exit 2; fi
	@test ! -e ".worktrees/$(NAME)" || { echo "already exists: .worktrees/$(NAME)" >&2; exit 2; }
	@root=$$(bash scripts/repo_root.sh); \
		test -f "$$root/.env" || { echo "no .env in $$root; copy .env.example and fill it in" >&2; exit 1; }
	git worktree add ".worktrees/$(NAME)" "$(REF)"
	@root=$$(bash scripts/repo_root.sh); \
		ln -sfn "$$root/.env" ".worktrees/$(NAME)/.env"; \
		ln -sfn "$$root/.linear.toml" ".worktrees/$(NAME)/.linear.toml"
	cd ".worktrees/$(NAME)" && uv sync
	@echo "worktree ready: .worktrees/$(NAME) on $(REF)"

# Remove one worktree and forget it. `git worktree remove` refuses a worktree
# with uncommitted changes, which is the answer that keeps a verification run
# from being deleted by accident; `--force` is a deliberate second step.
worktree-clean:
	@if [ -z "$(NAME)" ]; then echo "usage: make worktree-clean NAME=<name>" >&2; exit 2; fi
	git worktree remove ".worktrees/$(NAME)"
	git worktree prune
	@echo "removed: .worktrees/$(NAME)"

# --- later issues, commented until the issue that needs them ----------------
# Each block names the target that issue will add, so its purpose is visible
# before the target exists. A commented target is not a target: `make` does not
# see it, and the scaffold test checks `make` rather than this text.
#
# W16, the adjudicator and its human queue.
# adjudicate:
# 	uv run python -m warrant.adjudicator
#
# W22, the matrix run across model families and effort variants.
# matrix:
# 	uv run python -m evals.matrix
