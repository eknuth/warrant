# Warrant. Every target runs from a checkout of this repository.

# uv keeps its cache under `$UV_CACHE_DIR`, which defaults to `~/.cache/uv`. A
# checkout that cannot write there, which is what a sandboxed session is, fails
# every target that shells out to uv before it runs anything. Two of those are
# the project's own checks: the merge guard's `make test` and the post-commit
# lint hook. A checkout-local cache keeps the build self-contained, and a caller
# that sets `UV_CACHE_DIR` still wins over this default.
UV_CACHE_DIR ?= $(CURDIR)/.uv-cache
export UV_CACHE_DIR

# The main checkout's runs directory, absolute. `make up` from a worktree has to
# mount the same directory the seeder writes its graph to, and compose resolves
# a relative bind source against the directory the command runs from. Deriving
# the path from `scripts/repo_root.sh` makes the mount checkout-independent, so
# a stack started from a worktree still shares one graph with the seeder.
REPO_ROOT := $(shell bash scripts/repo_root.sh)
WARRANT_RUNS_HOST_DIR ?= $(REPO_ROOT)/runs
export WARRANT_RUNS_HOST_DIR

.PHONY: install lint test up down reset gitea-mcp postgres-mcp mail-mcp dsh-profile worktree worktree-clean evals smoke qwen-smoke jev-smoke matrix throughput queue

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
	@mkdir -p "$(WARRANT_RUNS_HOST_DIR)" "$(WARRANT_RUNS_HOST_DIR)/graph"
	docker compose up -d --wait

down:
	docker compose down

# `-v` drops the named volumes, so this brings the stack back empty: an empty
# Keycloak realm store, and later an empty database and mailbox.
reset:
	docker compose down -v
	@mkdir -p "$(WARRANT_RUNS_HOST_DIR)" "$(WARRANT_RUNS_HOST_DIR)/graph"
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

# W15. The full matrix: every scenario under every ablation, three repeats. The
# runner rebuilds the image, seeds each cell, restarts the gateway into the
# ablation, runs the tasks, grades, and renders the column's report. W17 runs
# this and analyzes it; the target exists so the command is one word.
evals:
	@if [ -z "$(COLUMN)" ]; then echo "usage: make evals COLUMN=<name>" >&2; exit 2; fi
	uv run python -m evals.run --scenarios all --ablations all --repeats 3 --column "$(COLUMN)"

# W15. The two-scenario smoke the acceptance criteria name: 08 and 01 once under
# `full`, end to end with a real model, then the column's report.
smoke:
	uv run python -m evals.run --scenarios 08,01 --ablations full --repeats 1 --column smoke

# W22. The second model family's smoke: the full ablation on four scenarios,
# one repeat, through the local endpoint. The column is resumable, so the same
# command continues an interrupted run; `ARGS="--force"` reruns a graded cell.
qwen-smoke:
	uv run python -m evals.run --scenarios 01,08,09,10 --ablations full --repeats 1 \
		--models qwen-local:qwen3.8:27b@off --column smoke $(ARGS)

# W24. The two Jev columns' smoke: the typed provenance classifier and the
# model-staffed decision on four scenarios, one repeat. It needs JEV_API_KEY in
# `.env`; the column is resumable, so the same command continues an interrupted
# run and `ARGS="--force"` reruns a graded cell.
jev-smoke:
	uv run python -m evals.run --scenarios 01,08,09,10 --ablations jev,jev-only --repeats 1 \
		--column w24-smoke $(ARGS)

# W22. The full second-family column: every scenario, every ablation, three
# repeats, through the local endpoint. Run it long. A cell that already holds a
# grade.json is skipped, so the same command resumes after an interruption;
# `ARGS="--force"` reruns. `evals.throughput` measures the finished column.
matrix:
	@if [ -z "$(COLUMN)" ]; then echo "usage: make matrix COLUMN=<name>" >&2; exit 2; fi
	uv run python -m evals.run --scenarios all --ablations all --repeats 3 \
		--models qwen-local:qwen3.8:27b@off --column "$(COLUMN)" $(ARGS)

# W22. Tokens per second and the full-column estimate from a column's cells.
throughput:
	@if [ -z "$(COLUMN)" ]; then echo "usage: make throughput COLUMN=<name>" >&2; exit 2; fi
	uv run python -m evals.throughput --column "$(COLUMN)"

# W16. The human queue: what is waiting, and the answer to one entry.
# `make queue` lists the pending escalations; `make queue ARGS="approve <id>
# --minutes 10"` approves one with a time box and mints its grant.
queue:
	uv run python -m warrant queue $(or $(ARGS),list)
