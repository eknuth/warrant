# Warrant

Per-action authorization for agents, plus provenance evals. An agent proposes an action, Warrant
decides whether that action is allowed, and the decision is recorded so it can be audited later.
Work is tracked in Linear, team EDW, project "Warrant", issues EDW-1416 and up.

This file is the working agreement for every session in this checkout. It is read by the agent
harness at the start of a session and refreshed after edits, so a rule added here is in force on the
next step. `docs/decisions/` holds the decisions behind this setup.

## Getting oriented

1. Read the Linear issue before writing anything. The issue carries Context, Spec, Acceptance
   criteria, and Out of scope. Read it in full, all four sections.
2. Read this file and the parts of the tree the issue touches.
3. Say what you are about to do in one short paragraph, then do it.

## Rules

- Secrets come only from `.env`, which is gitignored. Never write a key into code, a commit, a
  fixture, a Linear comment, a profile patch, or any file under `runs/`. `.env.example` lists the
  names: every credential is an angle-bracket placeholder, and a setting that is not a credential
  carries its real default, because a placeholder there would be copied into `.env` and then used
  as a value. A hook blocks a commit that stages `.env` or adds a key-shaped line; do not work
  around it, remove the line.
- One issue per branch, named `w<N>-<slug>` where N is the number in the issue title. Branch off
  `main` and nothing else. Commit as Edwin Knuth `<eknuth@gmail.com>`.
- Do not tune the agent or the policies to a scenario. If the agent fails a scenario honestly, fix
  the method, not the prompt for that case. A failure is a finding, and it belongs in the notes.
- Python 3.12, `uv`, `pytest`, `ruff`. `make test` and `make lint` pass before an issue is called
  done. When a change adds a behavior, it adds a test that fails without the change.
- Prose in Ed's voice: plain sentences, zero em dashes anywhere, no rule-of-three flourishes, no
  hedging boilerplate, no "delve". No company names in prose, in comments, or in test names.
- Browser work is Ed's. He drives the browser himself, signed in. An implementer or reviewer
  subagent says what it needs from a browser and stops: a login wall, MFA, a payment step, or any
  change outside a disposable checkout is a reason to stop and ask, not to click.
- The orchestrator session owns Linear: it comments on the issue, moves its state, and posts the
  project status update. Implementer and reviewer children never write to Linear, never push, and
  never open a pull request; the orchestrator does those when `make test` and `make lint` pass.
- When the branch is rebased and `make test` and `make lint` pass, the orchestrator merges its own
  pull request with `gh pr merge --merge --delete-branch`, pulls `main`, moves the issue to Done,
  and comments the pull request link on the issue. Ed reviews after the merge and files follow-ups
  as issues. The `guard_merge.py` hook is what enforces the three conditions, so an attempt to merge
  out of order is refused with the reason rather than noticed afterwards.
- Every pull request body carries `Closes EDW-<n>`, so the issue closes when the pull request
  lands.
- Edit a Linear description only with an append or a targeted patch, never a full replace. A save
  that passes the whole `description` overwrites every section the ticket already had. That is how
  W6 lost its Spec and Acceptance criteria, which Linear cannot restore through its API.
- An issue that has to build on unmerged work stacks on that branch, and the pull request body says
  which branch it is stacked on and why. Once the base pull request merges, retarget the stacked
  pull request to `main` before Ed merges it. A stacked pull request that keeps an unmerged base
  lands on the base branch and never reaches `main`; that happened to W3 and W4, which were reported
  merged while `main` held neither.
- One issue branch is open at a time. The next issue waits for the current pull request to merge,
  even when the two touch different files, because the working tree is shared and a second branch
  changes the tree under the first one's tests.
- Rebase onto `origin/main` before a push and again before a merge; never merge `main` into an issue
  branch. On a `uv.lock` conflict take `main`'s copy and run `uv lock`, rather than resolving the
  lockfile by hand.
- After resolving any conflict, diff the result against both branch tips and account for every line
  that went in. A hasty resolution has silently dropped the other side's work more than once: a
  merge once deleted W5's core, and a scripted replay dropped a file's worth of tests.
- A worktree is for verifying a pull request, for an eval run pinned to a commit, and for the
  recording. It is not a way to build a second issue in parallel; one open issue branch at a time
  still holds. Worktrees live under `.worktrees/<name>` inside this checkout and are created with
  `make worktree REF=<ref> NAME=<name>`, which symlinks `.env` and `.linear.toml` from the checkout
  root and runs `uv sync` there. `make worktree-clean NAME=<name>` removes one. Never under `/tmp`
  and never outside the project: the session's write sandbox allows writes only under the checkout,
  and that is also what keeps a verification run's uncommitted state from being mistaken for the
  main checkout's.
- Every run writes its record to one absolute `WARRANT_RUNS_DIR`, the main checkout's `runs/` by
  default, with the commit sha in each run's `metadata.json`. A run started from a worktree
  therefore lands beside every other run rather than in its own tree, and a surprising number can
  be traced to the code that produced it. `compose.yml` carries a top-level `name: warrant`, so a
  worktree's `make up` finds the same stack the main checkout started.

## Model and effort

There is one DeepSeek cloud model, `deepseek-flash`, reached through the `deepseek-official` route.
"Model size" is not a variable here; reasoning effort is. The Linear label on an issue is the
effort level for its session:

| Label | Effort | Use |
|---|---|---|
| `effort:low` | `low` | Mechanical edits, renames, doc fixes, one-file changes |
| `effort:high` | `high` | The standing default for implementation work |
| `effort:max` | `max` | Adversarial review, a design decision, a stubborn bug |

The profile sets `high` as the default. The picker's Effort menu and `llm-deepseek.reasoningEffort`
override it per session. Two delegation tools carry the effort: `subagent` runs children at `high`
for implementation, and `subagent_review` runs them at `max` for review. A session cannot set a
child's effort per call, because the field that would carry it needs an agent preset.

## Harness

The coding harness is `dsh`, against the DeepSeek cloud API only. There is no other agent CLI in
this project and no other vendor's API anywhere, not for writing the code and not inside the code.
The profile, the hooks, and the skills below are the project's own extension points.

- `dsh --profile warrant` boots the Web UI. `dsh --profile warrant-headless "job"` is the one-shot.
  `make dsh-profile` installs the profiles from `infra/dsh/`, which is how this setup is
  reproducible; the live copies under `$DSH_HOME` are generated, so edit `infra/dsh/core.patch.yml`
  and `infra/dsh/web.patch.yml` and reinstall.
- `AGENTS.md` (this file) is loaded by the `agent-instructions` plugin.
- `.dsh/hooks.json` names five command hooks in `.dsh/hooks/`. They block a commit that stages
  `.env` or adds a key-shaped line, refuse two runs at once, refuse a parked results column at
  three levels, refuse a `gh pr merge` whose branch is not rebased, clean, and green, and warn when
  lint is red after a commit. They run in the session workspace and read the repository the command
  actually acts on, including a `git -C <path>` target or a `cd` before it.
- `.agents/skills/` holds the project skills. `skill-filesystem` discovers them from the project
  root, so they ship with the repository and need no profile change.
- `scripts/dsh_run.py` runs one issue headlessly through the SDK and records the cost to
  `runs/dsh/<session>.json`.

## Skills

| Skill | What it does |
|---|---|
| `/issue-start <ID>` | Read the issue, mark it In Progress, branch `w<N>-<slug>`, delegate to an implementer child |
| `/review [ref]` | Two-lens adversarial review of the current branch, as a fresh child at `max` effort |
| `/status` | Post a project status update to Linear with the health, what landed, what is next, and the blockers |
| `/pass-run <park>` | Before-and-after eval pass. Stub; W15 fills it in |
| `/compare <before> <after>` | Paired comparison of two result columns. Stub; W15 fills it in |
| `/cell <col> <scenario> <n>` | One result cell with its evidence. Stub; W15 fills it in |

## Layout

```
warrant/
  AGENTS.md          this file
  Makefile           install, lint, test, up, down, reset, gitea-mcp, postgres-mcp,
                     mail-mcp, dsh-profile, worktree, worktree-clean
  compose.yml        the local stack: Keycloak, gitea, postgres, mailpit, and
                     the W6 gateway with its upstream
  warrant/           the authorization service (W5, W6)
  servers/           gitea_mcp, postgres_mcp, mail_mcp (W3, W8, W9)
  agents/            providers, triage, support (W4, W10)
  gen/               scenario schema, seeders, scenarios/*.yml (W12, W13)
  evals/             runner, grader, report (W14, W15); results/ is gitignored
  infra/dsh/         profile sources: patches, the sdk manifest, the installer
  .dsh/              hooks.json and the five hook scripts
  .agents/skills/    project skills
  scripts/           dsh_run.py, the headless runner
  docs/decisions/    what was decided and why
  runs/              gitignored run records, including runs/dsh/
  .worktrees/        gitignored verification checkouts, one per name
```

The product packages are placeholders until their issues land. `docs/decisions/001-scaffold.md`
records what W1 chose, including why `.env.example` carries real defaults for the two model
variables.

## Writing prose

A README sentence has to survive someone running the code and checking the number. Do not write a
summary of what a file contains; write what is true and let the file show the rest. Never present
partial numbers as a result.
