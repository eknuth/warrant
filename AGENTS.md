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
  names with angle-bracket placeholders, nothing else. A hook blocks a commit that stages `.env` or
  adds a key-shaped line; do not work around it, remove the line.
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
- Do not push, do not open a pull request, and do not comment on Linear unless the issue says to.
  Ed says when to push, and Ed merges.

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
- `.dsh/hooks.json` names four command hooks in `.dsh/hooks/`. They block a commit that stages
  `.env` or adds a key-shaped line, refuse two runs at once, refuse a parked results column at
  three levels, and warn when lint is red after a commit. They run in the session workspace and
  read the diff of the repository a commit actually lands in, including a `git -C <path>` target.
- `.agents/skills/` holds the project skills. `skill-filesystem` discovers them from the project
  root, so they ship with the repository and need no profile change.
- `scripts/dsh_run.py` runs one issue headlessly through the SDK and records the cost to
  `runs/dsh/<session>.json`.

## Skills

| Skill | What it does |
|---|---|
| `/issue-start <ID>` | Read the issue, mark it In Progress, branch `w<N>-<slug>`, delegate to an implementer child |
| `/review [ref]` | Two-lens adversarial review of the current branch, as a fresh child at `max` effort |
| `/pass-run <park>` | Before-and-after eval pass. Stub; W15 fills it in |
| `/compare <before> <after>` | Paired comparison of two result columns. Stub; W15 fills it in |
| `/cell <col> <scenario> <n>` | One result cell with its evidence. Stub; W15 fills it in |

## Layout

```
warrant/
  AGENTS.md          this file
  Makefile           dsh-profile today; test and lint arrive with W1
  infra/dsh/         profile sources: patches, the sdk manifest, the installer
  .dsh/              hooks.json and the four hook scripts
  .agents/skills/    project skills
  scripts/           dsh_run.py, the headless runner
  docs/decisions/    what was decided and why
  runs/              gitignored run records, including runs/dsh/
```

The product tree arrives with the later issues. W1 scaffolds the Python package, the test layout,
and the `test` and `lint` targets.

## Writing prose

A README sentence has to survive someone running the code and checking the number. Do not write a
summary of what a file contains; write what is true and let the file show the rest. Never present
partial numbers as a result.
