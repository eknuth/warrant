---
name: issue-start
description: Start a Warrant issue the way every issue is started. Reads AGENTS.md and the Linear issue, marks it In Progress with the linear CLI, branches w<N>-<slug> off main, then hands the spec to one implementer child at the effort the issue's Linear label names. Use at the top of a fresh session when Ed says "start on EDW-<n>" or pastes a prompt that begins with an issue id.
---

# Start an issue

Argument: the issue id, for example `EDW-1438`.

## Steps

1. Read `AGENTS.md`, then the issue and its comments: `linear issue view <ID>`. The issue carries
   Context, Spec, Acceptance criteria, and Out of scope. The Linear CLI reads its key from
   `LINEAR_API_KEY` or the gitignored `.linear.toml`. The MCP overlay is optional and not needed.
   Quote nothing back to Ed; he wrote it.
2. Find the W number. It is in the issue title, `W0`, `W1`, and so on. Linear is authoritative.
   If the title carries no `W<n>`, take the highest `W<N>` from the project's issue titles and
   from `git branch -a`, then use N+1. State the mapping in the first reply ("W0 is EDW-1438").
3. Branch off `main` and nothing else:

   ```
   git checkout main && git checkout -b w<N>-<slug>
   ```

   One issue per branch. If a branch for the issue already exists, check it out instead and say so.
4. Mark the issue In Progress: `linear issue update <ID> --state "In Progress"`. This is the one
   Linear write the opening makes. Comments come later, with results.
5. Spawn one implementer child with the `subagent` tool. The child's effort comes from the issue's
   Linear label: `effort:low` is `low`, `effort:high` is `high`, `effort:max` is `max`. That
   label sets the session, because children run at the row's pinned effort and a per-call effort
   field needs an agent preset. `subagent` runs at `high` and `subagent_review` at `max`, so an
   `effort:low` or `effort:max` issue is a session-level choice made before starting.
6. The delegation prompt carries the whole spec, the acceptance criteria verbatim, the branch, the
   tests to write, and these constraints: do not push, do not open a pull request, do not post to
   Linear, do not touch a browser, do not write a secret anywhere, and do not tune the code to a
   scenario. The orchestrator does not implement; it reads the diff and verifies.
7. When the implementer reports, verify: `make test`, `make lint`, the full `git diff main...HEAD`,
   and the live check the issue names. Then `/review`. Fix in-scope findings, record the rest on the
   issue, and tell Ed. Ed says when to push, and Ed merges.

## Reply shape

Branch name, the W mapping, the child's effort, and what Ed will be asked for. Nothing else until
the implementer reports.
