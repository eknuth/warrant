---
name: issue-start
description: Start a Warrant issue the way every issue is started. Reads AGENTS.md and the Linear issue, comments the opening plan on the issue, marks it In Progress, branches w<N>-<slug> off main, then hands the spec to one implementer child at the effort the issue's Linear label names. Use at the top of a fresh session when Ed says "start on EDW-<n>" or pastes a prompt that begins with an issue id.
---

# Start an issue

Argument: the issue id, for example `EDW-1438`.

The orchestrator session owns Linear. It posts every comment with
`linear issue comment add <ID> --body "..."` and moves the state with
`linear issue update <ID> --state "<state>"`. Implementer and reviewer children never write to
Linear, never push, and never open a pull request.

Comments follow the prose rules in `AGENTS.md`: short, plain sentences, no em dashes. Write what
is true, name the evidence, and do not summarize the ticket back to Ed.

## Steps

1. Read `AGENTS.md`, then the issue and its comments: `linear issue view <ID>`. The issue carries
   Context, Spec, Acceptance criteria, and Out of scope. Read all four.
2. Find the W number. It is in the issue title, `W0`, `W1`, and so on. Linear is authoritative.
   If the title carries no `W<n>`, take the highest `W<N>` from the project's issue titles and from
   `git branch -a`, then use N+1.
3. Post the opening comment: the plan paragraph, the branch name, and the effort the issue's label
   names. Post it before the child starts, so the issue says what is happening while it happens.
4. Branch off `main` and nothing else:

   ```
   git checkout main && git checkout -b w<N>-<slug>
   ```

   One issue per branch. If a branch for the issue already exists, check it out instead and say so
   in the comment.
5. Mark the issue In Progress: `linear issue update <ID> --state "In Progress"`.
6. Spawn one implementer child with the `subagent` tool. The child's effort comes from the issue's
   Linear label: `effort:low` is `low`, `effort:high` is `high`, `effort:max` is `max`. That label
   sets the session, because children run at the row's pinned effort and a per-call effort field
   needs an agent preset. `subagent` runs at `high` and `subagent_review` at `max`.
7. The delegation prompt carries the whole spec, the acceptance criteria verbatim, the branch, the
   tests to write, and these constraints: do not push, do not open a pull request, do not post to
   Linear, do not touch a browser, do not write a secret anywhere, and do not tune the code to a
   scenario. The orchestrator does not implement; it reads the diff and verifies.
8. When the implementer reports, verify: `make test`, `make lint`, the full `git diff main...HEAD`,
   and the live check the issue names.
9. Run `/review` when the issue's label is `effort:high` or `effort:max`: one lens for `high`, both
   lenses for `max`. Do not review an `effort:low` issue.
10. Fix in-scope findings, and when `make test` and `make lint` pass, push and open the pull
    request. The body carries `Closes <ID>`. Then post the closing comment and move the issue to
    In Review.

## When to comment, and what to say

Post a comment at each of these four moments. Keep each one short.

**At the start.** One paragraph: what the issue is, the branch, and the effort the label names.

**At any stop.** When something needs Ed's decision, stop and ask. The comment carries the question,
the options with their costs, and what you recommend. Do not decide a design fork yourself and
report it afterward.

**After verify and review.** `make test` and `make lint` results with their numbers, then every
review finding with what happened to it: fixed, or deferred and why. Name what was deferred so it
can be found later.

**When the pull request opens.** The link, then move the issue to In Review with
`linear issue update <ID> --state "In Review"`.

## Reply shape

Branch name, the W mapping, the child's effort, and what Ed will be asked for. Nothing else until
the implementer reports.
