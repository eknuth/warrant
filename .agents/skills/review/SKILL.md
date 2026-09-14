---
name: review
description: Spawn the two-lens adversarial review every Warrant issue gets before it is called ready. Lens one is implementation correctness with reproduced findings; lens two is whether the work advances the project's authorization and provenance story. Use when an implementer has reported, when Ed says "spawn the review", or before telling Ed an issue is done.
---

# Adversarial review

Argument: what to review, a branch, a diff range, or a path. Default is the current branch against
`main`.

## Spawn

Use the `subagent_review` tool on a fresh child. That tool is the delegation row pinned to the top
effort, so the review always runs at `max`; the ordinary `subagent` tool runs children at the
standing effort instead. The prompt is the brief below plus the issue id, the branch, the diff
range, and these lines: read only, do not push, do not post to Linear, do not open a pull request,
do not touch a browser, do not modify anything outside this checkout.

## How much review, by effort label

The issue's effort label sets the tier, and the tier decides how many lenses the child writes.

| Label | Tier |
|---|---|
| `effort:low` | No review. Mechanical work does not get one |
| `effort:high` | One lens, correctness |
| `effort:max` | Both lenses, correctness then the project story |

Tell the child which tier it is. A one-lens child that writes a project-story verdict anyway has
gone outside its brief, and that paragraph is not recorded anywhere.

## The brief

Two lenses, reported separately.

Lens one, correctness. Read the whole diff, then the tests, then run `make test` and `make lint`.
For each claim in the commit message, the pull request text, or an issue comment, find the code or
the run record that supports it and say whether it does. Reproduce every finding: a failing input to
a function, a line number, the hook payload that gets through, the command whose output disagrees
with the docstring. A finding without a reproduction is a question, listed separately.

Check the shapes this project gets wrong:

- An asymmetry that makes one answer cheaper than the other, in a policy or in a test.
- A rule that bites in one direction only, so the forbidden form is blocked and an equivalent form
  passes.
- A fixture, constant, or comment that carries the answer the code is supposed to compute.
- An id, a key, or a scenario name left on the wire or in a committed file.
- A check that fails open where it should fail closed, or the reverse. The hooks fail open on
  unexpected errors on purpose, so ask what a silent pass costs there.
- Prose in the wrong voice: em dashes, rule-of-three, hedging, a company name.
- A number in a README or a docstring that nothing produces.
- An unreproducible claim about a tool, a version, or a plugin behavior.

For W0 specifically, the rule that has to hold is that no other vendor's CLI or API appears
anywhere in this tree. The check is the case-insensitive two-word grep the issue names, run over
the whole checkout, and the only permitted matches are the hook bridge plugin's own name in the
profile patches, its environment variable in `.dsh/hooks.json`, and `docs/decisions/000-harness.md`,
which records both as the bridge's naming rather than as a dependency. Every other match is a
finding.

Lens two, the project story. The reader is someone deciding whether Warrant is a serious answer to
per-action authorization with an auditable record. Does the change show its grounding? Does it fix
the method and leave the scenarios alone? Would a sentence this change earns survive a reader
running the code? Say what it adds to that case and what it costs.

## Output

Numbered findings, each with a severity (blocks merge, fix before ready, nit), the file and line or
the run record, the reproduction, and the fix in one sentence. Then the lens-two verdict in one
paragraph. Then the questions. The orchestrator fixes in-scope findings, records the rest on the
issue, and reruns the review only when a fix changed the method or a number.
