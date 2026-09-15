# W11. Provenance tagging

Date: 2026-09-16. Status: accepted.

W11 is the third input the policies read: what the agent read on the way to the
action, classified by rules, and turned into the context fields the Cedar set
tests. This file records the choices the code does not explain by itself. The
design answers are in `docs/provenance.md`; these are the implementation choices
behind them.

## The subject comes from the first call, not the exchange

The issue left one choice open: how a task's named target travels from the first
exchange, either a `task_subject` parameter on the token exchange or the first
tool call's arguments. The implementation takes it from the first call whose
arguments resolve to a resource.

The exchange path is worse here for one concrete reason. The subject would have
to travel as a claim the issuer mints, because the gateway never sees the
exchange request: the agent client calls the token endpoint directly with
`scope=task-id:<value>`, and the gateway only verifies the resulting token. A
`task_subject` would mean a parameterized scope in the realm, a change to every
agent client, and a claim to normalize in `warrant/oidc.py`. The first call's
arguments are already in front of the gateway, resolve through the same
`warrant/resources.py` path every other call uses, and need no realm change.

The cost is stated in `docs/provenance.md`: an agent whose first call is the
off-target write names that write's resource as the task's target. The
alternatives were a claim the issuer would have to mint, or a rule that reads the
first read rather than the first call. The first read is not reliably present
either, and a subject that only some tasks have would leave the target comparison
silently off for the rest. The first call always names what the task is about,
which is the property the field needs.

## The task state is keyed by task and actor

`TaskState` is per task, as the issue says, and the gateway's registry keys it by
`(task_id, actor)`. The actor is part of the key because the ledger's key already
is. An agent writes its own `scope=task-id:<value>`, so agent A can name agent
B's task id. With the ledger keyed on the actor, B's sources never appear under
A's name. With the taint keyed on the task id alone, A's reads would fill B's
content taint while B's provenance summary stayed empty, and B's later writes
would be refused by a rule whose evidence the decision line does not show. The
two keys have to agree or one of them is lying.

## The target argument is dropped from the scan

The scan skips the argument value that named the call's resource. Every comment
on `acme/widgets` carries `repo="acme/widgets"`, and that string appears in the
source id of every issue read from `acme/widgets`, so the identifier matcher
would report an overlap on the repository name for every write. That would turn
the paraphrase miss back into a hit and make content taint fire on quiet work.
Only the exact value is dropped; a body that repeats the repository name is still
scanned.

## Content taint is a `Provenance` flag, not a filtered source list

`TAINT=content` has to leave `provenance.hasExternal` false while the sources
stay in the record. The alternative considered was passing a `Provenance` whose
sources list had the external entries removed. That would have changed
`minTier`, `sourceIds`, and the decision line's evidence of what was read, all to
suppress one derived field. `Provenance.task_taint` is a real field with a
default of true; `has_external` reads it. The sources are untouched and a reader
of the line can see both what was read and that the task rule was switched off.

## Secrets are digests in the log and values only in memory

`warrant/taint.py` keeps the plain secret values in the `TaskState` and a
SHA-256 digest of each one. `overlapDetails` carries the digest for a secret hit,
and a sample of source text that contains a secret is redacted before it is
recorded. That is what makes the "no plain secret in `runs/`" criterion hold
without weakening the rule: the scan needs the value and the log must not have
it, so the two are separate from the point the value enters the state.

## `TAINT` is separate from `WARRANT_MODE`

`TAINT` is a second environment setting and not a fifth `Mode`. The modes name
ablations of the whole request path, and W15 runs the content taint alone inside
`full`. Folding `content` into `Mode` would have made it a mode that changes the
ledger, the chain, and the engine at once. It changes one computed field, so it
is its own switch, read once at import like `WARRANT_MODE`.
