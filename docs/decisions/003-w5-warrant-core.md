# 003. The W5 warrant core

Date: 2026-09-14. Status: accepted.

The number is 003 rather than 002 because W2's `002-token-exchange.md` was written on a branch that
is not merged here yet. The number is the ordering, and two files cannot both be 002.

## Decision

W5 lands the authorization data model (`warrant/models.py`), the SQLite access graph
(`warrant/graph.py` and `infra/graph.yml`), the Cedar adapter (`warrant/engine.py`), the
provenance ledger (`warrant/provenance.py`), the decision log (`warrant/log.py`), and the ablation
modes (`warrant/config.py`). No real policies ship: Cedar denies when no permit matches, so
`policies/` carries the schema and a comment-only policy file, and W7 writes the permits.

## Choices worth naming

The engine maps a request to `Action::"read"`, `Action::"write"`, or `Action::"send"`, and puts
the tool id in `context.tool`. Cedar's action scope is always an entity of type `Action`, and the
schema declares the three kinds plus the synthetic escalate action, so the tool cannot also be the
action id without leaving the schema. Policies that care about a specific tool read
`context.tool`, and policies that care about an agent's allowlist read
`principal.allowedTools.contains(context.tool)`.

The ticket writes the escalate action as `Escalate::"<tool>"`. That is not parseable Cedar: the
action scope has to be `Action`, and `Escalate::"gitea.search"` fails with "expected an entity uid
with type `Action`". Escalation is two passes over the same policy set. The first pass evaluates
the real action; if it is allowed the answer is allow and the second pass does not run. If the real
action is denied, the second pass evaluates `Action::"Escalate"` with the same principal, resource,
and context, and the tool is still in `context.tool`, so a per-tool escalate permit is
`when { context.tool == "gitea.search" }`. A `forbid` that matches every action also forbids
`Action::"Escalate"`, which is Cedar's rule that a forbid beats every permit; an escalate permit
lifts an implicit deny or a deny scoped to the real action. A request Cedar cannot evaluate at all
is a deny and does not reach the escalate pass, because escalation answers a deny, not a broken
request.

`Provenance.min_tier` is the least trusted tier present, with `owner` for an empty set. That empty
reading is vacuous rather than earned, so a permit that depends on how much has been read checks
`context.provenance.count > 0` for itself; the summary cannot tell "read nothing" from "read only
the owner's own material". `has_external` covers `external` and `unknown`, the two tiers below any
classification. It was `external` only, which let the least trusted tier in the model past a forbid
written on it; `unknown` is what a commit with no forge account gets, and that is exactly the case a
provenance check exists for.

`prompt-only` returns allow with `policy_ids == ["ablation:prompt-only"]` and writes that to the
decision log, so an ablation run is distinguishable from a real allow in the record. Every decision
also carries `mode`, because an allow logged under `no-provenance` and an allow under `full` where
the agent read nothing would otherwise serialize the same and the grader could not attribute a line
to an ablation from the record alone. In `no-provenance` the ledger records nothing and reads an
empty set. In `no-exchange` the chain comes from `X-Warrant-*` headers the agent sends; every other
mode refuses that path, because the verified chain needs the token exchange that W2 and W6 own.

Run directories are keyed by task id through one sanitizer in `warrant/config.py`. A crafted task id
cannot walk out of `runs/`. When the sanitizer changes an id it appends a short digest of the
original, because `a_b`, `a/b`, and `a b` would otherwise be one directory and so one ledger, and a
task could inherit another task's provenance set. That collision is reachable: `no-exchange` takes
the task id from a header the agent sends.

## What the first review changed

Three of these were fail-open in a way that mattered, and each is now pinned by a test.

**An evaluation error is not a deny.** cedarpy reports an error as `Decision.Deny` with
`diagnostics.errors` set, not as `NoDecision`, so a guard keyed on the decision let an erroring
policy escalate and dropped the error text. An error with no matching permit now denies, in the
error's name, and does not reach the escalate pass: escalation asks a human to answer a policy's
refusal, and an error is not a refusal. When a permit does match, the error is recorded in `reasons`
and the decision still follows Cedar, because a broken policy beside a good one should be visible
rather than silently vetoing the set.

**The action kind comes from the graph.** The engine used the request's own `action_kind`, and
`Graph.tool()` was never consulted, so a write labelled as a read was authorized by a read permit.
A disagreement with the tool's row is now a deny that says so. A tool the graph does not list is
left to the policies, since a deployment may call tools the seed does not enumerate.

**An unknown agent or resource is owned by nobody.** Both used to be given `owner = chain.sub`, so
`resource.owner == principal.owner` matched a resource the graph had never heard of and
`principal.owner == principal.onBehalfOf` matched an agent with no row. The owner is now a sentinel
that no human row can equal.

An escalate decision also carries the deny that caused it, and the escalate pass has a test that a
permit scoped to another tool does not match. When this was written the tool lived in `context.tool`
rather than in the action id, which is the shape the escalate pass still uses; the real pass moved
to `Action::"<tool>"` on 2026-09-14, below.

## Consequences

The decision log and the ledger are append-only JSONL, one line per record, so the grader (W14)
reconstructs a task without a model. `Ledger.get` replays the file when the process that recorded
the sources is gone. W6 wires `chain_from_headers` and the ledger into the request path. W7 writes
policies against the schema in `policies/schema.cedarschema.json`. W11 fills provenance.

## 2026-09-14: the tool is the action

W6's second acceptance criterion writes its refusal as `forbid(principal, action ==
Action::"gitea.create_issue_comment", resource)`. Under the three-kind action above, that forbid
named an action no request carried: the engine asked Cedar about `Action::"write"` and left the tool
in `context.tool`. The policy was therefore inert. With a permit beside it the comment was allowed,
and with nothing beside it the comment was refused by the default deny with reason `no permit
matched`. A test written to the criterion's letter would have passed for the wrong reason, and the
W6 smoke run could not deliver the criterion at all.

The tool is now the action. `Action::"<tool>"` is the real pass, generated into the schema from the
graph's `tools` table, and every tool action is a member of its kind, so a rule about a kind reads
`action in Action::"write"` and a rule about one tool reads `action ==
Action::"gitea.create_issue_comment"`. The criterion's policy works as written and a test asserts
that the forbid, not the default deny, produced the reason the agent receives. Cedar cannot express
`Action::"<tool>"` as a child of a kind without the membership relation, and a static schema would
need an edit for every tool W8, W9, and W21 add, so `warrant/engine.py` generates the schema at load
and `policies/schema.cedarschema.json` is the committed copy of that generation. A test regenerates
it and compares, which is what keeps the file from going stale.

The earlier claim that the schema "cannot declare every tool" was wrong, and the sentence above is
left in place because it is what was believed when W5 shipped. `Action::"escalate"` is the one
action whose tool is still `context.tool`, because that pass exists to ask a human about a denied
call and the tool is data there rather than the action. The three-kind actions remain in the schema
as membership groups, so a policy written against a kind keeps working. W7 writes one action per
tool plus `escalate`, per its own spec.
