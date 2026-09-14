# 002. The W5 warrant core

Date: 2026-09-14. Status: accepted.

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

`Provenance.min_tier` is the least trusted tier present, with `owner` for an empty set, because
nothing untrusted has been read yet. `has_external` is true only for a source whose tier is
`external`, matching the attribute the acceptance test forbids on.

`prompt-only` returns allow with `policy_ids == ["ablation:prompt-only"]` and writes that to the
decision log, so an ablation run is distinguishable from a real allow in the record. In
`no-provenance` the ledger records nothing and reads an empty set. In `no-exchange` the chain comes
from `X-Warrant-*` headers the agent sends; every other mode refuses that path, because the
verified chain needs the token exchange that W2 and W6 own.

Run directories are keyed by task id through one sanitizer in `warrant/config.py`. A crafted task
id cannot walk out of `runs/`. Two task ids that differ only in replaced characters would share a
directory, which is why task ids are opaque generated values.

## Consequences

The decision log and the ledger are append-only JSONL, one line per record, so the grader (W14)
reconstructs a task without a model. `Ledger.get` replays the file when the process that recorded
the sources is gone. W6 wires `chain_from_headers` and the ledger into the request path. W7 writes
policies against the schema in `policies/schema.cedarschema.json`. W11 fills provenance.
