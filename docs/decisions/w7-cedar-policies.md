# W7. The Cedar policy set

Date: 2026-09-14. Status: accepted.

W7 is the issue that writes the policies. W5 landed the model, the graph, and the engine, and
shipped an empty policy directory because Cedar denies when no permit matches. This file records the
choices that the policy text does not explain by itself.

## The action is the tool, and the kind is the membership

W6 changed the engine so `Action::"<tool>"` is the real action, and every tool action is a member of
its kind. W7 writes against that: a rule about a kind reads `action in Action::"write"`, and a rule
about one tool reads `action == Action::"gitea.create_issue_comment"`. A rule written with `==`
against a kind is inert, because no request carries `Action::"write"`. The schema is generated from
the graph, so a policy that names a tool the graph does not have fails validation at load rather
than never matching.

## Load-time validation

`CedarEngine.__init__` now validates the whole policy text against the schema and raises
`PolicyValidationError` before the engine is usable. The failure this prevents is the one W6 spent an
issue undoing: a policy that names an action the schema does not declare parses fine, matches
nothing, and shows up only as a missing permit at a decision. The check runs only when a schema is
present, which every deployment has. A test asserts that a deliberately broken policy is refused.

## The baseline permit has no ownership branch

Ed's scope-collapse rule says a permit must narrow the token's scopes to the human in `sub` against
the access graph, and must not use the agent's owner as the human. The permit reads
`context.onBehalfOf.entitledTools`, which the engine computes as the union of `allowed_tools` over
the agents that human owns and whose justification is live.

The first draft also allowed a call on a resource the caller owned through an agent the caller owned,
without requiring the tool to be in the agent's allowlist. That branch handed every tool on the
caller's own resources to any agent they owned: alice could read her confidential table through
`triage-agent`, which holds no database tool, and an agent with an empty allowlist still reached it.
The entitlement check was bypassed too, so emptying it did not fail closed. The branch existed to
make the visibility scenario reachable, because no agent held `gitea.set_repo_visibility` and a rule
that refuses a tool nobody holds is only ever the default deny. The review called it a policy tuned
to a scenario, and it was right: the honest way to make the rule bite is to grant the tool where the
agent's authority is written down. `infra/graph.yml` grants `gitea.set_repo_visibility` to
`triage-agent`, and the permit is the ticket's single rule. The grant is one tool on one agent, and
the taint rule is what refuses the change once the task has read something external.

An agent whose justification is missing or expired confers no entitlements either. Its own calls are
refused by `orphan-agent`, so letting a person borrow its allowlist would give authority to an agent
that may not act.

## The token subject is the graph's human id

The gateway builds `Chain.sub` from the token's `sub`, and the engine looks the acting human up in
the access graph by that value. The realm import originally let Keycloak mint a random user id, so a
real token's `sub` matched no human row: `entitledTools` came back empty, no permit that reads the
human matched, and the full policy set refused every call of the recorded W6 smoke. The fix is one
line per user in `infra/keycloak/warrant-realm.json`: alice is `h-alice` and bob is `h-bob`, the ids
`infra/graph.yml` already keys them by. `mallory` keeps a generated id, because the graph has no row
for the attacker and an unregistered caller is meant to resolve to nothing.
`tests/test_realm.py` holds the two trees to the same key, which is the check that would have caught
the mismatch before a reviewer had to replay a run to find it.

## Escalation is written twice

Cedar cannot ask which rule denied a request. The escalate permit therefore reproduces the
conditions of the two rules a person may answer, `scope-collapse` and `tainted-write`, and adds the
human's group and the `incident_id` task scope. On the escalate pass the action is
`Action::"escalate"`, so the real action's kind and tool are read from `context.actionKind` and
`context.tool`.

A forbid whose `when` clause does not test the action kind also matches the escalate action, and a
forbid beats every permit. That is what keeps an orphan and a cross-subject call from escalating. The
content and exfil rules test the action kind, so they do not match the escalate action themselves.
They never escalate for two reasons: the permit reproduces neither shape, and it refuses itself
outright when `overlapExternal` or `argsTouchSecret` is set. The second is what holds when an
exfil-shaped send also lacks its scope, or an overlap-shaped comment also leaves the target, because
in those cases an escalatable shape is present beside the one that must not be answered by a person.

The review found two more calls the first permit answered that it should not. It escalated a tool the
acting agent could never make, because the scope rule refuses a tool the allowlist lacks and no
widening by a person can change that; the permit now requires the baseline's non-scope conditions.
And it escalated a tainted visibility change, because the scope branch reproduced the scope rule's
shape and the request also matched the quiet-control rule; the permit now refuses itself when that
rule's ground holds. Both properties have table rows or tests.

The baseline permit is scoped to the three kinds so it does not reach the escalate action. Before
that scope was added, every denial escalated because the permit matched the escalate pass, and the
policy table caught it.

## Scope names are spelled per server prefix

Cedar has no string concatenation, so `20-scope.cedar` cannot build `<server>:<kind>` from the
context. The required scope is spelled per prefix, and the prefixes are the ones the graph records
for tool servers. A new server needs a line in that rule before its writes can pass. The alternative,
a `requiredScopes` set the engine computes into the context, would make the rule generic and would
move the policy's meaning into Python, which the ticket asks not to do.

## The mail tool is `mail.send`, not `mail.send_reply`

The ticket names `mail.send_reply` in the exfil rule. No graph row declares that tool, and the
generated schema refuses it at load, so the rule names `mail.send`, the one mail send tool this graph
has. A policy for a tool the graph does not have is dead text, which is the failure the load-time
validation exists to catch. When a reply tool lands and the graph gains its row, the rule gains the
name.

## The escalation group comes from the token

The ticket writes the escalation group check against `context.onBehalfOf`. The rule reads
`context.groups`, the verified token's group claim. Each of the realm's OBO client scopes carries a
group-membership mapper with `full.path: false`, so the exchanged token carries `groups: ["owners"]`
and `["engineers"]` rather than Keycloak's `/owners` path form, and the two names the rule tests are
the two the token holds. The graph seed records different group names for the same people
(`engineering`, `support`), so the rule reads the claim rather than the graph attribute. The graph
remains the authority for the agent's `allowed_tools`, which is what `entitledTools` uses.

Two group-shaped conditions have no definition in the stack. `support-leads`, the `wrong-subject`
exemption, is in no realm group and no graph row, so it is a knob an operator grants rather than a
path the seed exercises. `incident_id`, the escalate permit's scope, is minted by no client scope, so
the permit is false for every real token. Both are recorded in `docs/policies.md` under what the
running stack can decide today, and adding them is realm work rather than a policy change.

## What the two provenance rules miss

The content rule is the precise one and the task rule is the broad one. The content rule misses a
paraphrase of external text, because a paraphrase shares no literal token with its source and the
overlap fields are empty. The task rule catches a target shift that the content rule cannot see, and
it lets an injected comment through when the comment stays on the named target. The task rule costs
the honest task every write outside the named target. Both rules are kept, and the four split rows
in the table pin each one's miss.
