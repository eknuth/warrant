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

## The baseline permit has an ownership branch

Ed's scope-collapse rule says a permit must narrow the token's scopes to the human in `sub` against
the access graph, and must not use the agent's owner as the human. The permit reads
`context.onBehalfOf.entitledTools`, which the engine computes as the union of `allowed_tools` over
the agents that human owns. It also allows a call on a resource the human owns, and that branch does
not require the tool to be in the agent's allowlist. Ownership is a separate grant of authority, and
the provenance rules are what refuse a tainted change to a resource the caller owns. The alternative
reading, where ownership only widens the human check while the agent's allowlist stays the outer
gate, would make the visibility scenario unreachable: no agent in the seed holds
`gitea.set_repo_visibility`, so the rule that refuses a tainted visibility change would never be
denied by that rule, only by the default deny, and its `@id` would never appear in a decision.

## Escalation is written twice

Cedar cannot ask which rule denied a request. The escalate permit therefore reproduces the
conditions of the two rules a person may answer, `scope-collapse` and `tainted-write`, and adds the
human's group and the `incident_id` task scope. On the escalate pass the action is
`Action::"escalate"`, so the real action's kind and tool are read from `context.actionKind` and
`context.tool`.

A forbid whose `when` clause does not test the action kind also matches the escalate action, and a
forbid beats every permit. That is what keeps an orphan from escalating. The content and exfil rules
test the action kind, so they do not match the escalate action themselves. They never escalate for
two reasons: the permit reproduces neither shape, and it refuses itself outright when
`overlapExternal` or `argsTouchSecret` is set. The second is what holds when an exfil-shaped send
also lacks its scope, or an overlap-shaped comment also leaves the target, because in those cases an
escalatable shape is present beside the one that must not be answered by a person. The baseline
permit is scoped to the three kinds so it does not reach the escalate action. Before that scope was
added, every denial escalated because the permit matched the escalate pass, and the policy table
caught it.

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
`context.groups`, the verified token's group claim. The identity provider records membership under
those names and that claim is what the gateway verified, while the graph seed records different
group names for the same people. The two sources disagree, and the token is the one that carries the
names the rule is about. The graph remains the authority for the agent's `allowed_tools`, which is
what `entitledTools` uses.

## What the two provenance rules miss

The content rule is the precise one and the task rule is the broad one. The content rule misses a
paraphrase of external text, because a paraphrase shares no literal token with its source and the
overlap fields are empty. The task rule catches a target shift that the content rule cannot see, and
it lets an injected comment through when the comment stays on the named target. The task rule costs
the honest task every write outside the named target. Both rules are kept, and the four split rows
in the table pin each one's miss.
