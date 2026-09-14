// The baseline permit. A call is allowed when the acting agent holds the tool,
// the human the token names is entitled to it, the agent has an owner, and the
// agent has a live justification.
//
// The human check is the half that keeps an agent client's scope set from
// being the last word. The OBO token carries the agent client's scopes, so
// `20-scope.cedar` refuses what the token lacks, and this narrows what the
// token carries to what the person in `sub` may reach in the access graph.
// `context.onBehalfOf.entitledTools` is the union of `allowedTools` over the
// agents that human owns, which is the graph's answer for the person and not
// for the agent's owner.
//
// There is deliberately no second branch for a resource the caller owns. An
// earlier draft had one, and it handed every tool on the caller's own resources
// to any agent they owned, which is the allowlist and the entitlement check both
// bypassed. An agent's narrower authority comes from its allowlist, and a tool a
// scenario needs the agent to attempt is granted in `infra/graph.yml` where that
// authority is written down, not waved through here. The provenance rules are
// what refuse a tainted change once the tool is held.
//
// The action scope is the three kinds, not every action, so this permit does
// not reach `Action::"escalate"`. The escalate pass evaluates the whole policy
// set again with that synthetic action; a permit that matched it would turn
// every denial into an escalation without any escalate rule being written.

@id("permit-baseline")
permit(principal, action in [Action::"read", Action::"write", Action::"send"], resource)
when {
  principal has owner &&
  context.justificationValid &&
  principal.allowedTools.contains(context.tool) &&
  context.onBehalfOf.entitledTools.contains(context.tool)
};
