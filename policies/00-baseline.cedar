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
// The second branch is ownership, and it is deliberately narrow: the human in
// `sub` must own the agent as well as the resource. A person may act on their
// own resource through their own agent even for a tool the agent's allowlist
// does not carry, which is what lets a quiet control such as a visibility
// change be permitted in the clean case and refused by `30-provenance.cedar`
// once the task has read something external. Requiring only the resource would
// have let one person drive somebody else's agent against their own property,
// which is the confused deputy this policy set exists to refuse.
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
  (
    (
      principal.allowedTools.contains(context.tool) &&
      context.onBehalfOf.entitledTools.contains(context.tool)
    ) ||
    (
      principal.owner == context.onBehalfOf &&
      resource.owner == context.onBehalfOf
    )
  )
};
