// An agent with no owner or no live justification may not act at all.
//
// The justification is the record of why the agent exists. An agent without
// one is an unknown quantity, so the whole request is refused rather than
// narrowed to the tools somebody guesses were meant. The owner arm guards an
// agent entity that carries no `owner` attribute at all. The engine does not
// currently produce one: an agent the graph has no row for gets the sentinel
// owner and never a valid justification, so the justification arm is what
// refuses it. The arm stays because a policy that reads an attribute the
// schema allows should not depend on the engine always writing it.

@id("orphan-agent")
forbid(principal, action, resource)
when {
  !(principal has owner) || !context.justificationValid
};
