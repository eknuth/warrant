// Escalation. A denial by `scope-collapse` or `tainted-write` is a judgment
// call: the token could be widened for this task, or the target shift
// explained, and a person in the owners or engineers group can answer it. A
// denial by `tainted-content` is not, because text that first appeared in
// external material is evidence rather than a question, so this permit does
// not reproduce that rule's conditions.
//
// Cedar cannot ask which rule denied, so the shape of the two escalatable
// rules is written out again below. On this pass the action is
// `Action::"escalate"`, so the real action's kind and tool are read from the
// context as `context.actionKind` and `context.tool`. The task must carry an
// `incident_id` scope, which is the record that this work is an incident and
// not routine.
//
// A forbid whose `when` clause does not test the action kind also forbids
// `Action::"escalate"`, which is Cedar's rule that a forbid beats every
// permit. `orphan-agent` and `wrong-subject` are written that way, so neither an
// orphan nor a cross-subject call ever escalates, even when it also collapses a
// scope. `tainted-content` and `secret-in-args` test the kind, so they do not
// match the escalate action themselves; they never escalate because this permit
// reproduces neither of their shapes, and the first two conditions below
// refuse it outright when either rule applies beside an escalatable one.
//
// The target shift branch reads provenance, so it states `count > 0`, which the
// ticket requires of any permit written on a tier or on the absence of external
// content. `hasExternal` cannot be true on an empty set, so the count is a
// second reading of the same ground rather than a new condition. This is the
// only permit in the set that reads provenance; the baseline permit does not, so
// the rule is stated where it applies rather than as a property of the set. The
// scope branch does not read provenance and does not ask for it: a scope
// collapse is escalatable in a task that has read nothing.
//
// `incident_id` is the record that this work is an incident and not routine. No
// client scope mints it today, so this permit cannot fire on the running stack
// until one does. That is recorded in docs/policies.md rather than worked
// around here.

// The permit also requires the baseline's non-scope conditions: the agent holds
// the tool and the human is entitled to it. Without them the permit answered a
// denial no scope widening could fix, because an agent asked for a tool it does
// not hold, the scope rule refused it, and the record offered a human "denied
// by: scope-collapse" for a call the graph never allowed. And it refuses itself
// when the visibility rule's own ground holds, so a repository made public on a
// task that read external material is never answered by a person even though the
// request also collapses a scope. Only the visibility half of that rule can
// reach this permit: both escalatable shapes require a write or a send, and a
// read is never refused by the scope rule, so the confidential-read half is
// already out of reach.

@id("escalate-incident")
permit(principal, action == Action::"escalate", resource)
when {
  principal has owner &&
  context.justificationValid &&
  principal.allowedTools.contains(context.tool) &&
  context.onBehalfOf.entitledTools.contains(context.tool) &&
  !context.argsTouchSecret &&
  !context.provenance.overlapExternal &&
  !(
    context.tool == "gitea.set_repo_visibility" &&
    (context.provenance.hasExternal || context.provenance.overlapExternal)
  ) &&
  context.taskScopes.contains("incident_id") &&
  (context.groups.contains("owners") || context.groups.contains("engineers")) &&
  (
    (
      (context.actionKind == "write" || context.actionKind == "send") &&
      (
        (context.tool like "gitea.*" && !context.taskScopes.contains("gitea:write")) ||
        (context.tool like "db.*" && !context.taskScopes.contains("db:write")) ||
        (context.tool like "mail.*" && !context.taskScopes.contains("mail:send"))
      )
    ) ||
    (
      (context.actionKind == "write" || context.actionKind == "send") &&
      context.provenance.count > 0 &&
      context.provenance.hasExternal &&
      context.targetOutsideTask
    )
  )
};
