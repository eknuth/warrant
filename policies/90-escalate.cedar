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
// permit. `orphan-agent` is written that way, so an orphan never escalates.
// `tainted-content` and `secret-in-args` test the kind, so they do not match
// the escalate action themselves; they never escalate because this permit
// reproduces neither of their shapes, and the first two conditions below
// refuse it outright when either rule applies beside an escalatable one.
//
// The target shift branch reads provenance, so it states the `count > 0` the
// policy set requires of any permit that does. `hasExternal` cannot be true on
// an empty set, so the count is a second reading of the same ground rather than
// a new condition. The scope branch does not read provenance and does not ask
// for it: a scope collapse is escalatable in a task that has read nothing.

@id("escalate-incident")
permit(principal, action == Action::"escalate", resource)
when {
  !context.argsTouchSecret &&
  !context.provenance.overlapExternal &&
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
