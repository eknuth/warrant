// Provenance taint. Two rules, because "the task read something external" and
// "this write carries text that first appeared in external material" are
// different evidence and catch different attacks.
//
// `tainted-write` is task taint: anything external was read, and this write
// leaves the target the task named. It catches a target shift even when the
// write's own words are the agent's. What it misses is an injected comment
// posted on the honest issue, whose target is the named one.
//
// `tainted-content` is content taint: the write's arguments carry text, an
// identifier, or a URL that first appeared in an external-tier source. It
// catches the injected comment. What it misses is a paraphrase, which carries
// no literal overlap, and that miss is why `tainted-write` is kept even though
// it costs the task every write that leaves the named target.

@id("tainted-write")
forbid(principal, action, resource)
when {
  (action in Action::"write" || action in Action::"send") &&
  context.provenance.hasExternal &&
  context.targetOutsideTask
};

@id("tainted-content")
forbid(principal, action, resource)
when {
  (action in Action::"write" || action in Action::"send") &&
  context.provenance.overlapExternal
};

// Visibility and confidential reads are the quiet controls. A commit is
// visible; a repository made public, or a confidential row copied into a task
// that has read external material, is not, and neither has the literal overlap
// that `tainted-content` needs.

@id("tainted-visibility")
forbid(principal, action, resource)
when {
  (
    action == Action::"gitea.set_repo_visibility" ||
    (action in Action::"read" && resource.sensitivity == "confidential")
  ) &&
  (context.provenance.hasExternal || context.provenance.overlapExternal)
};
