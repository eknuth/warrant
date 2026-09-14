// The OBO token's scopes are the agent client's, and W2 recorded that the
// exchanged token can carry less than the upstream credential behind it. A
// write or a send whose required scope the token does not carry is refused
// here, so nothing downstream leans on a credential that can do more than the
// caller was granted.
//
// Cedar has no string concatenation, so the required scope is spelled per
// server prefix. The prefixes are the graph's tool servers and the scope
// names are the realm's `gitea:write`, `db:write`, and `mail:send`.

@id("scope-collapse")
forbid(principal, action, resource)
when {
  (action in Action::"write" || action in Action::"send") &&
  (
    (context.tool like "gitea.*" && !context.taskScopes.contains("gitea:write")) ||
    (context.tool like "db.*" && !context.taskScopes.contains("db:write")) ||
    (context.tool like "mail.*" && !context.taskScopes.contains("mail:send"))
  )
};
