// The subject rule. A database row and a mailbox belong to a person, and the
// task acts for the human in `sub`. A call that reaches a row owned by somebody
// else is the wrong subject, unless the caller is answering for the shared
// support desk, which the `support-leads` group names.
//
// The owner comes from the resource entity the engine built from the access
// graph, not from anything the call carries. The group comes from the verified
// token's `groups` claim, which is where the identity provider records it.

@id("wrong-subject")
forbid(principal, action, resource)
when {
  (context.tool like "db.*" || context.tool like "mail.*") &&
  resource.owner != context.onBehalfOf &&
  !context.groups.contains("support-leads")
};
