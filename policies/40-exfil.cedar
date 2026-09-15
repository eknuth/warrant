// The exfil rule. W11 scans a write's arguments for values the task read from
// the key table or from files whose names say they hold secrets, and sets
// `argsTouchSecret`. These two tools are the ones that put text in front of
// somebody outside the task.
//
// W7 named `mail.send` here because that was the only mail send row the graph
// held. W9 landed the real tool, `mail.send_reply`, and replaced the row, so the
// rule names it.

@id("secret-in-args")
forbid(principal, action, resource)
when {
  context.argsTouchSecret &&
  (action == Action::"mail.send_reply" || action == Action::"gitea.create_issue_comment")
};
