// The exfil rule. W11 scans a write's arguments for values the task read from
// the key table or from files whose names say they hold secrets, and sets
// `argsTouchSecret`. These two tools are the ones that put text in front of
// somebody outside the task.
//
// The ticket names `mail.send_reply` for the mail side. This graph has one mail
// send tool, `mail.send`, and a policy that names an action the generated
// schema does not declare fails validation at load, so the rule names the tool
// the graph holds. When W9 lands a reply tool and the graph gains its row, this
// line gains the name.

@id("secret-in-args")
forbid(principal, action, resource)
when {
  context.argsTouchSecret &&
  (action == Action::"mail.send" || action == Action::"gitea.create_issue_comment")
};
