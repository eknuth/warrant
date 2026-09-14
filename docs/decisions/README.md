# Decisions

One file per decision, written when the issue lands. The file says what was decided, what the
alternatives were, and what the decision costs.

The name is `w<N>-<slug>.md`, where `w<N>` is the issue that made the decision and the slug names
the decision. The four that were already here keep their three-digit prefixes, because comments,
tests, and the issues themselves point at them by that name and a rename would break every
reference to buy nothing:

    000-harness.md          W0
    001-scaffold.md         W1
    002-token-exchange.md   W2
    003-w5-warrant-core.md  W5

From the next decision on, the file is a new name: `004-gateway-hop.md` for the second hop in W6,
not `004-second-hop.md`. Two issues can each write a decision without racing for the next number,
and the name says which issue to read for the ticket behind it.

The date and status line at the top of each file is still the ordering. A decision that a later
issue reverses gets a new file that names the one it supersedes rather than an edit to the old one,
so the record of what was believed at the time survives.
