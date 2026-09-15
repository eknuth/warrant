# W9. The mail MCP server's tool surface

Date: 2026-09-15. Status: accepted. Amendment to the W9 decision: `get_message` now takes the
mailbox it opens.

W9 is the mail MCP resource server. `infra/graph.yml` gives all three mail tools
`resource_kind: mailbox`, and the gateway extracts the resource from the call's arguments before
the policy engine decides on it. This file records one amendment to the ticket's parameter list
and the two read filters the implementation settled.

## `get_message(mailbox, message_id)`, not `get_message(message_id)`

The ticket lists `get_message(message_id)`. The graph row for the tool says the resource is a
mailbox, and the extractor reads `to` or `mailbox` from the arguments. A call that carried only a
`message_id` therefore resolved to no resource, the engine presented an unknown resource, and the
subject rule refused the desk owner's own agent its honest read. The tool could not be allowed
through the gateway at all.

The tool now takes the mailbox it opens as well as the message id, so it names the resource the
graph row says it touches. This is a deliberate deviation from the ticket's parameter list, and
the ticket note carries the same amendment. The alternative was to change the graph row to a
message resource kind and write a new extractor, which would have moved the subject of the
decision from the mailbox to a message nobody has classified. Keeping the mailbox as the subject
is the smaller change and the stronger one.

Because the mailbox is now the named resource, the server holds the fetched message to it: a
message whose parsed recipient list does not carry that exact address is refused rather than
returned. Without that check a caller could name the one seeded mailbox and read a message that
was never sent to it, which would make the resource in the decision a formality.

## The reads filter Mailpit's substring searches exactly

Mailpit's `to:` and `from:` searches are substring matches. A search on `support@acme.test`
answers with `notsupport@acme.test` and `support@acme.test.evil`, so `list_inbox` and
`sent_messages` compare the parsed addresses again, in full, and keep only an exact match.
`get_message` uses the same recipient match.

Mailpit also answers one page at a time, 50 messages by default whatever the match count is. Both
reads walk its `start` offset until the match count it reports is consumed, bounded at 100 pages
of 100, so ten thousand matches is the limit one call will read.

## The raw URL is the record and the decoded query is a convenience

`send_reply` returns every URL in the body, and `inspect.sent_messages` recomputes the same list
from the stored body. The `url` field is kept exactly as it appeared, percent escapes and all,
and it is what a comparison should read. The `query` mapping decodes with `unquote` rather than
the form rules, so a `+` stays a `+`; a repeated key keeps its last value because a mapping cannot
hold two. `links.py`'s docstring says this where a caller will read it.
