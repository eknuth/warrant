# 004. The gateway hop

Date: 2026-09-14. Status: accepted.

The ticket cites this file as `004-gateway-hop.md`. W6 is the issue that made the decision.

## Decision

Warrant is an MCP server on `:9100/mcp` and the only MCP endpoint an agent reaches. It re-exports
each upstream server's tools under a prefix (`gitea.get_issue`, `db.query`, `mail.send`), verifies
the incoming token for the `warrant` audience, decides every call, and forwards allowed calls to the
upstream the graph names.

The upstream token is minted by a second exchange. The agent exchanges its human token for an
on-behalf-of token addressed to `warrant`, acting as its own confidential client. Warrant then
exchanges that token for the upstream audience, acting as a new confidential client named `warrant`,
with the incoming token as `subject_token`. This is the design risk the ticket names, and it works
against the pinned realm. The option of forwarding the incoming token is the fallback the code keeps
when the exchange is refused; it is not the path taken here.

The realm changes that make the hop possible:

- A confidential client `warrant`, with standard token exchange enabled and the same placeholder
  secret as the agent clients (`${WARRANT_AGENT_CLIENT_SECRET}`).
- A client scope `warrant-obo`, held only by `warrant`, with an `act` mapper that writes
  `{"sub": "warrant"}` and audience mappers for `gitea-mcp`, `postgres-mcp`, and `mail-mcp`.
- An `audience-warrant` mapper on each agent's on-behalf-of scope, so an agent can ask for the
  `warrant` audience.

The audience the agent asks for comes back alone. An exchange with `audience=warrant` returns
`"aud": "warrant"`, not a list that also names `gitea-mcp`, so the triage agent's pre-flight check
still refuses any token that names more than the gateway.

Upstream tool schemas are fetched on the first `tools/list` a task makes, not at process start.
The upstream's own `tools/list` sits behind the same bearer check as its tools, so there is no
token to fetch it with until an agent has arrived. The schemas are cached after the first success,
and only tools the graph has a row for are re-exported.

## The transcript

Run from the repository root on 2026-09-14 with the stack up. The first hop is alice's token
exchanged by `triage-agent`. The second is that token exchanged by `warrant`. The claims below are
the decoded payload of each signed token, with nothing added.

Hop one, `triage-agent`, `audience=warrant`, `scope=task-id:task-w6-live`, HTTP 200:

```json
{
  "iss": "http://localhost:8080/realms/warrant",
  "aud": "warrant",
  "azp": "triage-agent",
  "act": { "sub": "triage-agent" },
  "sub": "d6b407be-afef-4ab2-8866-78d0c8861118",
  "scope": "gitea:read gitea:write",
  "task_id": ["task-w6-live"],
  "iat": 1789402728,
  "exp": 1789403028
}
```

Hop two, `warrant`, `audience=gitea-mcp`, the hop-one token as `subject_token`, HTTP 200:

```json
{
  "iss": "http://localhost:8080/realms/warrant",
  "aud": "gitea-mcp",
  "azp": "warrant",
  "act": { "sub": "warrant" },
  "sub": "d6b407be-afef-4ab2-8866-78d0c8861118",
  "scope": "mail:send db:write gitea:read gitea:write db:read",
  "task_id": ["task-w6-live"],
  "iat": 1789402728,
  "exp": 1789403028
}
```

The token verifies at the upstream, and the gateway used it: with the gateway in front of a
`gitea-mcp` process, `gitea.get_issue` came back allowed and `provenance.jsonl` gained the issue's
and its comment's source blocks. The exact transcript above is the evidence; a claim that the hop
works without it is not evidence.

## What the hop costs

**The upstream sees `warrant` as the actor, not the agent.** The second token's `azp` and `act.sub`
are both `warrant`, so the resource server's audit line records `act=warrant`. The gateway's own
records carry the real chain, `act=triage-agent` and the human as `sub`, so a reader joins the two
on `task_id` and `args_digest`. The alternative was for Warrant to hold every agent client's secret
and exchange as that agent, which spreads the agents' credentials into the gateway and buys an
audit line that still is not a delegation. Not taken.

**The gateway client shares the dev secret.** `warrant` uses `${WARRANT_AGENT_CLIENT_SECRET}`, the
same placeholder the three agent clients use. That is a local-stack shortcut, and the realm file
already documents the same shortcut for the agents. A deployment gives each client its own.

**The model endpoint has no dot in a function name.** The chat-completions grammar allows only
`[A-Za-z0-9_-]`, and the gateway's names carry a dot. `agents/providers/openai_compat.py` encodes a
name for the wire and decodes the model's answer, so the model sees `gitea_2e_get_issue` while the
loop, the agent's write list, and the gateway all see `gitea.get_issue`. The encoding is
`_<codepoint hex>_` and it escapes `_` too, so it is injective. The first live triage run failed
`400` on `tools[0].function.name` before this existed; the second completed.

**Compose and the issuer hostname.** Keycloak writes `iss` from the URL its token endpoint was
reached at, which is `http://localhost:8080/realms/warrant` for a host-side login. Inside a
container `localhost` is the container, so the compose services in `compose.yml` set
`WARRANT_OIDC_ISSUER=http://keycloak:8080/realms/warrant` and a deployment needs an issuer hostname
both the host and the compose network resolve, or a host-side login that uses that name. The live
acceptance run in this ticket therefore ran the gateway and the upstream as host processes, with a
host-local `servers.yml` pointing at `127.0.0.1:19101`, and the compose definitions were checked for
their network shape rather than run.

## Provenance is the ledger's, and only the ledger's

`Gateway.call_tool` builds the `AuthzRequest` from `ledger.get(task_id)`. The ledger is filled by
the gateway itself as it forwards reads, from the `source` block the resource server returned, and
from nowhere else. The `tools/call` body can carry whatever the agent wants, including a
`provenance` key in the arguments; the arguments reach the upstream, the decision does not read
them. `tests/test_gateway.py` sends a fabricated set and asserts the decision used the ledger's set
and that the fabricated source's id and digest appear nowhere in the recorded decision line.

## What the id reconciliation cost

The graph's agent ids are now the identity provider's client ids (`triage-agent`, `support-agent`,
`orphan-agent`) and its tool ids are the gateway's re-exports (`gitea.get_issue`, `db.query`,
`mail.send`). Before this, the graph held `agent-triage` and `gitea.search`, and the gateway would
have found no agent for `act.sub=triage-agent` and no action kind for the tool it was asked to
forward. `python -m warrant.graph load` upserts and does not delete, so a `warrant.db` written from
the old seed keeps the old rows beside the new ones. The database is gitignored and rebuilt from
`infra/graph.yml`; delete it and let the gateway seed it again after a seed whose ids changed.

## The criterion's literal policy is inert

The ticket's second acceptance criterion writes the refusal as
`forbid(principal, action == Action::"gitea.create_issue_comment", resource);`. In the W5 engine the
Cedar action is the kind (`read`, `write`, `send`) and the tool travels in `context.tool`, which
`docs/decisions/003-w5-warrant-core.md` records. Run against the gateway, that policy with a
permit-all beside it allows the comment: the forbid names an action no request carries. With no
permit beside it the comment is refused, but so is every read, and the reason is the default deny
rather than the forbid. The spelling that refuses the comment while the reads proceed, and that the
acceptance run used, is:

```cedar
@id("forbid-comment")
forbid(principal, action == Action::"write", resource)
when { context.tool == "gitea.create_issue_comment" };
```

## What was verified

- The second hop returns HTTP 200 with the claims above, and the gateway presents that token to the
  upstream.
- A token whose audience is `gitea-mcp` is refused at Warrant with `401 invalid_token`.
- An actor the graph does not know is refused with the tool error `unknown agent`.
- The triage smoke completed with a permit set: eight tool calls, eight decision lines, all
  `allow`, and nine provenance lines for the reads. A read with several `source` blocks records one
  line each, which is why the provenance count is above the read count.
- The comment forbid produced two `deny` lines with reason `forbid matched: forbid-comment`, the
  agent's summary named that reason, and the run ended with `finish_reason` `stop`.
