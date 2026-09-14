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
name for the wire and decodes the model's answer, so the model sees `gitea_2e_get_5f_issue` while
the loop, the agent's write list, and the gateway all see `gitea.get_issue`. The encoding is
`_<codepoint hex>_` and `_` is outside the wire-safe class, so it is encoded too and the codec is
injective. That second half was wrong in the first version of this file: `_` was left literal, so
`db.public.orders` and a tool literally named `db.public_2e_orders` both encoded to
`db_2e_public_2e_orders`, one of them became unreachable, and the other answered calls aimed at it.
No shipped upstream tool name contains `_<hex>_` yet, which is why the collision was latent rather
than live. The first live triage run failed `400` on `tools[0].function.name` before any of this
existed; the second completed.

**Compose and the issuer hostname.** Keycloak writes `iss` from the URL its token endpoint was
reached at, which is `http://localhost:8080/realms/warrant` for a host-side login. Inside a
container `localhost` is the container, so the compose services in `compose.yml` set
`WARRANT_OIDC_ISSUER=http://keycloak:8080/realms/warrant` and a deployment needs an issuer hostname
both the host and the compose network resolve, or a host-side login that uses that name. The live
acceptance run in this ticket therefore ran the gateway and the upstream as host processes, with a
host-local `servers.yml` pointing at `127.0.0.1:19101`, and the compose definitions were checked for
their network shape rather than run.

## Provenance is the ledger's, and only the ledger's

`Gateway.call_tool` builds the `AuthzRequest` from `ledger.get(task_id, act)`. The ledger is filled
by the gateway itself as it forwards reads, from the `source` block the resource server returned,
and from nowhere else. The `tools/call` body can carry whatever the agent wants, including a
`provenance` key in the arguments; the arguments reach the upstream, the decision does not read
them. `tests/test_gateway.py` sends a fabricated set and asserts the decision used the ledger's set
and that the fabricated source's id and digest appear nowhere in the recorded decision line.

The actor is part of the ledger key, and that is load-bearing rather than tidy. The task id is not
proven to be the caller's: the realm comment says the caller writes `scope=task-id:<value>` and the
value comes back as the `task_id` claim, so an agent picks its own. With the ledger keyed on the id
alone, an agent could name another task's id and start from the sources recorded under it, and its
own reads appended to that other task's file. The files are now
`runs/<task_id>/provenance/<actor>.jsonl`, so a task id that was never this actor's reads as empty
and every actor's evidence stays under its own name. The review that found this is the reason the
key changed; the acceptance criterion's wording was already about the ledger, and this is what makes
it true rather than nearly true.

## What the id reconciliation cost

The graph's agent ids are now the identity provider's client ids (`triage-agent`, `support-agent`,
`orphan-agent`) and its tool ids are the gateway's re-exports (`gitea.get_issue`, `db.query`,
`mail.send`). Before this, the graph held `agent-triage` and `gitea.search`, and the gateway would
have found no agent for `act.sub=triage-agent` and no action kind for the tool it was asked to
forward. `python -m warrant.graph load` upserts and does not delete, so a `warrant.db` written from
the old seed keeps the old rows beside the new ones. The database is gitignored and rebuilt from
`infra/graph.yml`; delete it and let the gateway seed it again after a seed whose ids changed.

## The criterion's literal policy was inert, and the engine changed

The ticket's second acceptance criterion writes the refusal as
`forbid(principal, action == Action::"gitea.create_issue_comment", resource);`. In the W5 engine the
Cedar action was the kind (`read`, `write`, `send`) and the tool travelled in `context.tool`, which
`docs/decisions/003-w5-warrant-core.md` recorded. Run against the gateway, that policy with a
permit-all beside it allowed the comment: the forbid named an action no request carried. With no
permit beside it the comment was refused, but so was every read, and the reason was the default deny
rather than the forbid.

That is no longer the shape. The engine now evaluates `Action::"<tool>"`, with every tool action a
member of its kind, so the criterion's policy works exactly as written and the reason the agent
receives is the forbid's own. `docs/decisions/003-w5-warrant-core.md` carries the dated section that
supersedes its earlier mapping, and `tests/test_warrant_engine.py` holds the criterion's policy
verbatim with a permit beside it. The spelling the W6 acceptance run used before the change was:

```cedar
@id("forbid-comment")
forbid(principal, action == Action::"write", resource)
when { context.tool == "gitea.create_issue_comment" };
```

That spelling still works, because the kind actions remain in the schema as membership groups. The
substitution was never recorded as an accepted change to the criterion, which is why the engine was
changed instead.

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

## What the first review changed

An adversarial pass over the branch found ten things. Eight were live defects and two were nits,
and all ten are fixed here, because the ones that looked small were the same kind of mistake:

- The ledger key described above. This was the serious one: it made the ticket's central claim a
  convention rather than a property.
- The wire codec above. `_` is now escaped, and a test asserts that two different names never share
  a wire name, not just that one name round-trips.
- An upstream failure was recorded as `verdict: allow` with no error, so a lost call and a delivered
  one were the same line. The outcome now travels in an `error` field beside the verdict, because
  the verdict is the decision and the error is what happened after it.
- `.env` was copied into the image by `COPY . .`. A `.dockerignore` now excludes it along with
  `runs/`, `warrant.db`, and the rest of the local state.
- `no-exchange` crashed on `tools/list`, which is the first request an MCP client makes, so the
  whole ablation was unusable. `list_tools` now builds its chain the same way `call_tool` does.
- A refusal before the engine wrote nothing, because it carried no task id, while this file and the
  module docstring both said every call gets a line. Refusals that happen after the chain is built
  now write their line with the real `task_id` and `act`.
- A token whose task id was `.` or `..` raised `ValueError` out of the request handler, long after
  the call was accepted: an unlogged crash instead of a refusal. `Chain` refuses such an id where
  the claim enters, and the gateway answers with a tool error.
- A resource name that collided with the id of a row of another kind resolved to that row, so a
  `mail.send` whose `to` was `table-orders` was decided against the confidential table. A name that
  is some row's id under the wrong kind now resolves to nothing at all.
- `upstream_ms` counted the token exchange as well as the upstream call, so a slow issuer read as a
  slow upstream. The clock starts after the exchange.
- `tools/list` reached every upstream for an actor the graph does not know. It now answers an empty
  list, which is the same answer `call_tool` gives with `unknown agent`.
