# 002. Token exchange in the warrant realm

Date: 2026-09-14. Status: accepted.

The ticket for this work names `docs/decisions/001-token-exchange.md`. W1 already shipped
`001-scaffold.md`, and the number is the ordering, so this is `002`.

## Decision

The `warrant` realm runs standard token exchange (version 2), enabled per agent client, and every
agent client has a dedicated client scope holding a hardcoded `act` claim mapper. The mapper emits
`act` as the JSON object `{"sub": "<that client's id>"}`, signed by Keycloak. `warrant/oidc.py`
verifies the signature and the audience, then refuses any token whose `act.sub` differs from its
`azp`. The `task_id` travels as a parameterized scope the caller passes in the exchange request.
The realm file `infra/keycloak/warrant-realm.json` is imported by `start-dev --import-realm`, so
`make reset` reproduces the whole realm from committed state.

## What Keycloak 26.7.3 actually does

The pinned image is `quay.io/keycloak/keycloak:26.7.3`, the version in `compose.yml`. Its own
token exchange guide carries the capability table. Two rows matter:

| Capability | Standard token exchange V2 | Legacy token exchange V1 |
|---|---|---|
| Delegation per RFC 8693 | Experimental support via Token Exchange Delegation | Not supported |

The full table is in the guide at https://www.keycloak.org/securing-apps/token-exchange.

Standard V2 has no actor concept. Its request parameters are `subject_token`, `subject_token_type`,
`requested_token_type`, `scope`, and `audience`. There is no `actor_token` and no `act` claim. The
exchanged token is issued to the requesting client, recorded as `azp`, and carries the same `sub` as
the subject token.

The only built-in delegation feature is `token-exchange-delegation`, which the Keycloak guide
enables alongside `parameterized-scopes` in the string
`--features=token-exchange-delegation,parameterized-scopes`. Those are two separate features, and
only the second is enabled here. The delegation feature emits `may_act`, not `act`, and the `sub`
inside it is the actor's **user** id, not a client id. It also requires the user to approve a consent
screen at login. It does not issue the claim this project needs, so it is not enabled. Keycloak issue
#36203, "Support actor_token for Token Exchange", is open and unimplemented:
https://github.com/keycloak/keycloak/issues/36203.

`parameterized-scopes` is itself an experimental feature and that has a cost. Keycloak's own log
line at startup reads `Experimental features enabled: parameterized-scopes:v1`, and the vendor's
feature list says an experimental feature is not for production and carries no backward
compatibility guarantee. It was introduced as experimental in Keycloak 21.1 in January 2022, and it
is still there: issue #46523, "Promote Parameterized Client scopes feature to preview", has been open
since 2026-02-23. This realm can therefore break on a Keycloak bump, and the break will be in the
`task_id` claim rather than in the signature or the audience, which are supported features.

## Options considered

1. Standard V2 plus the built-in delegation feature. Rejected. It needs a user id, not a client id,
   it emits `may_act`, it adds a consent screen, and it is labelled experimental.
2. Legacy V1 with `--features=token-exchange,admin-fine-grained-authz`. Rejected. It has no
   delegation support at all and is a deprecated preview.
3. A homegrown security token service. Rejected before this session started. Ed's decision, and the
   ticket's fallback says not to build one without checking.
4. Standard V2 plus a per-client hardcoded `act` mapper, with the verifier requiring `act.sub` to
   equal `azp`. Chosen.

Option 4 does not make Keycloak attest a delegation. It makes Keycloak sign two claims on one token
and makes Warrant's verifier check that they agree. That is weaker than a real delegation token and
the cost is stated below.

Option 4 also inherits the `parameterized-scopes` limitation for `task_id`, described under "What
Keycloak 26.7.3 actually does". Option 1 was rejected partly for resting on an experimental feature;
option 4 rests on a different experimental feature, and saying so is the point of that section. The
difference is what the feature is for: `parameterized-scopes` carries a caller-supplied string into
a claim, while `token-exchange-delegation` would have changed the meaning of the token itself.

## The mappers

Each agent client has a dedicated client scope that no other client holds: `triage-agent-obo`,
`support-agent-obo`, `orphan-agent-obo`. The `act` mapper on `triage-agent-obo` is:

```json
{
  "name": "act",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-hardcoded-claim-mapper",
  "config": {
    "claim.name": "act",
    "claim.value": "{\"sub\":\"triage-agent\"}",
    "jsonType.label": "JSON",
    "access.token.claim": "true"
  }
}
```

`jsonType.label` is the load-bearing part. The mapper reads `claim.value` as a string and runs it
through the JSON type conversion. With `jsonType.label` set to `String`, the token carries
`"act": "{\"sub\":\"triage-agent\"}"`, a string. With `JSON`, the string is parsed and the token
carries `"act": {"sub": "triage-agent"}`. The decoded token from the running stack is the object,
which is the shape RFC 8693 section 4.1 describes and the shape `warrant/oidc.py` requires.

The audience mapper (`oidc-audience-mapper`) sits on the same per-agent scope. It is what makes the
requested audience available: the exchange's `audience` parameter filters the audiences the
requester's client scopes already add, it does not add one. `triage-agent` adds only `gitea-mcp`, so
exchanging with `audience=postgres-mcp` is refused by Keycloak with
`invalid_request: Requested audience not available: postgres-mcp`. `support-agent` adds
`postgres-mcp` and `mail-mcp`. A group membership mapper adds `groups`.

The realm sets `accessTokenLifespan` to 300 seconds, so every exchanged token lives five minutes.

## The task id, and what did not work

The caller passes `scope=task-id:<value>` in the exchange request. A client scope named `task-id` is
marked `is.parameterized.scope=true` with `parameterized.scope.type=string`, holds an
`oidc-parameterized-scope-mapper` whose `claim.name` is `task_id`, and is an optional client scope of
every agent. The claim comes back on the exchanged access token. This requires the
`parameterized-scopes` feature, so `compose.yml` starts Keycloak with
`--features=parameterized-scopes`. That feature is not the delegation feature and nothing else in
the realm depends on it.

Two simpler mechanisms do not work, and both were tried against the running stack before the
parameterized scope was chosen:

- An extra form parameter `task_id=<value>` on the exchange request is ignored. Keycloak reads a
  fixed set of parameters and has no generic pass-through. The user session note mapper
  (`oidc-usersessionmodel-note-mapper`) was configured on the agent scopes for this attempt and
  emitted nothing, because nothing set a `task_id` note. The extension point that would
  (`updateUserSessionFromClientAuth` copying the client authenticator's attributes into user session
  notes) exists, but no built-in client authenticator writes to it in 26.7.3.
- The OIDC `claims` parameter is ignored by the exchange. The two claims-parameter mappers read a
  client session note that only the authorization endpoint sets, and they write ID tokens, not
  access tokens.

So the parameterized scope is the only built-in path in 26.7.3 by which a caller-supplied value
reaches an exchanged access token. Its shape is a compromise: the mapper emits a list, so the raw
JWT carries `"task_id": ["task-1417"]`. `warrant.oidc.Claims` normalizes a one-element list to the
string, the same way it normalizes Keycloak's single-string `"aud": "gitea-mcp"` to a list. Callers
of `verify()` see `task_id` as a string and `aud` as a list; the raw values remain in the signed
token and are printed by `scripts/token_exchange.py`. A token carrying more than one `task-id` scope
is refused rather than truncated, because the mapper's order is not guaranteed and keeping the first
would key provenance to an arbitrary one of them.

`task_id` is chosen by whoever requests the exchange and Keycloak does not validate it. The scope
type is `string`, so any value is emitted verbatim, and the same client can exchange again with a
different value. It is an agent-supplied key for grouping a run's records together. It is never
evidence that a human named that task, and nothing in Warrant may read it as one.

## What the `act` claim costs

The `act` claim is synthesized by a mapper the realm owns, not attested by Keycloak's exchange.
Keycloak signs it, so nobody can alter it after issuance, and because the mapper sits on a scope
only one client holds, a token issued to a different client cannot carry it. Combined with the
`act.sub == azp` rule in `warrant/oidc.py`, a token that verifies proves:

- Keycloak minted the token for the client named in `azp`, and `sub` is the human whose token was
  exchanged. Keycloak checked that the subject token was a real, unexpired token for that user and
  that the exchanging client was allowed to hold it.
- The realm's configuration names that same client as the actor.

It does not prove that the human asked for this action. The realm asserts the acting client, and a
compromised agent client that already holds the human's token can exchange it. Warrant cannot
distinguish "alice asked and triage-agent acted" from "triage-agent exchanged alice's token on its
own initiative" from this token alone. That gap closes only when Keycloak implements `actor_token`
(keycloak#36203). Until then, the honest reading of the chain is: the token is real, the subject is
real, and the actor is the client the realm configured for this exchange, nothing more.

`act.sub == azp` is a consistency check, not the guard against a foreign actor. Because the mapper
hardcodes the client's own id and Keycloak sets `azp` to the client that requested the token, the
equality holds by construction for any token that carries an `act` at all. What actually stops one
agent from holding another's token is the realm's audience and scope assignment: `support-agent`
asking for `triage-agent-obo` is refused `403` by Keycloak before a mapper runs. `warrant/oidc.py`
has no actor allowlist, so it accepts any self-consistent actor the realm ever mints, and a client
that is later given an `act` mapper would verify too. `tests/test_realm.py` is what keeps the set of
clients writing `act` to the three agents, including mappers written on a client rather than on a
scope.

## Three properties of the exchange Warrant does not rely on

These are true of every token this realm issues, and none of them is a defect to fix so much as a
boundary to know. A later issue that wants provenance from the token has to respect them.

1. **The OBO scope is the agent's, not the human's.** Keycloak does not inherit the subject's scopes
   into the exchange unless the `downscope-assertion-grant-enforcer` policy executor is applied, and
   it is not applied here. The exchanged token carries the agent client's scope set, so a token can
   hold `gitea:write` while the subject token held only `openid`. The authority a resource server
   sees is the authority of the agent client, and Warrant's policy is where the human's narrower
   authority has to be enforced.
2. **The exchanged token outlives the subject token and can be re-minted.** An exchange run against a
   subject token with 100 seconds left returns a token with a fresh 300-second lifetime, so it
   outlives the token it came from. The result can then be exchanged again, because `triage-agent` is
   in its own audience, yielding another fresh five minutes, the same `sid`, and a rewritten
   `task_id`. The chain extends for as long as a live token exists and the user session lives (idle
   1800 seconds, maximum 36000 in this realm). If Warrant needs one task per human action, that
   needs more than the token: it needs a decision about whether `task_id` is per session or per
   `jti`, made in the issue that consumes it.
3. **The subject is a user, not necessarily a human.** `scripts/token_exchange.py` uses the resource
   owner password grant to obtain alice's token, and a service account can hold a subject token the
   same way. The token says which user it is about; it does not say that a person was involved.

## Secrets and reproducibility

No value lives in the committed realm file. User passwords and the agent client secret are written
as `${WARRANT_USER_PASSWORD}` and `${WARRANT_AGENT_CLIENT_SECRET}`, which Keycloak resolves from the
container environment during `--import-realm`; `compose.yml` passes them in from `.env`, and `.env`
is the only place the values exist. The three dev users share one password and the three agent
clients share one secret. That is a local-stack shortcut, not a claim that they should match, and
the decision to split them belongs to whoever deploys this.

`make reset` drops the volume and reimports `infra/keycloak/warrant-realm.json`. The Keycloak CLI
export was not used as the source of truth because it writes client secrets and password hashes into
the file. The realm file is written by hand and held to what it promises by `tests/test_realm.py`.

The `console` client also has direct access grants enabled, which `scripts/token_exchange.py` uses
for its dev-only login. That is a terminal convenience and not part of the client's intended use.
`console` is a public PKCE client, and a deployment turns direct access grants off and runs
authorization code with PKCE in a browser instead.

## What was not done

The `token-exchange-delegation` feature is not enabled. No security token service was written. The
`aud` and `task_id` normalizations are documented above rather than hidden in the verifier.

Two known limits are left for the issues that need them. `support-agent` cannot exchange a token
today: `console` holds one audience scope, `aud-triage-agent`, so a support-agent exchange is refused
`403 Client is not within the token audience`. Its scopes and audiences are committed for the shape
of the realm, and the console needs an audience scope for it when W4 uses it. The subject token also
carries no `preferred_username` or `email`, because the `console` client's explicit default scope
list replaces the realm's, so an audit record built from the token has a UUID rather than a name.

Neither is a defect in the exchange itself. Both are recorded here rather than fixed, because fixing
them changes what a later issue consumes.
