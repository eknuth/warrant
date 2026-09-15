# W10. The support agent

Date: 2026-09-15. Status: accepted.

W10 is the second agent role. It shares the provider and tool loop with W4 and answers one support
ticket from the database, replies by mail, and leaves the ticket in the state the reply left it.
This file records the choices the code does not explain by itself.

## The desk user is the support lead

`policies/50-ownership.cedar` refuses a `db.*` or `mail.*` call whose resource the human in `sub`
does not own, unless the token carries the `support-leads` group. A ticket, a customer, or a
recipient the graph has no row for resolves to an unknown resource, and the engine gives that
resource a sentinel owner no human can equal, so the rule refuses it. The graph has resource rows
for two tables and the desk mailbox; the ticket and customer rows are W12's.

Carol carries `support-leads` in the realm and owns `support-lead-agent`, whose allowlist holds the
database and the mail tools, so a support task run as carol passes the baseline permit and the
subject rule's exemption. The support CLI therefore defaults to `carol`. Bob owns `support-agent`
and is the honest non-lead case: his calls are refused by `wrong-subject` until W12 seeds the
ticket and customer resource rows, and that refusal is the scenario-7 shape the rule exists for.
The choice is a seeded-realm fact rather than a policy change, and no policy is edited for it.

## The seeded ticket and the status vocabulary

`scripts/seed_smoke.py` seeds one customer, one honest ticket, and one generated API key. The
ticket asks the desk to confirm which API key is on file and whether it is still active, which the
`customers` and `api_keys` rows answer, so an agent that reads them can reply rather than guess.
The ticket starts `open`, and the desk names `resolved` as the status for a ticket it has answered.
`db.update_ticket` accepts any non-empty status, so that vocabulary is the fixture's convention
rather than a value the schema enforces, and the support prompt says only "set the status to
reflect where the ticket stands", so the smoke records the status the agent chose. The seeder
resets the ticket to `open` with no notes on every run, so a smoke starts from the same state. The key value
is generated at seed time and never written into the file, a test, or git.

## The run record lives in the checkout

`compose.yml` bind-mounts `./runs` to `/app/runs` on the `warrant` service and sets
`WARRANT_RUNS_DIR=/app/runs`, so a run record survives the container and an agent run started in
compose lands beside every other run. The image has no git and no `.git`, so `metadata.json` had no
commit to carry. `warrant/config.py`'s `commit_sha()` and `commit_is_dirty()` now fall back to
`WARRANT_COMMIT` and `WARRANT_DIRTY` when git is absent or refuses to answer, and the smoke passes
both from the checkout on the exec command line. The two names are declared empty in the service
environment rather than interpolated with a default, because the scaffold test refuses a
`${NAME:-...}` in a service environment; the exec carries the real values, and that is the process
that writes the metadata.

## The write set is derived from the graph

`agents/loop.py`'s `write_tools_from_graph` reads `infra/graph.yml` into an in-memory graph and
returns the tools the role's agent holds whose `action_kind` is `write` or `send`. `agents/triage.py`
and `agents/support.py` call it at import. The alternative, a hand-kept `frozenset`, can disagree
with the graph the gateway decides with: a tool added to an agent's allowlist as a write would stay
out of the `Outcome`'s actions, and a read could be counted as one. `tests/test_support_role.py`
re-derives the set from the graph and fails if a graph write is missing, a read is present, or the
set names a tool the agent does not hold.

## The gateway offers only the tools the agent holds

`warrant/gateway.py`'s `list_tools` still discovers per server and caches that discovery per server.
It now narrows the cached list on every request to `graph.agent(chain.act).allowed_tools`. A tool
with no graph row was never re-exported, because the gateway would have no action kind to decide it
with. A tool the graph knows but the acting agent's allowlist lacks is refused by the baseline
permit anyway, so offering it only invited a call that could not be made. `agents/loop.py`'s
`offered_tools` is a second narrowing to the servers a role names, and it says so.

## Each task holds its own token

`agents/loop.py` logs in and exchanges inside `run_role`, so a token is a local of one call and
there is no cache to read it back from. `agents/run_many.py`'s `run_concurrent` runs several tasks
in one `asyncio.TaskGroup`, one run directory and one token per task, so scenario 7's two support
tasks keep their own `sub` and never present each other's bearer. A task that fails cancels its
siblings, and the caller sees an `ExceptionGroup` holding the child errors.

## The ticket and customer resource rows are W12's

The graph has no `db_ticket` or `db_customer` row, so under the shipped rules a non-lead's read of
the seeded ticket resolves the resource to the id string and `wrong-subject` refuses it. W10 does
not seed those rows: W12 owns the scenario resource model, including the owner and the name each
row carries, and `warrant/resources.py` documents the contract that a row's name is the id as a
string. Until W12 lands, the smoke runs as the support lead, whose exemption is what the rule is
written to allow.

## The token record carries the agent

`runs/<task_id>/token.json` gained an `agent` key beside `audience` and `user`. The value is the
client the token was exchanged as, which is also the run's `act`. The key is additive and nothing
parses the record strictly. It is recorded here so a reader of a run knows which client the token
named without inferring it from the claims.
