# Provenance

Warrant decides a call with what the agent read on the way to it. The gateway
records each read as it forwards it, `warrant/provenance.py` classifies the
source, `warrant/taint.py` keeps the task's running state, and
`warrant/overlap.py` answers whether a write's own arguments carry text from a
source. Nothing in that path calls a model. A classification is a rule over the
source identity and the strings, so the same read always gets the same tier and
the same two texts always produce the same hits. If a classification is wrong it
is wrong the same way on every run, and this file says where the rules are weak.

## The two taints

Task taint (`provenance.hasExternal`) is true when the task has read a source
whose tier is `external` or `unknown` at any point. It is coarse. It catches a
paraphrase because it does not look at the words at all. It costs a task every
write that leaves its named target once anything external has been read, even
when the write's words are the agent's own.

Content taint (`provenance.overlapSources`, `provenance.overlapExternal`) is
computed for one write or send from that call's argument strings. It names the
sources whose text overlaps those strings, and whether any of them is external
tier. It is the narrow rule: it fires only when the arguments share text with a
source. It is not free of false positives, and the cost is stated at the end of
this file. It is blind to a paraphrase, which is the other miss stated there.

`argsTouchSecret` is content taint restricted to secret values. `targetOutsideTask`
is the target comparison. Neither is a taint tier.

`TAINT` in the environment picks which of the two is computed. `both` is the
default and what `full` runs. `task` fills `hasExternal` and leaves the content
fields empty. `content` does the reverse: it fills the content fields and makes
the provenance summary report no external source, while the sources stay in the
record. An unrecognized value stops the process rather than falling back.

## What a read records

When the gateway forwards a read it does two things with the result. It writes
each provenance block to the ledger under
`runs/<task_id>/provenance/<actor>.jsonl`, which is the evidence on disk and
what a later request reads its source list from. It also hands the result to the
task's `TaskState`, which keeps the normalized text of the result beside each
source and collects the secrets the result carried.

`warrant/provenance.py`'s `classify` sets the tier. It starts from the
`author_tier` the resource server reported and corrects three cases the server
cannot see the meaning of:

- A raw SQL read (`run_readonly_sql`) is `unknown`. The statement's only identity
  is a digest and its rows have no single author, so no tier is earned.
- A mail source whose author is not in the member domain is `external`.
- A Gitea file read under `.github/` or `.cursor/`, or named `AGENTS.md`,
  `CLAUDE.md`, or `*.rules`, is `external` unless the last commit author is a
  member or an owner. A commit with no resolvable forge account is not a member,
  so an unaccountable instruction file is graded the same as one from outside.

The third rule is the scenario 4 shape. A file an agent will treat as
instructions is a prompt surface, and its tier follows who last wrote it.

## The text, and what it is matched against

`warrant/overlap.py` holds the three matchers and no I/O.

- `substring`: an exact shared run of 24 or more characters.
- `identifier`: a URL, an email, a repository name, an issue number, or a
  key-shaped token that appears in both the arguments and the source. A
  repository-shaped token whose two halves are both common English words is not
  an identifier, so `and/or`, `read/write`, and `either/or` do not match.
- `ngram`: more than three shared word 5-grams.

Both texts are lowercased and their whitespace is collapsed before matching, and
one source's text is capped at 64 KB. A hit records the source id, its kind, and
a sample. A shared 24-character run is a hit whether or not it is meaningful: a
license header, a signature block, or any boilerplate the source and the write
both carry counts, and the word-pair rejection above is a list rather than a
grammar, so a pair it does not hold can still match.

The overlap scan excludes the argument value that named the call's own resource.
A write has to name the repository or mailbox it touches, and that name appears
in everything read from it, so counting it would make every write overlap every
read of its own target. The comparison is after normalization, so `Acme/Widgets`
is dropped like `acme/widgets`. The body is still scanned. The secret scan keeps
the value, and the section on secrets says why.

## The target the task named

A task's subject is taken from the first call whose arguments resolve to a
resource. `gitea.get_issue(repo="acme/widgets", number=1)` names
`repo-acme-widgets`, and that is the task's target for the rest of the task. A
later call whose resolved resource is not the target sets `targetOutsideTask`.
The comparison is over the kind and the name, so a row of another kind that
happens to share an id is not read as the target.

Two costs of this choice, said here rather than found in a run:

- An agent whose first call is the off-target write names that write's resource
  as the task's target. The alternative was a `task_subject` parameter on the
  token exchange, which would carry the subject from the caller before any tool
  ran. That path needs a claim the issuer mints, so the realm and every client
  would change for it. Taking the subject from the first call keeps the change
  inside the gateway and inside what the agent already sends.
- The comparison is at the resource the graph holds. A repository is one
  resource, so a comment on issue 5 of `acme/widgets` is on the task's target
  when the task started from issue 1. The graph has no issue rows.

A task that never names a resource has no target, and nothing is outside it.

## Secrets

The secret set is filled from the `secrets` list a database result carries, from
the values in a file whose name says it holds secrets (`*.env`, `secrets*`), and
from key-shaped tokens (`sk_live_`, `ghp_`, `AKIA`) found in any file read. A
write or send whose argument strings contain a secret as a substring,
URL-encoded, or base64-encoded sets `argsTouchSecret`. The secret scan sees every
argument value, including the one that names the call's resource. The overlap
scan drops the resource value so a write does not overlap its own target; the
secret scan cannot drop it, because a secret used as the resource name is a leak.

The plain values stay in the process. Each one also has a SHA-256 digest, and
the digest is what the decision log carries. A sample of source text that
contains a secret is redacted before it is recorded, and a resolved resource that
contains a secret is replaced with its digest before it enters the request, so
the audit line for the call carries the digest and a resource that names no row
in the graph. A file under the run directory therefore carries no plain secret
value.

## One `TaskState` per task and actor

The state is keyed by the task id and the actor, the same pair the ledger uses.
An agent writes its own `task-id` scope, so keying on the id alone would let one
agent fill another agent's taint, and the ledger already refuses that for the
sources. A `(task, actor)` key keeps the two consistent.

The text lives in memory. A read is in the ledger as a digest and no content, so
a gateway that restarts has the sources and their tiers and no text to match.
Task taint survives a restart and content taint does not. That follows from what
the ledger keeps, and it is why the overlap fields are the ones that can be
absent after a restart.

## Worked examples

### Scenario 1, the target shift

A triage task reads `acme/widgets#1`, written by a person outside the
organization, so the source tier is `external` and `provenance.hasExternal` is
true for the rest of the task. The agent then calls
`gitea.set_repo_visibility(repo="acme/vault")`. The task's target is
`repo-acme-widgets`, so `targetOutsideTask` is true. The policy `tainted-write`
refuses the call on `hasExternal` and `targetOutsideTask`. A write on the named
target is allowed even after the external read, which is the rule the quiet
control measures.

### Scenario 3, the secret in the arguments

A support task calls `db.get_customer`. The result carries an API key value in
its `secrets` list, so the task's secret set holds it. The agent then calls
`mail.send_reply` with that value in the body. The scan finds the value, or its
URL-encoded or base64 spelling, in the body and sets `argsTouchSecret`. The
policy `secret-in-args` refuses the send. A reply whose body does not contain
the value gets `argsTouchSecret` false and is decided by the rest of the set.

### Scenario 4, the quiet control

A task reads `.github/copilot-instructions.md` whose last commit has no forge
account. The classifier gives that source `external`, so `hasExternal` is true
and `minTier` is `external`. The agent then asks to make a repository public, or
to read a confidential table. There is no text overlap to find because the call
carries no words. The policy `tainted-visibility` reads `hasExternal` and
refuses it, which is the case content taint cannot see.

## task taint or content taint

Task taint and content taint fail in opposite directions, and the shipped
configuration runs both.

Task taint catches a paraphrase. It never looks at the words, so an instruction
the agent restated in its own words is covered as long as the task read
something external. It is also the broad rule: once anything external has been
read, every write or send that leaves the named target is refused, including the
honest ones. That cost is what the quiet control scenario measures.

Content taint costs nothing only when there is nothing to match. A task that
read no source has no text for a hit, and the scan is milliseconds of string
work. It is not free of false positives. A shared run of 24 characters or more
is a hit, and a license header, a signature block, or any boilerplate the source
and the write both carry is 24 characters, so an honest write that repeats a
source's own phrasing is refused. A slash between two common words is a word
pair rather than a repository, and the identifier rule rejects the pairs it
knows, so `and/or` and `read/write` do not fire. A common word pair outside that
list is still a hit and can refuse an honest write. A hit names the source and
the kind of match, so a reader can see what was matched and judge whether it was
copied.

Content taint does not catch a paraphrase. The paraphrase shares no 24-character
run, no identifier, and fewer than four shared 5-grams, and the tests in
`tests/test_overlap.py` and `tests/test_gateway_taint.py` assert that it produces
no hit. A model that restated the injection in its own words is the case the
content rule misses by construction, and the miss is pinned rather than hidden.

Neither rule sees data flow through the model. Warrant observes the value a read
returned and the strings a write is about to send. It does not observe what the
model did between them, so a value the model derived, summarized, or transformed
is outside both rules. The README lifts this section when W18 lands.
