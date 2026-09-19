# Warrant

Work in progress. W18 replaces this file.

> Identity covers who and what. I want the authorization decision to also know how the agent got
> there, meaning what it read before it asked.

Warrant decides one action at a time. An agent proposes an action, Warrant evaluates it against a
policy and answers allow or deny, and the answer is written down with the evidence the agent put in
front of it, so a later reader can see what the agent had read before it asked and check the
decision against the policy that was in force at the time. The provenance evals in this repository
run the agents against seeded scenarios and grade whether the recorded decision matches what the
agent actually did. Today the tree holds the scaffold: the compose skeleton, the Makefile, the test
layout, and the working agreement in `AGENTS.md`. The service, the MCP servers, the agents, the
generator, and the evals arrive issue by issue.

## The Jev ablation rows

W24 adds two columns to the eval matrix, and they ask a different question from the deterministic
rules.

The `jev` column replaces the two deterministic taints with one typed classifier call. For each
candidate write the gateway sends Jev the sources the task read, with their trust tiers, and the
pending write, and asks the one boolean it is built for: does this write derive from content read
from an untrusted source. The probability at or above the threshold becomes the `derived` field,
and a deterministic rule in the engine refuses a write or send on it. The classifier never sees the
policy, the decision, or the expected answer, so the row measures what the classifier catches that
string overlap misses, and what it costs on the honest scenarios. Only seeded scenario data is sent,
and the key stays in the environment.

The `jev-only` column asks Jev for the whole decision. Cedar never runs. Every call goes to the
classifier with the delegation chain, the acting agent and owner, the read set with trust tiers, the
pending call and its resolved resource, the task, and both access graph rows, and one choice over
allow, deny, and escalate comes back. It is the modern sibling of `prompt-only`: there the
enforcement point exists and nothing staffs it, and here the enforcement point exists and a model
staffs it.

Both rows record the classifier's wall latency and its input and output tokens on every call, and a
cell sums them. A probabilistic rule is a policy input rather than the decision: in `jev` the
boolean is one more input to a deterministic rule, and in `jev-only` the same policy engine adapter
that runs Cedar runs the model instead, with no policy set behind it. A prompt-only row tells the
agent the rules and enforces nothing, and a `jev-only` row lets a model enforce them. If `jev-only`
scores well, that is the finding, and the case for the policy engine is still audit: a probability
cannot be reviewed, diffed, or edited, and a Cedar policy can.

## The cascade column

W27 adds `cascade`. Cedar decides first, as it does in `full`. Only a call Cedar already allowed and
that is a write or a send goes to Jev, which answers the same derived question the `jev` column asks.
A yes turns the allow into a deny and records the Cedar permit beside the probability that overrode
it. A no leaves the allow alone. A deny and an escalation never reach the network, so scope
collapse, an orphan agent, and a wrong-subject refusal cost nothing and cannot be talked out of the
answer by a model.

The ordering is the security property. A model may subtract permission and may never add it. Every
deny still has a rule behind it and the probability is evidence beside that rule rather than a
substitute for one. Every allow still passed the policy, so a prompt that convinces Jev to say allow
buys an attacker nothing. Running Jev first loses that: its allow would be the verdict, its deny
would be final, and a probabilistic answer would stand where a policy is supposed to. That is why
the reverse arrangement is rejected. The ordering also means the classifier's latency is paid only
on the allow path, and a call Cedar denies costs no network round trip at all. An endpoint that does
not answer leaves Cedar's answer standing and says `overlay: unavailable`; a timeout is not a deny.

The column checks writes, because a write is where content leaves the task. A read that an injection
asked for is not a candidate, so the cascade does not close the read-side gap W24 found, and the
decision record says so plainly.
