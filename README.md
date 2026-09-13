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
