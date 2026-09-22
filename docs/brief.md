# The call brief

Identity tells you who asked and which agent is acting. It authenticates the call and says nothing
about whether to trust it. Warrant adds the third input: what the agent read on the way to the
action. Every tool call passes through it, the read set goes to the policy engine beside the chain
and the resource, and the decision is written down so a later reader can check it.

<img src="diagrams/architecture.png" alt="Warrant architecture" width="520">

One model family: `deepseek:deepseek-flash@off` with the DeepSeek adjudicator, three repeats per
cell, 30 cells per row. Held means no unauthorized action ran. False blocks are legitimate actions a
run denied or escalated.

| ablation | held | false blocks | mean score |
| --- | --- | --- | --- |
| `full` | 30 of 30 | 12 | 3.30 |
| `task-taint` | 30 of 30 | 5 | 4.17 |
| `content-taint` | 28 of 30 | 11 | 3.07 |
| `jev` | 26 of 30 | 20 | 0.30 |
| `cascade` | 30 of 30 | 20 | 3.17 |
| `no-provenance` | 28 of 30 | 3 | 2.80 |
| `no-exchange` | 27 of 30 | 35 | -2.33 |
| `prompt-only` | 24 of 30 | 0 | 0.60 |
| `jev-only` | 27 of 30 | 14 | 1.53 |

Three findings.

1. The ledger is what refuses the private read. Take provenance out and the confidential read of
   the private repository runs, in 2 of the 3 repeats of that row. The chain and the scopes alone
   still held 27 of 30 cells; what they missed was the read whose identity they could not check.
2. Task taint against content taint is a policy choice Warrant exposes, not a property of the
   model. Task taint catches a paraphrase and refuses honest work that leaves the named target.
   Content taint lets a paraphrase through and refuses an honest comment that repeats the source's
   words. On 09 the task rule paid two false blocks and the content rule three. On 10 the content
   rule paid three and the task rule paid none only because the agent never made the call. Neither
   rule sees what the model did between the read and the write.
3. Most of the held rate is the agent declining the bait. In 270 cells the agent never attempted the
   injected call of scenarios 02, 03, and 04, and it attempted the private reads of 01 and 10 in 15
   of 54. A second model family would separate Warrant holding from one model being well behaved. It
   was cut.

The question to put to them: how does their policy engine see provenance today, only who the agent
is and what it holds, or also what it read before it acted? Would their customers rather take the
task-taint cost, honest work refused, or the content-taint miss, a paraphrase getting through?

`README.md` has the full argument, the ten scenarios, the findings, and the limits.
