---
name: status
description: Post a status update to the Warrant project on Linear. Reads the issues and their pull requests, works out the project health, and posts the update with the MCP save_status_update tool. Use at the end of a plan day and whenever stopping for Ed's decision.
---

# Post a project status update

The orchestrator session posts project updates. This is the one thing the `linear` CLI cannot do:
it has no project update command, so the update goes through the MCP `save_status_update` tool.

Argument: none, or a phrase to lead the body with.

## Health

Work the health out from the issues and their pull requests, in this order. Off track wins over at
risk, and at risk wins over on track.

| Verdict | When |
|---|---|
| `offTrack` | Any issue whose due date has passed and whose state is not Done or Canceled |
| `atRisk` | Any issue due today whose state is neither In Review nor Done |
| `onTrack` | Neither of the above |

An issue with an open pull request belongs in In Review. If it is still In Progress, the state is
stale: move it with `linear issue update <ID> --state "In Review"` before you compute health, so the
update describes the board as it is.

Pull request state lives in GitHub, not Linear, so read it with
`gh pr list --state open --json number,title,headRefName,url`. A branch that starts with the W number
in the issue title is the issue's pull request.

## The body

Three short sections, plain sentences, no em dashes, no summary of what the project is.

**Landed today.** The work that reached a pull request today, each with its issue and the pull
request link on the same line. A merged pull request says so. If nothing landed, write that.

**Next up.** The next issue in the sequence, and anything else that is due within the next day.

**Blockers.** Anything waiting on Ed, with the specific question. If nothing is blocked, write that
nothing is.

Name the numbers you actually read: test counts, lint state, review findings and their disposition.
Do not claim a criterion passed unless a command or a test in the repository says so.

## Example

```
Health: atRisk

Landed today
- W2 Keycloak realm and verified OBO tokens, PR #3 open, 128 tests, lint clean.
- W5 Warrant core, PR #6 open, 128 tests, lint clean.

Next up
- W6 Warrant as the MCP gateway, due today.
- W7 Cedar policy set, due today.

Blockers
- Four pull requests are open and unmerged, W2 through W5. W6 needs W2, W4, and W5 in the
  request path, so it stacks on unmerged work until they land. Ed decides the merge order.
```

## After posting

Reply with the health and the blockers in two lines. Nothing else.
