# 000. The harness

Date: 2026-09-13. Status: accepted.

## Decision

Warrant is built with DeepSeek Harness (`dsh`) against the DeepSeek cloud API. There is no other
agent CLI in this project and no other vendor's API anywhere, not for writing the code and not
inside the code. The agents under test, the adjudicator, and the coding agent all run on
`deepseek-flash`.

Pinned versions:

| Thing | Version |
|---|---|
| dsh | 0.1.5-rc.1 |
| `deepseek-harness-sdk` | 0.1.5rc1 |
| Model | `deepseek-flash` |
| Provider route | `deepseek-official` |
| Default reasoning effort | `high` |

## What worked

The profile layering is the part worth keeping. `dsh-base` composes with one application bundle,
a profile adds its own patch on top, and the patch can insert plugins, retarget an existing row by
id, or disable one. The `warrant` profile carries the DeepSeek route, its own settings document
(so the global one never reaches it), the project hooks, and the Linear MCP overlay in a single
file that `make dsh-profile` installs.

The hooks bridge runs unmodified command hooks. It puts the tool name in `tool_name` and the tool
arguments in `tool_input`, substitutes `${CLAUDE_PROJECT_DIR}` in each command string at config
parse time, and blocks with exit 2, using stderr as the model-visible reason. The four checks from
the Receipts checkout ported with two changes: the tool is named `bash` rather than `Bash`, and the
project directory comes from the bridge rather than from an assumption about the launch directory.

Project-local skills need no configuration. `skill-filesystem` scans `.agents/skills` at the
project root, and `tool-skill` turns a `/name` token in a user message into the skill body. Both
`issue-start` and `review` appeared in the session catalog the moment their files existed, with no
restart.

`AGENTS.md` loads from the workspace and refreshes after edits.

## What did not

The `warrant` profile cannot host the SDK runtime. It bundles the web app, and the SDK owns stdin
and stdout for its JSON-RPC frames, so a stdio server and a web server cannot share the process.
The SDK path got its own profile, `warrant-sdk`, built from the sdk app bundle over `dsh-base` and
fed the same core patch. It is created by `infra/dsh/install-profile.sh` rather than by
`dsh --from-default-profile sdk`, because the sdk app bundle ships inside the dsh package and is
not published to npm, so `dsh plugin add` cannot install it.

The SDK's `RunResult` carries no usage field. Token counts have to come out of the run's own events.
`scripts/dsh_run.py` folds them from the `assistant/message` events, which carry `inputTokens`,
`outputTokens`, `cacheReadTokens`, and `reasoningTokens`. When a run reports none the record says
`usage_source: "unavailable"` instead of writing zeros, because zeros read like a measurement.

The bridge reads its config once per process and never discovers a project-local `hooks.json` per
session. The profile patch therefore has to name the file. A relative `configPath` resolves against
the directory that launched dsh, so a relative path would silently run no hooks at all from any
other directory; both `configPath` and `projectDir` are absolute for that reason.

Each command in `hooks.json` resolves its script as `$PWD/.dsh/hooks/<name>.py`. The bridge runs a
hook with its working directory set to the session workspace, and `projectDir` pins that to this
checkout, so `$PWD` is the repository root and the absolute `configPath` keeps the config itself
findable from anywhere. The earlier form interpolated the bridge's project-directory variable
instead, which works but writes that tool's variable name into a file that otherwise never mentions
it. `tests/hooks/test_port.py` asserts both halves of the `$PWD` choice: every command names a file
under `.dsh/hooks/`, and every one of those files exists. The cost of the choice is that a session
launched with a workspace other than this repository finds no hook scripts, which is why
`projectDir` is set rather than left to default.

These hooks fail closed on a missing script. Each command checks for its own file and, when the file
is absent, writes `hook missing: <path>` to stderr and exits 2, so the call is refused and the
reason is in the transcript. The earlier `[ -f "$F" ] && python3 "$F"` form exited 0 in that case,
which turned every block into a pass with nothing in the log to say so.

`dsh` rewrites its profile root `cordis.yml` during profile preparation. Under a workspace-confined
file sandbox that write is denied and the command fails before it composes anything, so installing
profiles or booting dsh from inside a confined session needs the wider access.

The lint-after-commit hook had a bug that only a scratch repository could surface. It resolved the
project directory with `git rev-parse --show-toplevel`, which fails in a repository that has no
commits yet, and it then fell back to a configured project directory. Committing for the first time
in an unrelated repository therefore ran this project's `make lint` and reported it red. The
fallback is now the payload's own `cwd` when that directory has a Makefile, and nothing at all
otherwise. The same shape is worth watching anywhere a hook resolves a path: a failure that falls
through to a default turns "I do not know where I am" into "I know, and it is somewhere else".

The same hook then reported red lint for a project whose Makefile has no `lint` target, which is
W0's own state: `make lint` exits non-zero with "No rule to make target". It now asks make for its
database with `make -p -n lint`, which runs nothing, and reads the entry's annotation, where a
target that does not exist is marked "File has not been updated".

The secrets hook had a second, quieter bug. It judged the diff at the payload's `cwd`, which is the
session workspace, so a `git -C <path> commit` was judged against a different repository than the
one the commit landed in. It now follows `git -C` and `cd` in the command text before reading the
diff. That is the same resolution the Receipts hook always did, and dropping it was a regression
worth catching.

Its key patterns also had to be tightened. A broad `sk-` prefix matched plausible-looking tokens in
documentation and in tests, so an ordinary commit of this project's own files was refused with a
reason naming a source file rather than a secret. The patterns now describe the long, specific
shapes real keys have, and `tests/hooks/test_port.py` stages this repository's whole tracked tree
and asserts the hook passes on it. That test is what makes the shape checkable instead of a
judgement call: a key-shaped literal anywhere in the tracked files fails it, and the fixture that
found this one was removed because of it.

There are two delegation rows, because a per-call effort field is not available. The mechanism for
one is `modelSelectionSettings: true` on the delegation tool, and that cannot be set on a standing
row: the plugin rejects it at load with "standing `modelSelectionSettings` requires a scoped preset
Context", which fails the whole profile rather than the one row. That scoped Context comes from an
agent preset, and per-call effort belongs with the preset work. Until then the effort is pinned per
row: `subagent` at `high` for implementers, `subagent_review` at `max` for the reviewer. Verified
by delegating through `subagent_review`: the child session logs `origin: subagent` and its request
header carries `reasoningEffort: max` against `deepseek-flash`.

## The fallback

If dsh blocks on something, the fallback is the Codex CLI with DeepSeek's official setup script
over the Responses API. The trigger is a dsh defect that stops W0 through W2, not a slow afternoon.
Nothing in this repository is written against the SDK twice: `scripts/dsh_run.py` is the only file
that imports the SDK, the skills call a shell command rather than a Python module, and the four
hooks are standard library scripts that any agent CLI with a hook protocol can run. So the fallback
would rewrite the profile layer and the runner, and leave `AGENTS.md`, the hooks, and the skills in
place.

## Consequences

The name the bridge owns, `hooks-claude-code`, is the only place another tool's name appears, plus
the variable it uses internally, named once here. Both are the bridge's public identifiers rather
than a dependency, and the grep check in the review skill treats them as such. Nothing in
`hooks.json` mentions them, because the commands resolve from the working directory instead.
