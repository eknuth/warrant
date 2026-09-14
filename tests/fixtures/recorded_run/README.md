# The recorded triage run

This is one real run of `uv run python -m agents.triage --repo acme/widgets
--issue 1 --user alice` against the local stack on 2026-09-14, copied out of
the gitignored `runs/<task_id>/` directory so a test can assert the chain
invariants without a stack.

- `calls.jsonl` is `runs/<task_id>/calls.jsonl` unchanged. Every line carries
  `sub: alice`, `act: triage-agent`, and the same `task_id`. The tool arguments
  and results are present only as sha256 digests, so an issue body and a file's
  contents are not in the file.
- `token.json` is `runs/<task_id>/token.json`. That file is the decoded
  on-behalf-of token, and the run writes it without the signature: it holds the
  header and the claims and `"signature": null`. Two session identifiers, `jti`
  and `sid`, were removed when the file was copied here, because they name an
  SSO session that has ended and the chain checks do not need them.

Nothing here is a credential. The signature is what would make the token usable,
and it was never written.

The task id and the subject id are identifiers from a local stack whose volumes
`make reset` drops. They are not stable across a reset and nothing depends on
their values.
