"""The authorization service.

One module per concern: `models` is the data model for a request and its
decision, `graph` is the SQLite access graph, `engine` is the Cedar adapter,
`provenance` is the ledger of what an agent read, `log` is the decision record,
and `config` is the ablation mode. W6 puts these in the request path.
"""
