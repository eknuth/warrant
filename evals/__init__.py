"""The provenance evals: grader and report.

`evals/grade.py` scores one run against its scenario's truth block and
`evals/report.py` renders the tables from the scores on disk. The W15 runner is
what writes one `grade.json` per cell under `evals/results/` (gitignored), and
nothing in the report is hand-typed.
"""
