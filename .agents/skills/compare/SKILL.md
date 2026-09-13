---
name: compare
description: Compare two result columns cell by cell with the eval comparison module. Placeholder until the eval tree exists, so do not run it yet. Usage /compare <before> <after>, both paths under evals/results/.
---

# Compare two columns

Status: stub. W15 fills this in with `evals/compare.py` and the reading order.

Argument: `<before> <after>`, both paths under `evals/results/`, for example
`w15-pass/full full`.

What it will do when W15 lands it: run the paired comparison and read it in a fixed order, the
paired line first, then by scenario, then the moved cells, the controls, and the validation codes.
The reply carries the paired total and outcome with their signs, the count that came out right, the
validation failures, calls, cost, and each moved cell on one line.

Until W15 exists there is no comparison module and no results directory.
