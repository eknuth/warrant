---
name: cell
description: Read one result cell, its grade, validation messages, hypotheses, evidence, and tool log. Placeholder until the eval tree exists, so do not run it yet. Usage /cell <col> <scenario> <n>.
---

# Read one cell

Status: stub. W15 fills this in with `evals/cell.py` and the reading order.

Argument: `<column> <scenario> <n>`, for example `full checkout-latency 1`.

What it will do when W15 lands it: print the cell's grade, validation messages, hypotheses, and the
tool log, then read them in a fixed order, the component below 1.0 first, then the validation
messages, then the top hypothesis against the scenario's ground truth, then the query in the tool
log that would have settled it. The reply names the loss as a method gap in general form, with the
query id or the missing query, in under ten lines.

Until W15 exists there is no cell to read and no results directory.
