---
name: pass-run
description: Run a before-and-after eval pass in the shape W15 owns. Placeholder until the eval tree exists, so do not run it yet. Use when Ed says "start the pass" or an issue's acceptance criteria call for a before-and-after across the scenarios.
---

# Run a pass

Status: stub. W15 fills this in with the real scenario list, the ingest and cost checks, and the
exact pass script.

Argument: `<park>`, the name for the column being replaced, for example `w15-pass`.

What it will do when W15 lands it:

1. Check the branch is the issue branch and never `main`, and write the short SHA into the log.
2. Check that no other run is going. The `block_double_emit` hook refuses a second run; do not wait
   it out with a sleep loop, because one run's tail overlaps the other's head.
3. Park the live results column four levels deep, `evals/results/<park>/<config>/<scenario>/<n>`.
   The `block_parked_column` hook refuses a three-level park, and the park name must not be one the
   runner writes.
4. Run the scenarios for the before and after columns, then render the report.
5. Report the paired number, and trace every loss to the method gap behind it before it becomes a
   finding.

Until W15 exists, `evals/` does not exist and there is nothing to park or compare. If an issue asks
for this before then, say so instead of inventing a shape.
