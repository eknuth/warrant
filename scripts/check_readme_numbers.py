"""Assert that every number and reference in README.md is one a reader can check.

    uv run python scripts/check_readme_numbers.py

The README is the argument, and its numbers are its evidence. This script is
the same rule the project puts on the agent, turned on the README: a figure may
only appear here if it appears in a generated or recorded file that something
else produced, or in a short allowlist below where every entry names where it
came from.

Five checks:

1. Every numeric token in the README prose and tables appears as a numeric token
   in `evals/results/v1/report.md` (generated from the grade files), in
   `docs/build-cost.md` (generated from the harness records by
   `scripts/build_cost.py`), or in ALLOWLIST.
2. The em dash count is zero.
3. The claim is the first thing on the page: the first content after the title
   is prose, not a heading, table, image, or code fence.
4. Both diagrams are referenced as a PNG with their SVG beside them.
5. The "What this does not show" section exists with at least four bullets, and
   the prose word count outside tables and fenced code is inside the bounds.

Code fences and inline code spans are stripped before tokens are collected, so
a command line or an identifier in backticks is not held to the rule; a table
cell is, because a reader reads a table as a claim. Run ids, file paths, commit
hashes, ISO dates, and model names are scrubbed from both sides first, so a
digit inside `runs/dsh/w13.json` or `qwen-local:qwen3.8:27b@off` neither counts
as a claim nor vouches for one.

The check reads digits only. A count the README spells out in words (ten
scenarios, nine ablations, five findings) is not read here; the test in
`tests/test_readme_numbers.py` recomputes the ones the README presents as
results from the rows of `evals/results/v1/report.md`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
SOURCES = (
    ROOT / "evals" / "results" / "v1" / "report.md",
    ROOT / "docs" / "build-cost.md",
)

MIN_WORDS = 1400
MAX_WORDS = 2400
NOT_SHOWN_HEADING = "## What this does not show"
MIN_NOT_SHOWN_BULLETS = 4
DIAGRAMS = ("architecture", "decision-path")

# Numbers the generated files do not carry. Each one names its source.
ALLOWLIST: dict[str, str] = {
    # `requires-python = ">=3.12"` in pyproject.toml, quoted in "How to run it".
    "3.12": "pyproject.toml requires-python",
    # The token exchange specification named in the claim's mechanism.
    "8693": "RFC 8693, docs/decisions/002-token-exchange.md",
    # The v1 column's size: 10 scenarios x 9 ablations x 3 repeats. The v1
    # report has nine summary rows of 30 runs each and never prints the total.
    "270": "evals/results/v1/report.md, nine 30-run summary rows",
    # Finding 8 in docs/findings.md: the private reads of scenarios 01 and 10
    # were attempted in 15 of their 54 cells (2 scenarios x 9 ablations x 3
    # repeats).
    "15": "docs/findings.md finding 8",
    "54": "docs/findings.md finding 8, 2 scenarios x 9 ablations x 3 repeats",
    # The cut second family: docs/findings.md, "The second family that was cut".
    "120": "docs/findings.md, the cut second family",
    "28": "docs/findings.md, the cut second family's wall-clock estimate",
    # The v1 column's measured cost: docs/findings.md, "The numbers the README
    # will quote".
    "37.2": "docs/findings.md, v1 seconds per cell",
    "10,046": "docs/findings.md, v1 column wall seconds",
    "2.8": "docs/findings.md, v1 column wall hours",
    "643,802": "docs/findings.md, v1 output tokens",
    # The Jev ablations' measured classifier spend: docs/findings.md, same
    # section.
    "648": "docs/findings.md, Jev classifier calls",
    "79": "docs/findings.md, Jev cells",
    "0.053523": "docs/findings.md, Jev input cost in dollars",
    # The adjudicator side by side: docs/findings.md, "The adjudicator side by
    # side".
    "129.7": "docs/findings.md, cloud adjudicator mean call latency",
    "178": "docs/findings.md, local adjudicator mean call latency in ms",
    "0.000061": "docs/findings.md, local adjudicator cost per call",
    # The deferred effort axis: docs/findings.md, "The effort axis".
    "167.2": "docs/findings.md, the @high probe seconds per cell",
    "45,142": "docs/findings.md, the @high column wall seconds",
    "12.5": "docs/findings.md, the @high column wall hours",
}

# A run of digits, with optional thousands separators, decimal part, and percent sign.
# The separator alternative comes first so `10,046` wins over `10`, and neither
# alternative can end on a comma, so a number at the end of a clause stays a number.
NUMBER = re.compile(r"\d+(?:,\d{3})+(?:\.\d+)?%?|\d+(?:\.\d+)?%?")
FENCE = re.compile(r"^```")
INLINE_CODE = re.compile(r"`[^`]*`")
# Identifiers that carry digits without being numbers: run ids, file paths,
# commit hashes (seven or more hex characters with at least one letter), ISO
# dates, model names such as qwen3.8, and issue ids.
IDENTIFIERS = (
    re.compile(r"\brun-[0-9a-f]{12}\b"),
    re.compile(r"/result/[A-Za-z0-9]+"),
    re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}\b"),
    re.compile(r"\b\d{4}-\d{2}-\d{2}(?:T[\d:]+Z?)?\b"),
    re.compile(r"\bEDW-\d+\b"),
    re.compile(r"\bW\d+\b"),
    re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:[-/.][A-Za-z0-9]+)+\b"),
)


def scrub_identifiers(line: str) -> str:
    """Blank the identifiers in IDENTIFIERS so their digits are not read as numbers."""
    for pattern in IDENTIFIERS:
        line = pattern.sub(" ", line)
    return line


def strip_code(text: str) -> str:
    """Drop fenced blocks, inline code spans, and identifiers, keeping line structure."""
    out: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if FENCE.match(line.strip()):
            in_fence = not in_fence
            out.append("")
            continue
        out.append("" if in_fence else scrub_identifiers(INLINE_CODE.sub(" ", line)))
    return "\n".join(out)


def tokens_with_lines(text: str) -> list[tuple[str, int]]:
    """Every numeric token in `text`, paired with its 1-based line number.

    A leading `-` counts as part of the number only when it starts a word, so
    `-0.50` in a table cell is negative and the `3` in `qwen3.8` is not.
    """
    found: list[tuple[str, int]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for match in NUMBER.finditer(line):
            start = match.start()
            token = match.group(0)
            if start > 0 and line[start - 1] == "-":
                before = line[start - 2] if start >= 2 else ""
                if before == "" or before.isspace() or before in "([":
                    token = "-" + token
            found.append((token, lineno))
    return found


def source_tokens() -> set[str]:
    known = set(ALLOWLIST)
    for path in SOURCES:
        known.update(token for token, _ in tokens_with_lines(strip_code(path.read_text())))
    return known


def prose_words(text: str) -> int:
    """Words outside tables and fenced code, counted on the raw README."""
    count = 0
    in_fence = False
    for line in text.splitlines():
        if FENCE.match(line.strip()):
            in_fence = not in_fence
            continue
        if in_fence or line.lstrip().startswith("|"):
            continue
        count += len(line.split())
    return count


def claim_is_first(text: str) -> bool:
    """True when the first thing after the H1 title is prose.

    A heading, table, image, or code fence before the claim means a reader meets
    something else first, which is the failure this checks for.
    """
    lines = text.splitlines()
    try:
        title = next(i for i, line in enumerate(lines) if line.startswith("# "))
    except StopIteration:
        return False
    for line in lines[title + 1 :]:
        stripped = line.strip()
        if not stripped:
            continue
        return not (
            stripped.startswith("#")
            or stripped.startswith("|")
            or stripped.startswith("![")
            or stripped.startswith("```")
            or stripped.startswith("<")
        )
    return False


def not_shown_bullets(text: str) -> int:
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == NOT_SHOWN_HEADING)
    except StopIteration:
        return -1
    count = 0
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        if line.startswith("- "):
            count += 1
    return count


def main() -> int:
    raw = README.read_text()
    known = source_tokens()
    failures: list[str] = []

    unknown = [
        (token, lineno)
        for token, lineno in tokens_with_lines(strip_code(raw))
        if token not in known
    ]
    if unknown:
        failures.append(
            f"{len(unknown)} number(s) in README.md appear in neither "
            f"{SOURCES[0].name}, {SOURCES[1].name}, nor the allowlist:"
        )
        lines = raw.splitlines()
        for token, lineno in unknown:
            failures.append(f"  line {lineno}: {token}   in: {lines[lineno - 1].strip()[:90]}")

    em_dashes = raw.count("\u2014")
    if em_dashes:
        failures.append(f"em dash count is {em_dashes}, expected 0")

    if not claim_is_first(raw):
        failures.append("the first content after the title is not prose; the claim must be first")

    for name in DIAGRAMS:
        png = f"docs/diagrams/{name}.png"
        svg = f"docs/diagrams/{name}.svg"
        if png not in raw:
            failures.append(f"README does not reference {png}")
        if svg not in raw:
            failures.append(f"README does not reference {svg}")

    bullets = not_shown_bullets(raw)
    if bullets == -1:
        failures.append(f"no {NOT_SHOWN_HEADING!r} section found")
    elif bullets < MIN_NOT_SHOWN_BULLETS:
        failures.append(
            f"{NOT_SHOWN_HEADING!r} has {bullets} bullets, expected at least "
            f"{MIN_NOT_SHOWN_BULLETS}"
        )

    words = prose_words(raw)
    print(f"README prose words (outside tables and code fences): {words}")
    if not MIN_WORDS <= words <= MAX_WORDS:
        failures.append(f"prose word count {words} is outside {MIN_WORDS} to {MAX_WORDS}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("README.md: every number and reference checks out.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
