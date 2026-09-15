"""The provenance design doc, which the README lifts when W18 lands.

The doc is a deliverable, so what it promises is pinned here: the section
heading the README will lift, the paraphrase miss stated as a miss, the secret
ordering limit it names, and the house rule that prose carries no em dash.
"""

from __future__ import annotations

from pathlib import Path

DOC = Path(__file__).resolve().parents[1] / "docs" / "provenance.md"
HEADING = "## task taint or content taint"


def test_the_doc_has_the_section_the_readme_lifts() -> None:
    text = DOC.read_text(encoding="utf-8")

    assert HEADING in text
    section = text.split(HEADING, 1)[1]
    assert "does not catch a paraphrase" in section
    assert "sees data flow through the model" in section


def test_the_doc_states_the_secret_ordering_limit() -> None:
    """The doc names the one value the redaction cannot reach, rather than claiming none."""
    text = " ".join(DOC.read_text(encoding="utf-8").split())

    assert "ordering limit" in text
    assert "leak lasts until some read reveals the value" in text
    assert "over-redaction is the safe direction" in text


def test_the_doc_has_no_em_dash() -> None:
    assert "\u2014" not in DOC.read_text(encoding="utf-8")
