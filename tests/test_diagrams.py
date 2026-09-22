"""The archify diagrams under `docs/diagrams/` cannot drift from their sources.

Three checks, all over the committed files:

  * `diagrams.txt` is the list `make diagrams` reads. Every line's name has a
    JSON whose `diagram_type` matches the listed type, and every id in that
    JSON is unique, so a rename cannot leave a dangling reference.
  * Every label a diagram draws appears in its rendered SVG. An IR edited
    without a `make diagrams` afterward fails here instead of shipping a stale
    picture.
  * A `policies/*.cedar` label is a glob, and it has to match real files: the
    diagram names the policy set, so an empty match means the label is wrong.

The README's side of the same contract, that both diagrams are referenced as a
PNG with the SVG beside them, is checked in `tests/test_readme_numbers.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIAGRAMS_DIR = ROOT / "docs" / "diagrams"
DIAGRAMS_TXT = DIAGRAMS_DIR / "diagrams.txt"


def _listed() -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for line in DIAGRAMS_TXT.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, diagram_type = stripped.split()
        entries.append((name, diagram_type))
    return entries


def _labels(payload: dict) -> list[str]:
    """Every label the payload draws, whichever diagram type it is."""
    labels: list[str] = []
    for key in ("components", "participants", "nodes"):
        for item in payload.get(key, []):
            labels.append(item["label"])
    for message in payload.get("messages", []):
        labels.append(message["label"])
    return labels


def test_every_listed_diagram_parses_and_matches_its_type():
    entries = _listed()
    assert entries, "diagrams.txt lists no diagrams"
    for name, diagram_type in entries:
        payload = json.loads((DIAGRAMS_DIR / f"{name}.json").read_text())
        assert payload["diagram_type"] == diagram_type, name
        assert payload["meta"]["quality_profile"] == "showcase", name
        for suffix in ("html", "svg", "png"):
            rendered = DIAGRAMS_DIR / f"{name}.{suffix}"
            assert rendered.exists(), rendered
            assert rendered.stat().st_size > 0, rendered


def test_every_id_in_a_diagram_is_unique():
    for name, _ in _listed():
        payload = json.loads((DIAGRAMS_DIR / f"{name}.json").read_text())
        ids = [
            item["id"]
            for key in ("components", "participants", "nodes")
            for item in payload.get(key, [])
        ]
        assert len(ids) == len(set(ids)), name


def test_every_drawn_label_is_in_the_rendered_svg():
    for name, _ in _listed():
        payload = json.loads((DIAGRAMS_DIR / f"{name}.json").read_text())
        svg = (DIAGRAMS_DIR / f"{name}.svg").read_text()
        missing = [label for label in _labels(payload) if label not in svg]
        assert not missing, f"{name}: labels missing from the SVG: {missing}"


def test_a_cedar_glob_matches_real_policy_files():
    for name, _ in _listed():
        payload = json.loads((DIAGRAMS_DIR / f"{name}.json").read_text())
        for label in _labels(payload):
            if label.endswith("*.cedar"):
                assert list(ROOT.glob(label)), f"{name}: {label} matches no file"
