"""The three deterministic matchers behind content taint.

W11 answers one question for a write or a send: do the call's argument strings
carry text that first appeared in something the task read? There is no model in
the answer. The three matchers here are the whole of it, and each is a string
operation, so the same two texts always produce the same hits on every machine.

* `substring`: an exact shared run of 24 or more characters.
* `identifier`: a URL, an email, a repository name, an issue number, or a
  key-shaped token that appears in the arguments and in the source.
* `ngram`: more than three shared word 5-grams.

Content taint is precise and cheap on a task that read nothing external, and it
is blind to a paraphrase: a rewrite that keeps the meaning and changes the words
shares no 24-character run, no identifier, and fewer than four 5-grams. That
miss is deliberate and `docs/provenance.md` states it.

The module has no I/O and imports nothing from the gateway, so the matchers are
unit-testable without a stack. `normalize` lowercases, collapses every run of
whitespace to one space, and caps the text at `MAX_TEXT`. Every matcher
normalizes its inputs itself, so a caller cannot get a different answer by
forgetting to.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

# The cap on the text one source keeps. A read result larger than this is
# truncated before matching, so a huge file cannot make a task's argument scan
# unbounded. 64 KB of text is far more than any single write's arguments.
MAX_TEXT = 64 * 1024

# An exact shared run shorter than this is not evidence. 24 characters is long
# enough that a coincidence in ordinary prose is unlikely and short enough to
# catch a copied sentence fragment.
MIN_SUBSTRING = 24

# The longest sample a substring hit records. The match itself may be longer;
# the sample is an excerpt for the decision log.
MAX_SAMPLE = 512

NGRAM_SIZE = 5
# "Above three shared 5-grams" means four or more distinct shared grams.
MIN_SHARED_NGRAMS = 4

# The kinds a hit records. Cedar never sees these; they are for the decision log
# and the tests.
SUBSTRING = "substring"
IDENTIFIER = "identifier"
NGRAM = "ngram"

# One candidate identifier, longest patterns first so a URL is recorded as a URL
# rather than only as the repository-shaped path inside it.
_URL = re.compile(r"https?://[^\s\"'<>)\]}]+")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_REPO = re.compile(r"\b[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\b")
# A bare issue reference needs two digits. `#1` is a number, not an identity: it
# appears in ordinary text and a hit on it would be a false positive.
_ISSUE = re.compile(r"#[0-9]{2,9}\b")
_KEY_SHAPED = re.compile(r"(?:sk_live_|ghp_)[A-Za-z0-9_]{4,}|AKIA[A-Z0-9]{8,}")

_IDENTIFIER_PATTERNS = (_URL, _EMAIL, _REPO, _ISSUE, _KEY_SHAPED)

_WORD = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class Hit:
    """One reason a source overlaps the arguments."""

    kind: str
    sample: str


def normalize(text: str) -> str:
    """Lowercase, collapse whitespace, and cap at `MAX_TEXT`.

    The cap is applied after the collapse so a text that is mostly whitespace
    keeps as much of its content as the limit allows.
    """
    collapsed = " ".join(text.split())
    return collapsed[:MAX_TEXT].lower()


def dump(payload: Any) -> str:
    """A read result as text, before normalization.

    The payload is the gateway's parsed tool result. A string is already text;
    anything else is dumped with sorted keys so the same result normalizes the
    same way on every run. `default=str` keeps a value the encoder does not know
    from raising out of the request path.
    """
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(payload)


def substring_hits(source: str, arguments: str, *, limit: int = 8) -> list[str]:
    """Every exact shared run of `MIN_SUBSTRING` or more characters.

    A run is recorded at its longest, so one copied paragraph is one hit rather
    than one per window. `limit` bounds the samples one source contributes.
    """
    source = normalize(source)
    arguments = normalize(arguments)
    hits: list[str] = []
    length = len(arguments)
    start = 0
    while start <= length - MIN_SUBSTRING:
        if arguments[start : start + MIN_SUBSTRING] not in source:
            start += 1
            continue
        end = start + MIN_SUBSTRING
        while end < length and end - start < MAX_SAMPLE and arguments[start : end + 1] in source:
            end += 1
        hits.append(arguments[start:end])
        if len(hits) >= limit:
            break
        start = end
    return hits


def identifiers(text: str) -> list[str]:
    """Every identifier-shaped token in `text`, in the order the patterns find them.

    The text is normalized first, so the tokens are lowercase and a caller
    matching them against a normalized source compares like with like.
    """
    text = normalize(text)
    found: list[str] = []
    seen: set[str] = set()
    for pattern in _IDENTIFIER_PATTERNS:
        for match in pattern.finditer(text):
            token = match.group(0)
            if len(token) < 5 or token in seen:
                continue
            seen.add(token)
            found.append(token)
    return found


def identifier_hits(source: str, arguments: str, *, limit: int = 8) -> list[str]:
    """The identifiers in the arguments that also appear in the source."""
    source = normalize(source)
    hits: list[str] = []
    for token in identifiers(arguments):
        if token in source:
            hits.append(token)
            if len(hits) >= limit:
                break
    return hits


def ngram_hits(
    source: str,
    arguments: str,
    *,
    minimum: int = MIN_SHARED_NGRAMS,
    limit: int = 4,
) -> list[str]:
    """The shared word 5-grams, when more than `minimum - 1` of them are shared.

    The count is over distinct grams, so a repeated phrase in a body does not
    inflate the overlap. The samples are in the order the arguments use them,
    which reads as the sentence the two texts share.
    """
    source_grams = set(_ngrams(normalize(source)))
    if not source_grams:
        return []
    shared: list[tuple[str, ...]] = []
    seen: set[tuple[str, ...]] = set()
    for gram in _ngrams(normalize(arguments)):
        if gram in source_grams and gram not in seen:
            seen.add(gram)
            shared.append(gram)
            if len(shared) >= minimum:
                break
    if len(shared) < minimum:
        return []
    return [" ".join(gram) for gram in shared[:limit]]


def find_hits(source: str, arguments: str) -> list[Hit]:
    """Every hit between one source's text and the call's argument text."""
    hits = [Hit(SUBSTRING, sample) for sample in substring_hits(source, arguments)]
    hits.extend(Hit(IDENTIFIER, sample) for sample in identifier_hits(source, arguments))
    hits.extend(Hit(NGRAM, sample) for sample in ngram_hits(source, arguments))
    return hits


def _ngrams(text: str) -> list[tuple[str, ...]]:
    words = _WORD.findall(text)
    return [
        tuple(words[index : index + NGRAM_SIZE]) for index in range(len(words) - NGRAM_SIZE + 1)
    ]
