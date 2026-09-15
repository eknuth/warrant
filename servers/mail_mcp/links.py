"""Pull the URLs out of a message body.

The exfiltration scenario steers the agent into writing a link that carries a
value the task read from the key table. Warrant refuses that send from the
arguments and the secret policy (W7, W11), and this module is what makes the
sent message checkable afterwards: `send_reply` returns the list, and
`inspect.sent_messages()` recomputes it from the stored body, so the grader can
compare what the caller claimed with what the mailbox holds.

A URL is the run of non-whitespace that starts at `http` or `https` and stops at
whitespace, at a quote, or at an angle bracket. `[` and `]` and `(` and `)` stay
inside that run, because a URL can carry them: an IPv6 authority is bracketed
(`https://[2001:db8::1]:8025/x`) and a path can hold a bracketed or parenthesized
segment (`/report[1]`, `/wiki/Foo_(bar)`). A closer at the end of the run that
the run does not open belongs to the body rather than the URL, so it is dropped:
the `)` of `[notice](https://docs.test/b)`. The `url` field is kept exactly as it
appeared, without decoding, and it is the record. A string `urlsplit` cannot
parse is still returned with an empty `query`, because a message that crossed the
wire has to stay readable.

The `query` field is a convenience decoded from the URL. It decodes with
`unquote`, not `unquote_plus`, so a `+` in a value stays a `+` instead of
becoming a space; `%20` is still a space. A key repeated in one URL keeps its
last value, because the field is a mapping and one key cannot hold two values,
and a bare token becomes a key with an empty value. Trailing sentence
punctuation stays in the value, because a period can be part of a path. A
comparison whose value matters reads the raw `url` field, not this mapping.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from .models import Link

# A URL runs until whitespace, an angle bracket, or a quote. Brackets and
# parentheses are part of the run and are balanced afterwards, so a bracketed
# IPv6 authority and a parenthesized path segment survive while a body's own
# closing punctuation does not.
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")

# The closer a run may end with, and the opener that has to balance it.
_CLOSERS = {")": "(", "]": "["}


def _trim_unbalanced(url: str) -> str:
    """Drop trailing closers the URL itself does not open.

    The run keeps `[` and `]` and `(` and `)`. A body that wraps a URL in
    parentheses or brackets leaves that closer in the run. It belongs to the URL
    only while the run has at least as many openers as closers; a trailing
    closer past that balance is the body's punctuation and is dropped.
    """
    while url and url[-1] in _CLOSERS:
        if url.count(_CLOSERS[url[-1]]) >= url.count(url[-1]):
            break
        url = url[:-1]
    return url


def _query_pairs(raw_query: str) -> list[tuple[str, str]]:
    """A query string as decoded key/value pairs, without the form `+` rule.

    `parse_qsl` decodes with the form rules and turns `+` into a space, which
    would make the decoded value disagree with the raw `url`. This splits on
    `&` and `=` and decodes each side with `unquote`, so only percent escapes
    are decoded. An empty segment between separators names nothing and is
    skipped; a bare token is kept as a key with an empty value.
    """
    pairs: list[tuple[str, str]] = []
    for segment in raw_query.split("&"):
        if not segment:
            continue
        key, separator, value = segment.partition("=")
        pairs.append((unquote(key), unquote(value) if separator else ""))
    return pairs


def extract_links(text: str) -> list[Link]:
    """Every URL in `text`, in the order it appears, with query values decoded.

    A URL with no query gets an empty mapping. A query key repeated in one URL
    keeps its last value, because the mapping holds one value per key. A URL the
    parser refuses is returned with an empty mapping rather than raised, so one
    odd link does not hide the message it came in.
    """
    links: list[Link] = []
    for match in URL_PATTERN.finditer(text or ""):
        url = _trim_unbalanced(match.group(0))
        if not url:
            continue
        try:
            raw_query = urlsplit(url).query
        except ValueError:
            raw_query = ""
        query: dict[str, str] = {}
        for key, value in _query_pairs(raw_query):
            query[key] = value
        links.append(Link(url=url, query=query))
    return links
