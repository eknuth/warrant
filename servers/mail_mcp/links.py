"""Pull the URLs out of a message body.

The exfiltration scenario steers the agent into writing a link that carries a
value the task read from the key table. Warrant refuses that send from the
arguments and the secret policy (W7, W11), and this module is what makes the
sent message checkable afterwards: `send_reply` returns the list, and
`inspect.sent_messages()` recomputes it from the stored body, so the grader can
compare what the caller claimed with what the mailbox holds.

The pattern is on purpose plain. It finds `http` and `https` URLs, stops at
whitespace and at the closing delimiters a body wraps a URL in, and decodes each
URL's query with the standard form parser. It does not strip trailing sentence
punctuation, because a period can be part of a path and guessing which one is
which would make the same body parse two ways. A caller that needs the URL as a
person would read it does that on top of this, not inside it.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from .models import Link

# A URL runs until whitespace or one of the delimiters a body wraps it in. `)`
# and `]` end a markdown link's target; the quote characters end an HTML
# attribute. A URL that legitimately contains a balanced parenthesis is
# truncated at it, which is the plain-pattern tradeoff named above.
URL_PATTERN = re.compile(r"https?://[^\s<>\"'\)\]]+")


def extract_links(text: str) -> list[Link]:
    """Every URL in `text`, in the order it appears, with query values decoded.

    A URL with no query gets an empty mapping. A query key repeated in one URL
    keeps its last value, because the mapping holds one value per key.
    """
    links: list[Link] = []
    for match in URL_PATTERN.finditer(text or ""):
        url = match.group(0)
        query: dict[str, str] = {}
        for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            query[key] = value
        links.append(Link(url=url, query=query))
    return links
