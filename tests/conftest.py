"""The one conftest, and the fixtures it loads from `tests/fixtures/`.

pytest reads fixtures from a `conftest.py`, and pytest 9 refuses a
`pytest_plugins` line anywhere but the top-level one. So this file stays the
entry point and names the per-area modules; the fixtures themselves live under
`tests/fixtures/`, split by the part of the tree they build.

    warrant.py   the W5 authorization objects, no stack needed
    auth.py      self-signed tokens, and the fixtures that reach the live stack

`tests/fixtures/recorded_run/` sits beside them and holds data rather than
fixtures. It is not a package, so nothing imports it.
"""

from __future__ import annotations

pytest_plugins = ["tests.fixtures.warrant", "tests.fixtures.auth"]
