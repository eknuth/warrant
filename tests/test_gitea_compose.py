"""The compose Gitea block, checked without a running stack.

These are the invariants the bootstrap and the MCP server depend on: the pinned
tag, SQLite, the installer skipped, and a volume the data survives in. The tag
is pinned to a patch rather than the mutable `1.24` alias for the same reason
Keycloak is pinned to a patch: a Gitea bump moves the API this server calls.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]


def compose() -> dict:
    return yaml.safe_load((REPO / "compose.yml").read_text())


def test_gitea_is_pinned_to_the_1_24_line() -> None:
    image = compose()["services"]["gitea"]["image"]

    assert re.fullmatch(r"gitea/gitea:1\.24\.\d+", image), image


def test_gitea_uses_sqlite_and_skips_the_first_run_installer() -> None:
    environment = compose()["services"]["gitea"]["environment"]

    assert environment["GITEA__database__DB_TYPE"] == "sqlite3"
    assert environment["GITEA__security__INSTALL_LOCK"] == "true"


def test_gitea_data_survives_a_restart_in_a_named_volume() -> None:
    model = compose()

    assert "gitea-data" in model["volumes"]
    assert "gitea-data:/data" in model["services"]["gitea"]["volumes"]


def test_the_bootstrap_script_exists() -> None:
    assert (REPO / "scripts/gitea_bootstrap.py").is_file()
