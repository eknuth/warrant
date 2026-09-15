"""The compose postgres block and the schema it loads, checked without a stack.

These are the invariants the resource server and the tests depend on: the
pinned major, the database name, the schema file mounted where the image reads
it at initdb, and a volume the data survives in. The schema check reads the
file rather than a running database, so it fails the moment a table is dropped
from the init SQL.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
SCHEMA = REPO / "infra" / "postgres" / "schema.sql"

TABLES = {"customers", "tickets", "api_keys", "notes"}


def compose() -> dict:
    return yaml.safe_load((REPO / "compose.yml").read_text())


def test_postgres_is_pinned_to_17() -> None:
    assert compose()["services"]["postgres"]["image"] == "postgres:17"


def test_the_support_database_and_role_are_named_in_the_service() -> None:
    environment = compose()["services"]["postgres"]["environment"]

    assert environment["POSTGRES_DB"] == "support"
    assert environment["POSTGRES_USER"] == "warrant"
    # The password is the credential and has to come from `.env` rather than be
    # defaulted, the same rule every other credential in the file follows.
    assert "${POSTGRES_PASSWORD:?" in environment["POSTGRES_PASSWORD"]


def test_the_schema_is_mounted_read_only_at_the_init_directory() -> None:
    volumes = compose()["services"]["postgres"]["volumes"]

    assert "./infra/postgres/schema.sql:/docker-entrypoint-initdb.d/01-schema.sql:ro" in volumes


def test_postgres_data_survives_a_restart_in_a_named_volume() -> None:
    model = compose()

    assert "postgres-data" in model["volumes"]
    assert "postgres-data:/var/lib/postgresql/data" in model["services"]["postgres"]["volumes"]


def test_the_schema_creates_the_four_tables() -> None:
    text = SCHEMA.read_text(encoding="utf-8")

    created = set(re.findall(r"CREATE TABLE (\w+)", text))
    assert created == TABLES


def test_the_schema_is_schema_only() -> None:
    """No rows in the init file: W12 seeds them, and a seeded row here would be
    invisible to the scenario fixture and surprising to find in a clean volume."""
    statements = SCHEMA.read_text(encoding="utf-8").upper()

    assert "INSERT INTO" not in statements
    assert "COPY " not in statements


def test_the_postgres_mcp_service_matches_the_gitea_one() -> None:
    service = compose()["services"]["postgres-mcp"]

    assert service["image"] == "warrant-local:latest"
    assert service["command"] == ["python", "-m", "servers.postgres_mcp.server"]
    assert service["expose"] == ["9102"]
    assert service["environment"]["POSTGRES_HOST"] == "postgres"
    assert service["depends_on"]["postgres"]["condition"] == "service_healthy"


def test_the_gateway_lists_the_postgres_upstream() -> None:
    servers = yaml.safe_load((REPO / "infra" / "servers.yml").read_text())["servers"]
    entry = next(server for server in servers if server["name"] == "postgres-mcp")

    assert entry["prefix"] == "db"
    assert entry["url"] == "http://postgres-mcp:9102/mcp"
    assert entry["audience"] == "postgres-mcp"
