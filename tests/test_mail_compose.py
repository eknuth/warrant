"""The compose mailpit and mail-mcp blocks, checked without a stack.

These are the invariants the resource server and the integration tests depend
on: the mailpit image, the port split (SMTP on the compose network, HTTP on the
host), a healthcheck that works in that image, the mail server's command and
upstream URL, and the gateway entry that re-exports its tools.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]


def compose() -> dict:
    return yaml.safe_load((REPO / "compose.yml").read_text())


def test_mailpit_is_the_mail_sink_with_a_working_healthcheck() -> None:
    service = compose()["services"]["mailpit"]

    assert service["image"] == "axllent/mailpit"
    # The image has no curl, so the healthcheck has to be one busybox wget can
    # run. `/livez` answers 200 once the HTTP listener serves.
    check = " ".join(service["healthcheck"]["test"])
    assert "wget" in check
    assert "/livez" in check


def test_only_the_mailpit_http_port_is_published_to_the_host() -> None:
    """SMTP is compose-internal; the grader reads the mailbox over HTTP."""
    service = compose()["services"]["mailpit"]

    assert "8025:8025" in service["ports"]
    assert "1025" in service["expose"]
    assert "1025:1025" not in service["ports"]


def test_the_mail_mcp_service_matches_the_postgres_one() -> None:
    service = compose()["services"]["mail-mcp"]

    assert service["image"] == "warrant-local:latest"
    assert service["command"] == ["python", "-m", "servers.mail_mcp.server"]
    assert service["expose"] == ["9103"]
    assert service["environment"]["SMTP_HOST"] == "mailpit"
    assert service["environment"]["MAIL_URL"] == "http://mailpit:8025"
    assert service["depends_on"]["mailpit"]["condition"] == "service_healthy"


def test_the_gateway_lists_the_mail_upstream_and_waits_for_it() -> None:
    servers = yaml.safe_load((REPO / "infra" / "servers.yml").read_text())["servers"]
    entry = next(server for server in servers if server["name"] == "mail-mcp")

    assert entry["prefix"] == "mail"
    assert entry["url"] == "http://mail-mcp:9103/mcp"
    assert entry["audience"] == "mail-mcp"
    assert "mail-mcp" in compose()["services"]["warrant"]["depends_on"]


def test_env_example_names_the_mail_settings() -> None:
    text = (REPO / ".env.example").read_text(encoding="utf-8")

    for name in ("MAIL_URL", "SMTP_HOST", "SMTP_PORT", "MAIL_FROM"):
        assert f"\n{name}=" in text, name


def test_the_makefile_runs_the_mail_server() -> None:
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")

    assert "mail-mcp:" in makefile
    assert "servers.mail_mcp.server" in makefile
