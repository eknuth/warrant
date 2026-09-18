"""Warrant's process entry points.

`uv run python -m warrant serve` starts the MCP gateway on `:9100/mcp`. The
gateway seeds the access graph from `infra/graph.yml` (idempotent upsert), reads
its policies from `policies/`, and fronts the servers in `infra/servers.yml`.

`uv run python -m warrant queue list|approve <id> --minutes N|deny <id>` reads
and answers the human escalation queue under the runs directory.

Nothing here reads a secret at import time: settings are constructed only when
`serve` runs, and the client secret comes from `.env`.
"""

from __future__ import annotations

import argparse
import logging
import sys

import uvicorn

from warrant import graph as graph_module
from warrant.engine import CedarEngine
from warrant.gateway import Gateway, GatewaySettings, build_app, load_servers
from warrant.log import DecisionLog
from warrant.provenance import Ledger


def serve(host: str | None = None, port: int | None = None) -> int:
    """Build the gateway and serve it until interrupted."""
    settings = GatewaySettings()
    if host is not None:
        settings.warrant_gateway_host = host
    if port is not None:
        settings.warrant_gateway_port = port

    # `load` creates the database when it is absent and upserts the seed, so a
    # fresh checkout can serve without a separate seeding step.
    graph = graph_module.load(settings.warrant_graph_seed, settings.warrant_graph_db)
    decision_log = DecisionLog(settings.warrant_runs_dir)
    engine = CedarEngine(
        policies_dir=settings.warrant_policies_dir,
        graph=graph,
        decision_log=decision_log,
    )
    ledger = Ledger(settings.warrant_runs_dir)
    gateway = Gateway(
        graph=graph,
        engine=engine,
        ledger=ledger,
        decision_log=decision_log,
        servers=load_servers(settings.warrant_servers_file),
        settings=settings,
    )
    app = build_app(gateway)
    logging.getLogger(__name__).info(
        "warrant gateway on %s:%d%s",
        settings.warrant_gateway_host,
        settings.warrant_gateway_port,
        settings.warrant_gateway_path,
    )
    uvicorn.run(
        app,
        host=settings.warrant_gateway_host,
        port=settings.warrant_gateway_port,
        log_level="info",
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    # `queue` carries its own parser and its own subcommands, so it is routed
    # before this parser sees its arguments; the subparser below exists so
    # `warrant --help` lists the command.
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["queue"]:
        from warrant.queue import main as queue_main

        return queue_main(argv[1:])

    parser = argparse.ArgumentParser(
        prog="warrant", description="The Warrant authorization service."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    serve_parser = sub.add_parser("serve", help="run the MCP gateway")
    serve_parser.add_argument("--host", default=None, help="bind address")
    serve_parser.add_argument("--port", type=int, default=None, help="bind port")
    sub.add_parser("queue", help="read and answer the human escalation queue")
    args = parser.parse_args(argv)

    if args.command == "serve":
        return serve(args.host, args.port)
    parser.error(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
