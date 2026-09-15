"""The audit line every Warrant resource server writes for a tool call.

W3 wrote this line for gitea-mcp, W8 needs the same one for postgres-mcp, and
W9 will need it for mail-mcp. It lives here so the shape is one definition
rather than three copies that can drift: `ts`, `tool`, `sub`, `act`, `task_id`,
`args_digest`, and `status`.

The server keeps its own logger, so the lines are attributable and the stream
handler is configured once per logger. `claims` is `None` for a call refused
before any claim was verified, which is the one case where the caller fields are
null rather than absent: the line still records that the tool was called and
what it was asked to do.

Nothing here reads a secret or starts a server at import time.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from warrant.oidc import Claims


def args_digest(args: dict[str, Any]) -> str:
    """A stable digest of a tool call's arguments.

    The arguments can carry ticket bodies and query text, so the audit line
    records a digest rather than the values. Canonical JSON (sorted keys, no
    extra whitespace) is what makes the digest stable across runs.
    """
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def audit_record(
    tool: str,
    claims: Claims | None,
    digest: str,
    status: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """One tool call's structured log line as a dict.

    The keys are fixed: `ts`, `tool`, `sub`, `act`, `task_id`, `args_digest`,
    `status`. `sub` is the human the token is about, `act` is the agent client
    the realm configured, and `status` is `ok`, `error`, or `refused`.
    """
    moment = now or datetime.now(UTC)
    return {
        "ts": moment.isoformat().replace("+00:00", "Z"),
        "tool": tool,
        "sub": claims.sub if claims else None,
        "act": claims.act.sub if claims else None,
        "task_id": claims.task_id if claims else None,
        "args_digest": digest,
        "status": status,
    }


def configure_audit_logging(logger: logging.Logger) -> None:
    """Emit one logger's audit lines as bare JSON on their own stream handler.

    Left to the root logger they would pick up uvicorn's formatter and stop
    being one JSON object per line. Done here rather than at import so a test
    that imports a server module does not reconfigure logging.
    """
    if logger.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def log_audit(
    logger: logging.Logger,
    tool: str,
    claims: Claims | None,
    digest: str,
    status: str,
) -> None:
    """Write one audit line to `logger`."""
    logger.info(json.dumps(audit_record(tool, claims, digest, status), sort_keys=True))
