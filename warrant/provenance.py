"""The provenance ledger: what one actor has read in one task.

Warrant records a `Source` as it forwards each read, keyed by the task id *and*
the actor. The in-memory dict answers the next request; the JSONL file under
`runs/<task_id>/provenance/<actor>.jsonl` is the evidence a crash leaves behind,
and `get` replays it when the process that recorded it is gone.

The actor is part of the key because the task id is not. `scope=task-id:<value>`
is written by the caller of the token exchange, so an agent chooses its own task
id; keying the ledger on the id alone let one agent name another task's id and
inherit its sources, and let one agent's reads append to another task's file.
Binding the file to the actor closes both directions without needing the task id
to be trustworthy: a task id that was never this actor's reads as empty, and
every actor's evidence stays on disk under its own name.

In the `no-provenance` ablation nothing is recorded and `get` returns an empty
set, which is how W15 measures what the provenance checks are worth.
"""

from __future__ import annotations

import re
from pathlib import Path

from warrant import config
from warrant.config import RUNS_DIR, Mode, task_dir
from warrant.models import Provenance, Source, Tier

LEDGER_NAME = "provenance.jsonl"
LEDGER_DIR = "provenance"

# The member domain the mail server treats as inside the business. The classifier
# repeats it rather than importing the server so a mail source is graded the same
# way whichever resource server produced it.
MEMBER_DOMAIN = "acme.test"

# Gitea file paths that carry instructions an agent may follow: the forge's own
# workflow files, the two agent instruction files, and any rules file. A read of
# one of these is the prompt-injection surface, so its tier is external unless
# the last commit author is a member of the organization.
_INSTRUCTION_PATH = re.compile(
    r"(^|/)(\.github/|\.cursor/)|(^|/)(agents|claude)\.md$|\.rules$",
    re.IGNORECASE,
)

# The source kind a raw SQL read carries. `run_readonly_sql` has no author, and
# the statement's digest is the only identity it has.
QUERY_KIND = "query"


def classify(source: Source) -> Tier:
    """The tier Warrant records for one read, from the upstream block plus overrides.

    The upstream `author_tier` is the starting point: the forge knows whether a
    commit author is an org member, the mail server knows whether a sender is
    inside the domain, and the database knows whether a ticket came from a
    customer. Three overrides correct the cases the upstream cannot see the
    meaning of.

    A raw SQL read is `unknown`. The statement's only identity is a digest and
    the rows have no single author, so a tier would be a claim no source
    supports. `run_readonly_sql` can return a key table, and the least trusted
    tier is the honest answer for it.

    A mail source whose author is not in the member domain is `external`. The
    upstream grades this too; repeating it here means the rule holds even if a
    sender tier is added upstream, and it makes `mail.list_inbox`'s outside
    sender explicit at the one place the tiers are decided.

    A Gitea file read whose path is an instruction file is `external` when the
    last commit author is not a member or an owner. A commit with no resolvable
    forge account is `unknown`, which is not a member either, so an
    unaccountable `.github/` or `AGENTS.md` edit is treated the same as one from
    outside the org. A member's or owner's own instruction file keeps the
    upstream tier, which is what makes the same path committed by a member
    classify as `member`.
    """
    if source.system == "db" and source.kind == QUERY_KIND:
        return Tier.unknown
    if source.system == "mail" and not _is_member_address(source.author):
        return Tier.external
    if _is_instruction_file(source) and source.author_tier not in (Tier.member, Tier.owner):
        return Tier.external
    return source.author_tier


def _is_member_address(address: str) -> bool:
    """Whether a mail author is inside the business.

    The check is on the whole domain, so `notacme.test` and `acme.test.evil` are
    outside it, the same rule the mail server applies to a sender.
    """
    return address.lower().endswith("@" + MEMBER_DOMAIN)


def _is_instruction_file(source: Source) -> bool:
    """Whether a gitea read is one of the paths an agent takes instructions from."""
    if source.system != "gitea" or source.kind != "file":
        return False
    return bool(_INSTRUCTION_PATH.search(_gitea_path(source.id)))


def _gitea_path(source_id: str) -> str:
    """The file path inside a gitea source id, `<repo>:<path>@<ref>`.

    A search-code match names the same shape, so a path from either read is
    graded the same way.
    """
    _, _, rest = source_id.partition(":")
    path, separator, _ = rest.rpartition("@")
    return path if separator else rest


def ledger_dir(root: Path | str, task_id: str) -> Path:
    """The directory holding one task's per-actor ledger files."""
    return task_dir(root, task_id) / LEDGER_DIR


def ledger_path(root: Path | str, task_id: str, actor: str) -> Path:
    """The JSONL file holding one actor's sources in one task.

    `actor` is a client id from a verified token, but it still names a file, so
    it is sanitized on the way. The digest the sanitizer appends keeps two
    different actors from sharing a file.
    """
    return ledger_dir(root, task_id) / f"{task_dir('.', actor).name}.jsonl"


class Ledger:
    """Sources by task and actor, in memory and on disk."""

    def __init__(self, root: Path | str = RUNS_DIR, mode: Mode | None = None) -> None:
        self.root = Path(root)
        # `Mode(...)` rather than the value as given: a bare string that happens
        # to match would compare unequal against `is`, silently disabling the
        # ablation and corrupting the measurement.
        self._mode = Mode(mode) if mode is not None else config.current_mode()
        self._sources: dict[tuple[str, str], list[Source]] = {}

    def record(self, task_id: str, actor: str, source: Source) -> None:
        """Record one read. A no-op under `no-provenance`."""
        if self._mode is Mode.no_provenance:
            return
        self._sources.setdefault((task_id, actor), []).append(source)
        path = ledger_path(self.root, task_id, actor)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(source.model_dump_json() + "\n")

    def get(self, task_id: str, actor: str) -> Provenance:
        """Every source this actor read in this task, memory first, then the file."""
        if self._mode is Mode.no_provenance:
            return Provenance(task_id=task_id)
        key = (task_id, actor)
        sources = self._sources.get(key)
        if sources is None:
            sources = self._read(task_id, actor)
            self._sources[key] = sources
        return Provenance(task_id=task_id, sources=list(sources))

    def _read(self, task_id: str, actor: str) -> list[Source]:
        path = ledger_path(self.root, task_id, actor)
        if not path.exists():
            return []
        return [
            Source.model_validate_json(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
