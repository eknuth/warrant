"""Provenance taint: the deterministic context W11 adds to every call.

`TaskState` is one task's running memory of what it read. The gateway calls
`on_read` after each forwarded read with the sources Warrant recorded and the
result's payload, and it calls `context_for` before each decision with the
call's arguments. The four fields it produces are the ones the Cedar policies
read: `overlapSources`, `overlapExternal`, `argsTouchSecret`, and
`targetOutsideTask`.

There is no model and no data flow. The gateway sees the value a read returned
and the strings a write is about to send; it cannot see what the model did in
between. Anything the model paraphrased or restated in its own words is outside
what this module can observe, and `docs/provenance.md` says so.

Two taints, chosen by `TAINT`
------------------------------

Task taint is `Provenance.has_external`: the task read an external-tier source
at some point. It is computed from the ledger, not here, so that the sources a
decision reports are the sources the rule saw.

Content taint is the argument scan in this module. For a write or a send it
compares every argument string against the text of every source with the three
matchers in `warrant.overlap`. A hit names the source, and a hit on an
external-tier source sets `overlapExternal`.

Secrets
-------

The secret set is filled from three places: the `secrets` list a database result
carries (W8's metadata), the values in a file whose name says it holds secrets
(`*.env`, `secrets*`), and key-shaped tokens (`sk_live_`, `ghp_`, `AKIA`) found
in any file read. A write or send whose argument strings contain a secret as a
substring, URL-encoded, or base64-encoded sets `argsTouchSecret`.

The plain values live in this object and nowhere else. Every secret also has a
SHA-256 digest, and the digest is what goes into `overlapDetails` and therefore
into the decision log. A sample of source text that happens to contain a secret
is redacted before it is recorded, so no log line carries a value.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, quote_plus

from warrant.config import Taint, current_taint
from warrant.models import ActionKind, AuthzRequest, Source, Tier
from warrant.overlap import dump, find_hits, normalize

# The action kinds whose arguments are scanned. A read sends nothing, so there is
# nothing to leak and nothing to taint.
SCANNED_KINDS = (ActionKind.write, ActionKind.send)

# A value in a file that says it holds secrets. The assignment is read from the
# raw JSON of the result, so a JSON-escaped newline ends the value rather than
# swallowing the rest of the file.
_ENV_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*[=:]\s*\"?([^\s\"',\\]{8,})")

# A key-shaped token in a file read. The same shapes the acceptance criterion
# names, plus a length floor that keeps a bare prefix from being a secret.
_KEY_SHAPED = re.compile(r"(?:sk_live_|ghp_)[A-Za-z0-9_]{4,}|AKIA[A-Z0-9]{8,}")

# A file whose name says it holds secrets, matched against the path inside the
# source id. `secrets*` is a basename prefix; `.env` may be a name or a suffix.
_SECRET_FILE = re.compile(r"(^|/)\.env($|\.)|(^|/)secrets", re.IGNORECASE)

# The shortest value a file may contribute to the secret set. A shorter value is
# a word like `true` that would match half the writes in a run.
MIN_FILE_VALUE_LENGTH = 8


@dataclass(frozen=True)
class ResourceRef:
    """One resource the task's subject resolves to.

    `kind` is the graph's resource kind and `name` is the id the graph resolved
    the subject to. A name the graph has no row for is the name as given, so a
    subject that resolves to nothing still compares to the call that names it.
    """

    kind: str
    name: str


@dataclass
class ReadSource:
    """One recorded read: the source block and the normalized text it sat in."""

    source: Source
    text: str


@dataclass
class TaskState:
    """Everything one task has read, and what that taint means for one call.

    Per task, not per process: two tasks in flight share nothing, which is what
    keeps one task's external read out of another's decision. The gateway keys
    its registry by task and actor, the same pair the ledger uses, so an agent
    that names another agent's task id cannot fill that agent's taint.
    """

    task_id: str
    taint: Taint = field(default_factory=current_taint)
    sources: dict[str, ReadSource] = field(default_factory=dict)
    # The plain values, in memory only. `secret_digests` is what a log may carry.
    secrets: set[str] = field(default_factory=set)
    secret_digests: dict[str, str] = field(default_factory=dict)
    named_targets: set[ResourceRef] = field(default_factory=set)
    # Whether a call has yet named the task's target. The first call that names a
    # resource names the target; a later call cannot move it.
    targets_named: bool = False

    # -- reading -----------------------------------------------------------

    def on_read(self, *, payload: Any, sources: Sequence[Source] = ()) -> None:
        """Record one forwarded read: its sources, its text, and its secrets.

        The text is the whole result, normalized, and every source from the call
        carries it. A result that holds an issue and its comments is one read,
        and the issue's words are what a later write would be quoting whichever
        block the words sat in.
        """
        raw = dump(payload)
        text = normalize(raw)
        for source in sources:
            self.sources[source.id] = ReadSource(source=source, text=text)
        self._harvest(payload, sources, raw)

    def name_target(self, kind: str, name: str) -> None:
        """Name the task's target from the first call that resolves a resource."""
        if not name:
            return
        self.named_targets.add(ResourceRef(kind=kind, name=name))
        self.targets_named = True

    @property
    def content_taint(self) -> bool:
        """Whether the argument scan runs, from `TAINT`."""
        return self.taint in (Taint.content, Taint.both)

    # -- the context fields ------------------------------------------------

    def context_for(
        self,
        request: AuthzRequest,
        arguments: Mapping[str, Any],
        *,
        exclude: Iterable[str] = (),
    ) -> dict[str, Any]:
        """The taint and target fields for one proposed call.

        A read gets no overlap and no secret match, because it sends nothing.
        The target comparison still runs, so a read that leaves the named target
        is visible in the log even though no shipped rule reads it for a read.

        `exclude` names argument values that are the call's own target. A write
        has to name the resource it touches, so a `repo` argument that repeats
        the repository the task is working on is not evidence that the write
        copied anything: leaving it in made every comment on a repository
        identifier-overlap every issue read from it, which is the whole
        paraphrase miss turned back into a hit. The gateway passes the resource
        name it resolved.
        """
        excluded = set(exclude)
        strings = [value for value in string_values(arguments) if value not in excluded]
        scanned = request.action_kind in SCANNED_KINDS
        overlap_sources: set[str] = set()
        overlap_external = False
        details: list[dict[str, str]] = []

        if scanned and self.content_taint and strings:
            arguments_text = normalize(" ".join(strings))
            for read in self.sources.values():
                hits = find_hits(read.text, arguments_text)
                if not hits:
                    continue
                overlap_sources.add(read.source.id)
                if read.source.author_tier in (Tier.external, Tier.unknown):
                    overlap_external = True
                details.extend(
                    {
                        "source_id": read.source.id,
                        "kind": hit.kind,
                        "sample": self.redact(hit.sample),
                    }
                    for hit in hits
                )

        matched = self._secret_matches(strings) if scanned else []
        for secret in matched:
            details.append(
                {
                    "source_id": "",
                    "kind": "secret",
                    "sample": self.secret_digests[secret],
                }
            )

        return {
            "overlap_sources": overlap_sources,
            "overlap_external": overlap_external,
            "args_touch_secret": bool(matched),
            "target_outside_task": self.target_outside_task(request.resource),
            "overlap_details": details,
        }

    def target_outside_task(self, resource: str) -> bool:
        """Whether a call's resolved resource leaves the target the task named.

        With no named target the answer is false: a task that never named a
        subject has nothing for a call to be outside of. That is the permissive
        direction, and it is why the subject is taken from the first call that
        names a resource rather than being left unset.
        """
        if not self.named_targets:
            return False
        return resource not in {ref.name for ref in self.named_targets}

    # -- secrets -----------------------------------------------------------

    def redact(self, text: str) -> str:
        """Replace every known secret value in `text` with its digest.

        Longest value first, so a secret that contains a shorter one is replaced
        whole. The result is what a decision log may carry.
        """
        for secret in sorted(self.secrets, key=len, reverse=True):
            for form in secret_forms(secret):
                if form:
                    text = text.replace(form, self.secret_digests[secret])
        return text

    def _harvest(self, payload: Any, sources: Sequence[Source], raw: str) -> None:
        """Collect secrets from the result's metadata and from any file read."""
        for value in values_under(payload, "secrets"):
            self._add_secret(value)
        for source in sources:
            if not _is_file_source(source):
                continue
            for token in _KEY_SHAPED.findall(raw):
                self._add_secret(token)
            if _SECRET_FILE.search(source_path(source)):
                for value in _ENV_ASSIGNMENT.findall(raw):
                    self._add_secret(value, minimum=MIN_FILE_VALUE_LENGTH)

    def _add_secret(self, value: Any, *, minimum: int = 1) -> None:
        if not isinstance(value, str):
            return
        value = value.strip()
        if len(value) < minimum:
            return
        self.secrets.add(value)
        self.secret_digests.setdefault(
            value, "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
        )

    def _secret_matches(self, strings: Sequence[str]) -> list[str]:
        """The task's secrets that any argument string carries, in sorted order."""
        matched: list[str] = []
        for secret in sorted(self.secrets):
            forms = secret_forms(secret)
            if any(form and form in text for form in forms for text in strings):
                matched.append(secret)
        return matched


def secret_forms(secret: str) -> set[str]:
    """Every spelling of a secret the scan looks for.

    The value itself, its URL-encoded spellings, and its standard and URL-safe
    base64, with and without the `=` padding a body may have dropped.
    """
    standard = base64.b64encode(secret.encode("utf-8")).decode("ascii")
    urlsafe = base64.urlsafe_b64encode(secret.encode("utf-8")).decode("ascii")
    forms = {
        secret,
        quote(secret, safe=""),
        quote_plus(secret, safe=""),
        standard,
        urlsafe,
        standard.rstrip("="),
        urlsafe.rstrip("="),
    }
    forms.discard("")
    return forms


def string_values(value: Any) -> Iterable[str]:
    """Every string inside a JSON-shaped argument mapping.

    Keys are not values: a write cannot leak through the name of a field it
    sends. Numbers and booleans are not strings either, so an id does not become
    text to match.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from string_values(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from string_values(item)


def values_under(payload: Any, key: str) -> Iterable[Any]:
    """Every value stored under `key` anywhere in the payload.

    A result may nest the key (a ticket with notes, a search with rows), and the
    `secrets` list is the same metadata wherever it sits.
    """
    if isinstance(payload, Mapping):
        for name, value in payload.items():
            if name == key:
                yield from _flatten(value)
            else:
                yield from values_under(value, key)
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            yield from values_under(item, key)


def _flatten(value: Any) -> Iterable[Any]:
    if isinstance(value, (list, tuple, set)):
        yield from value
    else:
        yield value


def _is_file_source(source: Source) -> bool:
    """Whether a source is a file read, the only read a key-shaped token counts in."""
    return source.kind == "file"


def source_path(source: Source) -> str:
    """The file path inside a gitea source id, `<repo>:<path>@<ref>`."""
    if source.system != "gitea":
        return ""
    _, _, rest = source.id.partition(":")
    path, separator, _ = rest.rpartition("@")
    return path if separator else rest
