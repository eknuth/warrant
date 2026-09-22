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
substring, URL-encoded, or base64-encoded sets `argsTouchSecret`, matched without
regard to case.

The plain values live in this object and nowhere else. A secret is keyed on its
case-folded spelling and has one SHA-256 digest, over that spelling, so two
spellings of one value are one secret and a sample's digest is the same in every
process. The digest is what a decision line carries. A sample of source text
that contains a secret is redacted before it is recorded, without regard to
case, and a resource that is a secret is replaced with its digest before it
enters the request. A resource that is a key-shaped value is redacted and added
to the secret set, whether or not the task read it first, so the call that first
names a key keeps it out of the resource field and out of every later sample.
The one value that can still reach a line is a non-key-shaped value that a read's
own argument names before that read reveals it: at decision time the value is
not in the secret set and is not key-shaped. `docs/provenance.md` states that
limit.
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
from warrant.models import FORGE_SYSTEMS, ActionKind, AuthzRequest, Source, Tier
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

# A key-shaped value as a whole resource. Case-sensitive, so `nakia@acme.test`
# and `acme/akia-vault` are ordinary names rather than keys: a case-insensitive
# or unbounded match made any id carrying `akia` an unknown resource, which is
# fail-open for a confidential row. The left boundary keeps an embedded fragment
# from matching, and the tail floor is one character so `sk_live_abc` redacts.
_KEY_RESOURCE = re.compile(
    r"(?<![A-Za-z0-9_])(?:sk_live_[A-Za-z0-9_]+|ghp_[A-Za-z0-9_]+|AKIA[A-Z0-9_]+)"
)

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
    # Keyed on the case-folded value, so two spellings of one value are one
    # secret with one digest and a sample's digest does not depend on set order.
    # The plain values are in memory only; `secret_digests` is what a log may
    # carry, and it is over the folded spelling.
    secrets: set[str] = field(default_factory=set)
    secret_digests: dict[str, str] = field(default_factory=dict)
    named_targets: set[ResourceRef] = field(default_factory=set)
    # Whether a call has yet named the task's target. The first call that names a
    # resource names the target; a later call cannot move it.
    targets_named: bool = False

    # -- reading -----------------------------------------------------------

    def on_read(
        self,
        *,
        payload: Any,
        sources: Sequence[Source] = (),
        records: Sequence[tuple[Source, Any]] = (),
    ) -> None:
        """Record one forwarded read: its sources, its text, and its secrets.

        The text is the whole result, normalized, and every source from the call
        carries it. A result that holds an issue and its comments is one read,
        and the issue's words are what a later write would be quoting whichever
        block the words sat in.

        `records` is every source block occurrence paired with the record it sat
        in, repeats included, because a code search returns several matches in
        one file and each match's snippet can hold a key. The harvest reads the
        record's own text field, not the whole result: the result carries the
        provenance block, and a block whose id names `.env` is metadata rather
        than a value the file held. A caller that passes only `sources` gets the
        payload as each source's record, so the harvest is never silently empty.
        """
        raw = dump(payload)
        text = normalize(raw)
        for source in sources:
            self.sources[source.id] = ReadSource(source=source, text=text)
        harvest = list(records) or [(source, payload) for source in sources]
        self._harvest(payload, harvest)

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
        resource_kind: str = "",
        resource: str | None = None,
    ) -> dict[str, Any]:
        """The taint and target fields for one proposed call.

        A read gets no overlap and no secret match, because it sends nothing.
        The target comparison still runs, so a read that leaves the named target
        is visible in the log even though no shipped rule reads it for a read.

        The two scans see different strings. The overlap scan honors `exclude`,
        which names the argument value that is the call's own target: a write has
        to name the resource it touches, and a `repo` argument that repeats the
        repository the task is working on is not evidence that the write copied
        anything. The exclusion is compared after normalization, so
        `Acme/Widgets` is the same value as `acme/widgets`. The secret scan sees
        every argument string, excluded or not, because a secret in the value
        that names the resource is exactly the leak that scan exists to catch.

        `resource_kind` is the graph's kind for the call, and the target
        comparison is over the `(kind, name)` pair. `resource` is the resolved
        name before redaction; the comparison uses it so that a target named
        before a value was harvested as a secret still matches after. When
        `resource` is None the request's own resource is compared, which is what
        a caller building a request by hand gets.
        """
        excluded = {normalize(value) for value in exclude}
        all_strings = list(string_values(arguments))
        overlap_strings = [value for value in all_strings if normalize(value) not in excluded]
        scanned = request.action_kind in SCANNED_KINDS
        overlap_sources: set[str] = set()
        overlap_external = False
        details: list[dict[str, str]] = []

        if scanned and self.content_taint and overlap_strings:
            arguments_text = normalize(" ".join(overlap_strings))
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

        # Every string, including the value that named the resource.
        matched = self._secret_matches(all_strings) if scanned else []
        for secret in matched:
            details.append(
                {
                    "source_id": "",
                    "kind": "secret",
                    "sample": self.secret_digests[secret],
                }
            )

        target_name = request.resource if resource is None else resource
        return {
            "overlap_sources": overlap_sources,
            "overlap_external": overlap_external,
            "args_touch_secret": bool(matched),
            "target_outside_task": self.target_outside_task(resource_kind, target_name),
            "overlap_details": details,
        }

    def target_outside_task(self, kind: str, name: str) -> bool:
        """Whether a call's resolved resource leaves the target the task named.

        The comparison is over the `(kind, name)` pair. A name is unique within a
        kind, and the graph can hold a row of another kind with the same id, so a
        name-only comparison would read that other row as the task's target.

        With no named target the answer is false: a task that never named a
        subject has nothing for a call to be outside of. That is the permissive
        direction, and it is why the subject is taken from the first call that
        names a resource rather than being left unset.
        """
        if not self.named_targets:
            return False
        return (kind, name) not in {(ref.kind, ref.name) for ref in self.named_targets}

    # -- secrets -----------------------------------------------------------

    def redact(self, text: str) -> str:
        """Replace every known secret value in `text` with its digest.

        One pass over the original text, with a single alternation of every form
        longest first. Writing digests into the text and then re-scanning it
        would let a later secret match inside an already-written digest, and an
        auditor's hash of the value would not find the line.

        The match is case-insensitive and by substring, so a sample of source
        text, which is normalized to lower case, is redacted even when the
        secret's spelling was mixed. Redacting by substring can replace a value
        that appears inside an unrelated word or id; that over-redaction is the
        safe direction and `docs/provenance.md` says so.
        """
        forms: dict[str, str] = {}
        for secret in self.secrets:
            digest = self.secret_digests[secret]
            for form in secret_forms(secret):
                if form:
                    forms[form.casefold()] = digest
        if not forms:
            return text
        alternation = "|".join(re.escape(form) for form in sorted(forms, key=len, reverse=True))
        pattern = re.compile(alternation, re.IGNORECASE)
        return pattern.sub(lambda match: forms[match.group(0).casefold()], text)

    def redact_resource(self, value: str) -> str:
        """The digest for a resource value that is a secret, else the value.

        The equality is whole-value and case-insensitive. A resource id that
        merely contains a secret as a substring is left alone: redacting
        `repo-acme-widgets` because `acme-widgets` is a known secret would
        corrupt the id and move the task's named target.

        A key-shaped value is redacted whether or not it has been harvested, and
        it is added to the secret set with its digest, so the call that first
        names a key keeps it out of the resource field and out of every later
        sample. The key-shaped check is case-sensitive and anchored at a left
        boundary, so `nakia@acme.test` and `acme/akia-vault` stay ordinary
        names.

        The one ordering limit left is a non-key-shaped value that a read's own
        argument names before that read reveals it: at decision time the secret
        set does not hold it, so the value is not equal to a known secret and
        not key-shaped, and it reaches that one line. `docs/provenance.md` says
        so.
        """
        if not value:
            return value
        folded = value.casefold()
        for secret, digest in self.secret_digests.items():
            if secret == folded:
                return digest
        if _KEY_RESOURCE.search(value):
            self._add_secret(value)
            return self.secret_digests[value.casefold()]
        return value

    def _harvest(self, payload: Any, records: Sequence[tuple[Source, Any]]) -> None:
        """Collect secrets from the result's metadata and from every file record.

        The `secrets` list is read from the whole payload, wherever it sits. A
        file's own values are read from that file's text field, and every record
        is visited rather than one per source id, because a code search returns
        several matches in one file and each snippet can hold a key. The whole
        result also carries the provenance block, and a block whose id names a
        secret file (`acme/widgets:.env@main`) is metadata: scanning the whole
        result harvested that id and then every later write that mentioned it
        was a secret hit.
        """
        for value in values_under(payload, "secrets"):
            self._add_secret(value)
        for source, record in records:
            if not _is_file_source(source):
                continue
            text = file_text_of(record)
            if not text:
                continue
            for token in _KEY_SHAPED.findall(text):
                self._add_secret(token)
            if _SECRET_FILE.search(source_path(source)):
                for value in _ENV_ASSIGNMENT.findall(text):
                    self._add_secret(value, minimum=MIN_FILE_VALUE_LENGTH)

    def _add_secret(self, value: Any, *, minimum: int = 1) -> None:
        """Add one secret, keyed on its case-folded spelling.

        One digest per folded value, so two spellings of the same value are one
        secret and a sample's digest is the same in every process. The digest is
        over the folded spelling.
        """
        if not isinstance(value, str):
            return
        folded = value.strip().casefold()
        if len(folded) < minimum:
            return
        self.secrets.add(folded)
        self.secret_digests.setdefault(folded, secret_digest(folded))

    def _secret_matches(self, strings: Sequence[str]) -> list[str]:
        """The task's secrets that any argument string carries, in sorted order.

        The comparison is case-insensitive, and the encoded forms are computed
        from the folded value, so a body that carries the base64 of the folded
        spelling matches as well as the plain spelling.
        """
        folded = [text.casefold() for text in strings]
        matched: list[str] = []
        for secret in sorted(self.secrets):
            forms = [form.casefold() for form in secret_forms(secret) if form]
            if any(form in text for form in forms for text in folded):
                matched.append(secret)
        return matched


def secret_digest(value: str) -> str:
    """The SHA-256 digest a logged value is replaced with."""
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


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


def file_text_of(record: Any) -> str:
    """The file text in a gitea file record, or an empty string.

    `FileContent` carries the text in `content` and a `search_code` match carries
    its line in `snippet`. Every match's record is the match itself, so a search
    hit's snippet is harvested. The rest of the record and its provenance block
    are not scanned. A record with neither field, such as a `commit_file` result,
    contributes no text.
    """
    if not isinstance(record, Mapping):
        return ""
    for name in ("content", "snippet"):
        value = record.get(name)
        if isinstance(value, str):
            return value
    return ""


def source_path(source: Source) -> str:
    """The file path inside a forge source id, `<repo>:<path>@<ref>`."""
    if source.system not in FORGE_SYSTEMS:
        return ""
    _, _, rest = source.id.partition(":")
    path, separator, _ = rest.rpartition("@")
    return path if separator else rest
