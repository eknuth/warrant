"""The data model for one authorization request and the decision it produced.

A request carries four things Warrant needs to answer one question: who asked
(`Chain.sub`), which agent is acting (`Chain.act`), what that agent has read so
far in this task (`Provenance`), and what this call would touch (`tool`,
`action_kind`, `resource`). Nothing here is sent by the agent except the tool
call itself. Provenance in particular is assembled by Warrant as it forwards
reads, which is what stops a hijacked agent from lying about it.

Every model is a pydantic model so a `Decision` serializes to one JSON line and
parses back with `Decision.model_validate_json`, which is how the decision log
and the grader read it without a model in the loop.
"""

from __future__ import annotations

from enum import StrEnum
from re import compile as re_compile

from pydantic import AwareDatetime, BaseModel, Field, computed_field, model_validator

# The characters a task id may keep when it becomes a directory name. The rule
# itself lives in `warrant.config.task_dir`, which this module cannot import:
# `config` imports this one. `tests/test_warrant_config.py` pins the two to each
# other, so a change there that is not made here fails rather than drifting.
_UNSAFE_TASK_ID = re_compile(r"[^A-Za-z0-9._-]")


class Tier(StrEnum):
    """How close a source's author is to the task's owner.

    The values are the ones Cedar policies see. The ranking is not the enum
    order: `owner` is most trusted, then `member`, then `customer`, then
    `external`, and `unknown` is least trusted because it means classification
    failed. `TRUST_ORDER` is the ranking; `Provenance.min_tier` depends on it.
    """

    owner = "owner"
    member = "member"
    external = "external"
    customer = "customer"
    unknown = "unknown"


# Most trusted first. The index into this tuple is the trust rank.
TRUST_ORDER: tuple[Tier, ...] = (
    Tier.owner,
    Tier.member,
    Tier.customer,
    Tier.external,
    Tier.unknown,
)


class ActionKind(StrEnum):
    """What a tool does to the resource it touches."""

    read = "read"
    write = "write"
    send = "send"


class Verdict(StrEnum):
    """The three answers Warrant can give."""

    allow = "allow"
    deny = "deny"
    escalate = "escalate"


class Chain(BaseModel):
    """The verified identity behind one task.

    `sub` is the human who asked, `act` is the agent acting for them, and the
    rest is what the token exchange proved at the start of the task. Building a
    `Chain` from a token is the exchange (W2); the `no-exchange` ablation builds
    one from headers the agent sends, which is the dishonest baseline.
    """

    sub: str
    act: str
    task_id: str
    scopes: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    token_exp: AwareDatetime

    @model_validator(mode="after")
    def _task_id_can_name_a_run(self) -> Chain:
        """A task id the run layout refuses is refused here, at the boundary.

        The task id becomes a directory name, and `task_dir` raises on a value
        that cannot name one. The gateway builds this from a token claim, so a
        token with `task_id: "."` used to raise out of the decision log long
        after the call was accepted: an unlogged crash instead of a refusal.
        Refusing the chain applies the same rule where the claim enters.

        An empty task id is not refused here. It cannot name a directory either,
        but it means "the token carried no task id", which is a different answer
        with a different refusal, and the gateway says so before it gets this
        far.
        """
        if self.task_id and set(_UNSAFE_TASK_ID.sub("_", self.task_id)) <= {"."}:
            raise ValueError(f"task id {self.task_id!r} cannot name a run directory")
        return self


class Source(BaseModel):
    """One thing an agent read in a task.

    `digest` is a hash of the content, not the content, so the ledger can show
    what was read without storing it.
    """

    system: str
    kind: str
    id: str
    author: str
    author_tier: Tier
    digest: str


class Provenance(BaseModel):
    """Every source read so far in one task.

    `min_tier` and `has_external` are computed from `sources`, so a caller
    cannot assert a trust level that the sources do not support.

    `has_external` covers both `external` and `unknown`, the two tiers below any
    classification. `unknown` means classification failed, and a commit with no
    forge account is exactly the case it describes, so a policy that forbids on
    external content has to see it too. Leaving `unknown` out let the least
    trusted tier in the model past a `hasExternal` forbid.

    With no sources, `min_tier` is `owner` and `has_external` is false, which
    reads as the most trusted state. That is vacuous, not earned: nothing has
    been read yet. A permit that depends on how much has been read has to check
    `context.provenance.count > 0` for itself, because the summary cannot tell
    "read nothing" from "read only the owner's own material".

    `task_taint` is W11's switch for the two taints. When it is false the
    sources stay in the record but `has_external` reports false, which is what
    `TAINT=content` asks for: the task did read something external, and the task
    rule is not allowed to see it. The content rule reads `overlapExternal` from
    the argument scan instead. The flag is a field and not a filtered source list
    so the decision log still carries every source the read recorded.
    """

    task_id: str
    sources: list[Source] = Field(default_factory=list)
    task_taint: bool = True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def min_tier(self) -> Tier:
        if not self.sources:
            return Tier.owner
        return max((source.author_tier for source in self.sources), key=TRUST_ORDER.index)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_external(self) -> bool:
        if not self.task_taint:
            return False
        return any(source.author_tier in (Tier.external, Tier.unknown) for source in self.sources)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_customer(self) -> bool:
        """True when any source's author is a customer.

        Customer material is not external, so `has_external` does not cover it.
        A policy that treats a customer's words as untrusted reads this beside
        `has_external`; the two are separate because a customer is known to the
        business while an external author is not.
        """
        return any(source.author_tier is Tier.customer for source in self.sources)


class AuthzRequest(BaseModel):
    """One proposed tool call, with everything needed to decide it.

    `tool` is a tool id from the access graph, `resource` a resource id. The
    provenance must belong to the same task as the chain; a mismatch is a caller
    bug, not a request to evaluate.

    The four taint and target fields at the end are computed by W11 from the
    call's arguments and the task's named target. They are on the request so the
    engine can put them in the Cedar context, and they default to the value that
    claims nothing: no overlapping sources, no external overlap, no secret in
    the args, and a write that stays on the task's target. A request built
    outside the gateway, which is what W7's policy tests do, sets them directly.
    A request the gateway decided carries what `warrant.taint.TaskState`
    computed for that call.
    """

    chain: Chain
    tool: str
    action_kind: ActionKind
    resource: str
    args_digest: str
    provenance: Provenance
    ts: AwareDatetime
    # W11: the ids the args overlap, and whether any of them is external-tier.
    overlap_sources: set[str] = Field(default_factory=set)
    overlap_external: bool = False
    # W11: a deterministic secret-shape scan of the write's arguments.
    args_touch_secret: bool = False
    # W11: the write leaves the target the task named.
    target_outside_task: bool = False
    # W11: one entry per overlap or secret hit, for the decision log. Each is
    # `{source_id, kind, sample}` where `kind` is `substring`, `identifier`,
    # `ngram`, or `secret`. A `sample` carries source text, so it is redacted of
    # every known secret value before it reaches the log, and a `secret` entry's
    # sample is the digest of the matched value rather than the value.
    overlap_details: list[dict[str, str]] = Field(default_factory=list)

    @model_validator(mode="after")
    def _provenance_belongs_to_the_task(self) -> AuthzRequest:
        if self.provenance.task_id != self.chain.task_id:
            raise ValueError(
                f"provenance is for task {self.provenance.task_id!r}, "
                f"chain is for task {self.chain.task_id!r}"
            )
        return self


class Decision(BaseModel):
    """The verdict for one request, with the policies that produced it.

    `request` is inlined, not referenced, so a decision line on its own carries
    the full chain and the full provenance set.

    `mode` names the ablation that produced the line. Without it an allow logged
    under `no-provenance` and an allow under `full` where the agent read nothing
    serialize the same, and the grader cannot attribute a line to an ablation
    from the record alone.
    """

    verdict: Verdict
    policy_ids: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    request: AuthzRequest
    mode: str = ""
