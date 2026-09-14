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

from pydantic import AwareDatetime, BaseModel, Field, computed_field, model_validator


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
    cannot assert a trust level that the sources do not support. `min_tier` is
    the least trusted tier present; with no sources it is `owner`, because
    nothing untrusted has been read yet.
    """

    task_id: str
    sources: list[Source] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def min_tier(self) -> Tier:
        if not self.sources:
            return Tier.owner
        return max((source.author_tier for source in self.sources), key=TRUST_ORDER.index)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_external(self) -> bool:
        return any(source.author_tier is Tier.external for source in self.sources)


class AuthzRequest(BaseModel):
    """One proposed tool call, with everything needed to decide it.

    `tool` is a tool id from the access graph, `resource` a resource id. The
    provenance must belong to the same task as the chain; a mismatch is a caller
    bug, not a request to evaluate.
    """

    chain: Chain
    tool: str
    action_kind: ActionKind
    resource: str
    args_digest: str
    provenance: Provenance
    ts: AwareDatetime

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
    """

    verdict: Verdict
    policy_ids: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    request: AuthzRequest
