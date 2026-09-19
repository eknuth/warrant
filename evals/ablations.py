"""The eval ablations, each a named configuration the runner switches on.

An ablation is not a change to the scenarios. It is a change to the running
Warrant process and, for `prompt-only`, to the agent's system prompt. The runner
restarts the gateway into one of these before a cell and reads the mode back
from `/healthz`.

`WARRANT_MODE` picks the request path and `TAINT` picks which provenance rule
W11 (and W24) computes; `docs/provenance.md` and
`docs/decisions/w15-eval-runner.md` hold the reasoning. W24 adds `jev`, the
typed classifier in place of the two deterministic taints, and `jev-only`, the
whole decision made by one Jev choice with no Cedar at all. The names are the
ones the issue and the report use, and the directory a cell writes is named from
them.
"""

from __future__ import annotations

from dataclasses import dataclass

from warrant.config import Mode, Taint

# `full` sorts first everywhere it appears. The rest follow the order the issue
# lists them, which is the order a person reads the tradeoff in. W24's `jev`
# sits beside the two deterministic taints; `jev-only` sits at the end, after
# the policy-free floor it is the sibling of.
FULL = "full"
ORDER = (
    FULL,
    "task-taint",
    "content-taint",
    "jev",
    "no-provenance",
    "no-exchange",
    "prompt-only",
    "jev-only",
)


@dataclass(frozen=True)
class Ablation:
    """One named configuration the runner can switch the stack into.

    `mode` and `taint` are the `WARRANT_MODE` and `TAINT` values the gateway
    process imports. `hardened_prompt` selects `agents/prompts/<kind>.hardened.md`
    instead of the shipped role prompt, which is the whole of `prompt-only`'s
    agent-side change.
    """

    name: str
    mode: str
    taint: str
    hardened_prompt: bool = False
    description: str = ""


ABLATIONS: dict[str, Ablation] = {
    "full": Ablation(
        name="full",
        mode=Mode.full.value,
        taint=Taint.both.value,
        description="everything on: the verified chain and both provenance taints",
    ),
    "task-taint": Ablation(
        name="task-taint",
        mode=Mode.full.value,
        taint=Taint.task.value,
        description="provenance is only whether the task read anything external",
    ),
    "content-taint": Ablation(
        name="content-taint",
        mode=Mode.full.value,
        taint=Taint.content.value,
        description="provenance is only string overlap between a read and a write",
    ),
    "jev": Ablation(
        name="jev",
        mode=Mode.full.value,
        taint=Taint.jev.value,
        description=("provenance is only the Jev classifier's per-write derived boolean"),
    ),
    "no-provenance": Ablation(
        name="no-provenance",
        mode=Mode.no_provenance.value,
        taint=Taint.both.value,
        description="the ledger returns empty; only the chain and the scopes remain",
    ),
    "no-exchange": Ablation(
        name="no-exchange",
        mode=Mode.no_exchange.value,
        taint=Taint.both.value,
        description="self-reported sub and act headers instead of a verified token",
    ),
    "prompt-only": Ablation(
        name="prompt-only",
        mode=Mode.prompt_only.value,
        taint=Taint.both.value,
        hardened_prompt=True,
        description="every decision allow; the agent runs the hardened prompt",
    ),
    "jev-only": Ablation(
        name="jev-only",
        mode=Mode.jev_only.value,
        taint=Taint.both.value,
        description="Cedar never runs; one Jev choice decides allow, deny, or escalate",
    ),
}

# The names in the order a report and the CLI list them.
ABLATION_NAMES: tuple[str, ...] = ORDER


class AblationError(ValueError):
    """An ablation name the runner does not know."""


def parse_ablations(value: str | None) -> list[Ablation]:
    """The ablations one `--ablations` value names, in `ORDER`.

    `all` or an empty value is every ablation. A comma-separated list is those
    names, each checked, in the order given by `ORDER` rather than the order the
    caller typed them, so two invocations with the same set run the same cells.
    """
    if value is None or value.strip() in ("", "all"):
        return [ABLATIONS[name] for name in ABLATION_NAMES]
    requested = {part.strip() for part in value.split(",") if part.strip()}
    unknown = sorted(requested - set(ABLATIONS))
    if unknown:
        raise AblationError(f"unknown ablation(s) {unknown}; known: {', '.join(ABLATION_NAMES)}")
    return [ABLATIONS[name] for name in ABLATION_NAMES if name in requested]
