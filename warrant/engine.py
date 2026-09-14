"""The policy engine adapter, with Cedar behind it.

`PolicyEngine` is the whole surface callers see: `decide(req) -> Decision` and
`explain(req) -> str`. `CedarEngine` implements it with cedarpy. Nothing outside
this module imports cedarpy, so OPA or a second engine can replace it without
touching the request path.

Mapping
-------

A request becomes a Cedar request like this:

* principal: `Agent::"<chain.act>"`, the acting agent. Its entity carries
  `owner` (the graph's owner for the agent, or the human who asked when the
  graph has no row), `onBehalfOf` (always `chain.sub`), `clientId`,
  `allowedTools`, and `justification`.
* action: `Action::"<action_kind>"`, one of `read`, `write`, or `send`. The
  tool id travels in `context.tool`, because a Cedar action scope is always an
  `Action` and the schema can declare three kinds but not every tool.
* resource: `Resource::"<request.resource>"`, with `kind`, `name`, `owner`, and
  `sensitivity` taken from the graph. A resource the graph does not know is
  presented as `kind` and `sensitivity` `"unknown"`, which no permit should
  match.
* context: the provenance summary (`minTier`, `hasExternal`, `systems`,
  `count`), the task id, the token scopes, the human's groups, the action kind,
  the args digest, `justificationValid`, and `tokenExp`.

Escalate
--------

Cedar has no third verdict, so escalation is two passes over the same policy
set:

1. Evaluate the real action. If it is allowed, return `allow` and stop. The
   escalation pass is not consulted.
2. If and only if the real action is *denied* by policies, evaluate the
   synthetic action `Action::"Escalate"` with the same principal, resource, and
   context. If that is allowed, the verdict is `escalate` and `policy_ids` names
   the escalate permit. Otherwise the verdict is `deny` and `policy_ids` names
   what denied the real action.

The ticket writes the synthetic action as `Escalate::"<tool>"`. Cedar's action
scope has to be an entity of type `Action`, so the literal form will not parse.
The shape here is `Action::"Escalate"` with the tool in `context.tool`; a
per-tool escalate permit reads

    @id("escalate-search")
    permit(principal, action == Action::"Escalate", resource)
    when { context.tool == "gitea.search" };

and keeps the whole policy set inside one schema. A `forbid` that is not scoped
to the real action also forbids `Action::"Escalate"`, which is Cedar's rule that
a forbid beats every permit; an escalate permit only lifts an implicit deny or a
deny scoped to the real action.

A request that Cedar cannot evaluate at all (no decision, an error) is a deny
with the error in `reasons`. It does not fall through to the escalation pass,
because escalation is the answer to a deny, not to a broken request.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import cedarpy

from warrant import config
from warrant.config import PROMPT_ONLY_POLICY_ID, Mode
from warrant.graph import Graph
from warrant.log import DecisionLog
from warrant.models import AuthzRequest, Decision, Verdict

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICIES_DIR = PACKAGE_ROOT / "policies"
DEFAULT_SCHEMA_PATH = DEFAULT_POLICIES_DIR / "schema.cedarschema.json"

# The synthetic action the second pass evaluates. See the module docstring.
ESCALATE_ACTION = "Escalate"

# Cedar entity types. The schema uses the empty namespace, so these are bare.
AGENT = "Agent"
HUMAN = "Human"
RESOURCE = "Resource"
ACTION = "Action"


class PolicyEngine(Protocol):
    """What a caller needs from an engine, and nothing else."""

    def decide(self, req: AuthzRequest) -> Decision: ...

    def explain(self, req: AuthzRequest) -> str: ...


@dataclass
class _Outcome:
    """One cedarpy call, reduced to what a `Decision` needs."""

    decision: cedarpy.Decision
    policy_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _entity_ref(entity_type: str, entity_id: str) -> dict[str, Any]:
    return {"__entity": {"type": entity_type, "id": entity_id}}


class CedarEngine:
    """A `PolicyEngine` that evaluates `policies/*.cedar` with cedarpy."""

    def __init__(
        self,
        policies_dir: Path | str = DEFAULT_POLICIES_DIR,
        schema_path: Path | str | None = DEFAULT_SCHEMA_PATH,
        graph: Graph | None = None,
        mode: Mode | None = None,
        decision_log: DecisionLog | None = None,
    ) -> None:
        self.policies_dir = Path(policies_dir)
        if not self.policies_dir.is_dir():
            raise FileNotFoundError(f"policies directory not found: {self.policies_dir}")
        self.policy_files = sorted(self.policies_dir.glob("*.cedar"))
        text = "\n\n".join(path.read_text(encoding="utf-8") for path in self.policy_files)
        # cedarpy takes a string or a PolicySet, never a list. Parsing once here
        # is also what keeps a bad policy set from failing per request.
        self._policies: str | cedarpy.PolicySet = (
            cedarpy.PolicySet.from_str(text) if text.strip() else ""
        )

        self.schema_path = Path(schema_path) if schema_path is not None else None
        self._schema = (
            cedarpy.Schema.from_json_str(self.schema_path.read_text(encoding="utf-8"))
            if self.schema_path is not None
            else None
        )

        self.graph = graph
        self._mode = mode if mode is not None else config.current_mode()
        self._log = decision_log if decision_log is not None else DecisionLog()

    # The two methods a caller gets.

    def decide(self, req: AuthzRequest) -> Decision:
        """Evaluate the request and append the decision to the log."""
        decision = self._evaluate(req)
        self._log.append(decision)
        return decision

    def explain(self, req: AuthzRequest) -> str:
        """Render why the verdict came out the way it did, without logging."""
        decision = self._evaluate(req)
        provenance = req.provenance
        systems = sorted({source.system for source in provenance.sources})
        lines = [
            f"mode: {self._mode.value}",
            f"policies: {len(self.policy_files)} file(s) under {self.policies_dir}",
            (
                f"chain: sub={req.chain.sub} act={req.chain.act} task={req.chain.task_id} "
                f"scopes={req.chain.scopes} groups={req.chain.groups} "
                f"token_exp={req.chain.token_exp.isoformat()}"
            ),
            (
                f"call: tool={req.tool} action={req.action_kind.value} "
                f"resource={req.resource} args_digest={req.args_digest} at={req.ts.isoformat()}"
            ),
            (
                f"provenance: sources={len(provenance.sources)} "
                f"min_tier={provenance.min_tier.value} "
                f"has_external={str(provenance.has_external).lower()} systems={systems}"
            ),
            f"verdict: {decision.verdict.value}",
            f"policy_ids: {decision.policy_ids}",
            "reasons:",
        ]
        lines.extend(f"  - {reason}" for reason in decision.reasons)
        return "\n".join(lines)

    # Evaluation.

    def _evaluate(self, req: AuthzRequest) -> Decision:
        if self._mode is Mode.prompt_only:
            return Decision(
                verdict=Verdict.allow,
                policy_ids=[PROMPT_ONLY_POLICY_ID],
                reasons=["prompt-only ablation: no policy was evaluated"],
                request=req,
            )

        real = self._ask(req, req.action_kind.value)
        if real.decision is cedarpy.Decision.Allow:
            return Decision(
                verdict=Verdict.allow,
                policy_ids=real.policy_ids,
                reasons=_matched("permit", real),
                request=req,
            )
        if real.decision is not cedarpy.Decision.Deny:
            # NoDecision: the request could not be evaluated. Fail closed and do
            # not escalate, because escalation answers a deny, not an error.
            return Decision(
                verdict=Verdict.deny,
                policy_ids=[],
                reasons=["request could not be evaluated", *real.errors],
                request=req,
            )

        escalate = self._ask(req, ESCALATE_ACTION)
        if escalate.decision is cedarpy.Decision.Allow:
            reasons = [f"real action denied: {req.action_kind.value}"]
            reasons.extend(_matched("escalate permit", escalate))
            return Decision(
                verdict=Verdict.escalate,
                policy_ids=escalate.policy_ids,
                reasons=reasons,
                request=req,
            )
        return Decision(
            verdict=Verdict.deny,
            policy_ids=real.policy_ids,
            reasons=_denied(real),
            request=req,
        )

    def _ask(self, req: AuthzRequest, action_id: str) -> _Outcome:
        cedar_request = {
            "principal": {"type": AGENT, "id": req.chain.act},
            "action": {"type": ACTION, "id": action_id},
            "resource": {"type": RESOURCE, "id": req.resource},
            "context": self._context(req),
        }
        result = cedarpy.is_authorized(
            cedar_request, self._policies, self._entities(req), self._schema
        )
        annotations = dict(result.diagnostics.id_annotations_by_reason)
        policy_ids = [annotations.get(reason, reason) for reason in result.diagnostics.reasons]
        return _Outcome(
            decision=result.decision,
            policy_ids=policy_ids,
            errors=list(result.diagnostics.errors),
        )

    def _context(self, req: AuthzRequest) -> dict[str, Any]:
        provenance = req.provenance
        return {
            "tool": req.tool,
            "actionKind": req.action_kind.value,
            "argsDigest": req.args_digest,
            "taskId": req.chain.task_id,
            "scopes": list(req.chain.scopes),
            "groups": list(req.chain.groups),
            "justificationValid": self._justification_valid(req),
            "tokenExp": int(req.chain.token_exp.timestamp()),
            "provenance": {
                "minTier": provenance.min_tier.value,
                "hasExternal": provenance.has_external,
                "systems": sorted({source.system for source in provenance.sources}),
                "count": len(provenance.sources),
            },
        }

    def _justification_valid(self, req: AuthzRequest) -> bool:
        """True when the acting agent has a live justification on file.

        With no graph, or no row for the agent, there is nothing on file, so the
        answer is false. That is the deny-safe direction.
        """
        if self.graph is None:
            return False
        agent = self.graph.agent(req.chain.act)
        if agent is None or not agent.justification:
            return False
        expires = agent.justification_expires_at
        return expires is None or expires > req.ts

    def _entities(self, req: AuthzRequest) -> list[dict[str, Any]]:
        entities: dict[tuple[str, str], dict[str, Any]] = {}

        def add(entity_type: str, entity_id: str, attrs: dict[str, Any]) -> None:
            entities[(entity_type, entity_id)] = {
                "uid": {"type": entity_type, "id": entity_id},
                "attrs": attrs,
                "parents": [],
            }

        agent_row = self.graph.agent(req.chain.act) if self.graph is not None else None
        owner_id = (
            agent_row.owner_human_id
            if agent_row is not None and agent_row.owner_human_id
            else req.chain.sub
        )

        self._add_human(entities, add, req.chain.sub, fallback_groups=req.chain.groups)
        if owner_id != req.chain.sub:
            self._add_human(entities, add, owner_id)

        add(
            AGENT,
            req.chain.act,
            {
                "clientId": agent_row.client_id if agent_row is not None else req.chain.act,
                "owner": _entity_ref(HUMAN, owner_id),
                "onBehalfOf": _entity_ref(HUMAN, req.chain.sub),
                "allowedTools": list(agent_row.allowed_tools) if agent_row is not None else [],
                "justification": agent_row.justification if agent_row is not None else "",
            },
        )

        resource_row = self.graph.resource(req.resource) if self.graph is not None else None
        if resource_row is not None:
            self._add_human(entities, add, resource_row.owner_human_id)
            add(
                RESOURCE,
                req.resource,
                {
                    "kind": resource_row.kind,
                    "name": resource_row.name,
                    "owner": _entity_ref(HUMAN, resource_row.owner_human_id),
                    "sensitivity": resource_row.sensitivity,
                },
            )
        else:
            add(
                RESOURCE,
                req.resource,
                {
                    "kind": "unknown",
                    "name": req.resource,
                    "owner": _entity_ref(HUMAN, req.chain.sub),
                    "sensitivity": "unknown",
                },
            )
        return list(entities.values())

    def _add_human(
        self,
        entities: dict[tuple[str, str], dict[str, Any]],
        add: Any,
        human_id: str,
        fallback_groups: list[str] | None = None,
    ) -> None:
        if (HUMAN, human_id) in entities:
            return
        row = self.graph.human(human_id) if self.graph is not None else None
        if row is not None:
            add(HUMAN, human_id, {"login": row.login, "groups": list(row.groups)})
        else:
            add(
                HUMAN,
                human_id,
                {"login": human_id, "groups": list(fallback_groups or [])},
            )


def _matched(verb: str, outcome: _Outcome) -> list[str]:
    if outcome.policy_ids:
        return [f"{verb} matched: {policy_id}" for policy_id in outcome.policy_ids]
    return [f"{verb} path reached with no policy id reported"]


def _denied(outcome: _Outcome) -> list[str]:
    if outcome.policy_ids:
        return [f"forbid matched: {policy_id}" for policy_id in outcome.policy_ids]
    reasons = ["no permit matched (Cedar default deny)"]
    reasons.extend(outcome.errors)
    return reasons
