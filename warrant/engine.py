"""The policy engine adapter, with Cedar behind it.

`PolicyEngine` is the whole surface callers see: `evaluate(req) -> Decision` for
a decision without a log line, `decide(req) -> Decision` for one that is logged,
and `explain(req) -> str`. `CedarEngine` implements it with cedarpy. Nothing
outside this module imports cedarpy, so OPA or a second engine can replace it
without touching the request path.

`evaluate` is what the gateway calls: an escalated call has to reach the
adjudicator before its line is written, so the line can carry the verdict the
adjudicator answered with. `decide` is `evaluate` plus the append, which is what
the policy tests and the CLI use.

Mapping
-------

A request becomes a Cedar request like this:

* principal: `Agent::"<chain.act>"`, the acting agent. Its entity carries
  `owner` (the graph's owner for the agent, or `warrant:unknown` when the graph
  has no row), `onBehalfOf` (always `chain.sub`), `clientId`, `allowedTools`,
  and `justification`.
* action: `Action::"<tool>"`, the tool the call names, with the action kind as
  its membership: every tool action is a member of `Action::"read"`,
  `Action::"write"`, or `Action::"send"` according to the graph's `tools` row,
  so a rule about a kind reads `action in Action::"write"` and a rule about one
  tool reads `action == Action::"gitea.create_issue_comment"`. The schema is
  generated from the graph, so it declares every tool action. `context.actionKind`
  still carries the kind for the log and for a policy that wants it as data.
* resource: `Resource::"<request.resource>"`, with `kind`, `name`, `owner`, and
  `sensitivity` taken from the graph. A resource the graph does not know is
  presented as `kind` and `sensitivity` `"unknown"`, which no permit should
  match.
* context: the provenance summary (`minTier`, `hasExternal`, `hasCustomer`,
  `systems`, `sourceIds`, `overlapSources`, `overlapExternal`, `count`), the
  task id, the token scopes as `taskScopes`, the token's `incident_id` claim as
  `incidentId`, the human's groups, the human in `sub` as `onBehalfOf`, the
  action kind, the args digest, `justificationValid`, `tokenExp`,
  `argsTouchSecret`, and `targetOutsideTask`.

A human entity carries `entitledTools`, the union of `allowedTools` over the
agents that human owns. The OBO token's scopes name the agent client's
authority, not the human's, so a permit that narrows the token to the person
who asked reads `context.onBehalfOf.entitledTools` rather than `taskScopes`
alone. The agent's owner is the wrong human for that check: an agent owned by
one person and invoked by another must not carry the owner's entitlements.

Escalate
--------

Cedar has no third verdict, so escalation is two passes over the same policy
set:

1. Evaluate the real action, `Action::"<tool>"`. If it is allowed, return
   `allow` and stop. The escalation pass is not consulted.
2. If and only if the real action is *denied* by policies, evaluate the
   synthetic action `Action::"escalate"` with the same principal, resource, and
   context. If that is allowed, the verdict is `escalate` and `policy_ids` names
   the escalate permit. Otherwise the verdict is `deny` and `policy_ids` names
   what denied the real action.

The escalate action is the one place the tool stays in `context.tool`. The real
action already names the tool, so an escalate permit that needs to know which
tool was denied reads it as data; a per-tool escalate permit reads

    @id("escalate-search")
    permit(principal, action == Action::"escalate", resource)
    when { context.tool == "gitea.search_code" };

A `forbid` that is not scoped to the real action also forbids
`Action::"escalate"`, which is Cedar's rule that a forbid beats every permit; an
escalate permit only lifts an implicit deny or a deny scoped to the real action.

A request that Cedar cannot evaluate at all (no decision, an error) is a deny
with the error in `reasons`. It does not fall through to the escalation pass,
because escalation is the answer to a deny, not to a broken request.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

import cedarpy

from warrant import config
from warrant.config import PROMPT_ONLY_POLICY_ID, Mode
from warrant.graph import Graph, live_justification
from warrant.log import DecisionLog
from warrant.models import ActionKind, AuthzRequest, Decision, Verdict

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICIES_DIR = PACKAGE_ROOT / "policies"
DEFAULT_SCHEMA_PATH = DEFAULT_POLICIES_DIR / "schema.cedarschema.json"

# The synthetic action the second pass evaluates. See the module docstring.
ESCALATE_ACTION = "escalate"

# W24. The engine-level rule the Jev provenance field drives, and the policy id
# the `jev-only` engine stamps on its verdict. Neither is a Cedar policy: the
# derived field is a classifier's answer fed to a deterministic rule, and the
# `jev-only` engine has no policy set at all.
DERIVED_POLICY_ID = "derived-write"
JEV_ONLY_POLICY_PREFIX = "jev-only:"

# W27. The policy id the cascade overlay stamps when a Jev answer subtracts a
# Cedar allow. It is separate from `DERIVED_POLICY_ID` so a decision line says
# which arrangement refused the write: the engine rule the `jev` column runs, or
# the post-allow overlay the `cascade` column runs.
CASCADE_OVERLAY_POLICY_ID = "overlay:derived-write"

# The action kinds, which are also the membership groups the tool actions
# belong to. A rule about a kind reads `action in Action::"write"`.
ACTION_KINDS = ("read", "write", "send")

# Cedar entity types. The schema uses the empty namespace, so these are bare.
AGENT = "Agent"
HUMAN = "Human"
RESOURCE = "Resource"
ACTION = "Action"

# The owner given to an agent or resource the graph cannot vouch for. It is a
# sentinel rather than the requester, so an ownership permit cannot match an
# entity nobody owns. It is deliberately not a valid login.
UNKNOWN_HUMAN = "warrant:unknown"


class PolicyEngine(Protocol):
    """What a caller needs from an engine, and nothing else."""

    def evaluate(self, req: AuthzRequest) -> Decision: ...

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


# The action ids the generated schema writes itself: the three kinds, which are
# also the membership groups, and the escalate action. A tool may not take one of
# these names, because the generated action would overwrite the group or the
# escalate action and the policy that reads `action in Action::"write"` would no
# longer mean "a write tool".
RESERVED_ACTION_IDS = (*ACTION_KINDS, ESCALATE_ACTION)


class ReservedActionIdError(ValueError):
    """A tool id that collides with an action the schema writes itself."""


class PolicyValidationError(ValueError):
    """A policy set that does not validate against the schema it is loaded with.

    A policy that names an action the schema does not declare parses fine and
    then never matches, which is the failure mode W6 spent an issue undoing. The
    check belongs at load, where the policy file is in front of the author, not
    at a decision, where the only evidence is a missing permit.
    """


def schema_for(graph: Graph) -> dict[str, Any]:
    """The Cedar schema for the tools this graph holds.

    Every tool in the graph becomes an action, and each tool action is a member
    of its kind, so a rule can be about one tool (`action ==
    Action::"gitea.create_issue_comment"`) or about a kind (`action in
    Action::"write"`). Generating it rather than hand-writing it is what lets a
    policy name a tool: a static file would need an edit for every tool W8, W9,
    and W21 add, and a missing entry is not a policy error, it is a schema
    validation failure at load.

    A tool id that is one of `RESERVED_ACTION_IDS` is refused here rather than
    written. Cedar makes `Action::"read"` a member of itself a cycle and refuses
    to build the schema at all; a collision with another kind or with `escalate`
    is worse, because the schema builds and the group quietly stops meaning what
    a policy reads it to mean. Both are findings at load, where they can be
    fixed, rather than at a decision.

    The kind actions themselves carry the same `appliesTo` as the tools, so a
    rule scoped to a kind validates. `Action::"escalate"` is the second pass's
    action and is the one action whose tool is data rather than the action id.
    """
    applies_to = {
        "principalTypes": [AGENT],
        "resourceTypes": [RESOURCE],
        "context": {"type": "RequestContext"},
    }
    actions: dict[str, Any] = {kind: {"appliesTo": applies_to} for kind in ACTION_KINDS}
    for tool in graph.tools():
        if tool.id in RESERVED_ACTION_IDS:
            raise ReservedActionIdError(
                f"tool id {tool.id!r} is a reserved action name "
                f"({', '.join(RESERVED_ACTION_IDS)}); rename the tool in the graph seed"
            )
        actions[tool.id] = {
            "memberOf": [{"id": tool.action_kind}],
            "appliesTo": applies_to,
        }
    actions[ESCALATE_ACTION] = {"appliesTo": applies_to}
    return {
        "": {
            "commonTypes": {
                "ProvenanceSummary": {
                    "type": "Record",
                    "attributes": {
                        "count": {"type": "Long"},
                        "hasCustomer": {"type": "Boolean"},
                        "hasExternal": {"type": "Boolean"},
                        "minTier": {"type": "String"},
                        "overlapExternal": {"type": "Boolean"},
                        "overlapSources": {"type": "Set", "element": {"type": "String"}},
                        "sourceIds": {"type": "Set", "element": {"type": "String"}},
                        "systems": {"type": "Set", "element": {"type": "String"}},
                    },
                },
                "RequestContext": {
                    "type": "Record",
                    "attributes": {
                        "actionKind": {"type": "String"},
                        "argsDigest": {"type": "String"},
                        "argsTouchSecret": {"type": "Boolean"},
                        "groups": {"type": "Set", "element": {"type": "String"}},
                        "incidentId": {"type": "String"},
                        "justificationValid": {"type": "Boolean"},
                        "onBehalfOf": {"type": "Entity", "name": HUMAN},
                        "provenance": {"type": "ProvenanceSummary"},
                        "targetOutsideTask": {"type": "Boolean"},
                        "taskId": {"type": "String"},
                        "taskScopes": {"type": "Set", "element": {"type": "String"}},
                        "tokenExp": {"type": "Long"},
                        "tool": {"type": "String"},
                    },
                },
            },
            "entityTypes": {
                "Human": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "entitledTools": {
                                "type": "Set",
                                "element": {"type": "String"},
                            },
                            "groups": {"type": "Set", "element": {"type": "String"}},
                            "login": {"type": "String"},
                        },
                    }
                },
                "Agent": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "allowedTools": {"type": "Set", "element": {"type": "String"}},
                            "clientId": {"type": "String"},
                            "justification": {"type": "String"},
                            "onBehalfOf": {"type": "Entity", "name": HUMAN},
                            "owner": {"type": "Entity", "name": HUMAN},
                        },
                    }
                },
                "Resource": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "kind": {"type": "String"},
                            "name": {"type": "String"},
                            "owner": {"type": "Entity", "name": HUMAN},
                            "sensitivity": {"type": "String"},
                        },
                    }
                },
            },
            "actions": actions,
        }
    }


def write_schema(graph: Graph, path: Path | str = DEFAULT_SCHEMA_PATH) -> Path:
    """Write the graph's schema to `path`, for the committed copy.

    `policies/schema.cedarschema.json` is generated and committed so a reader
    can see the action surface without running anything. A test regenerates it
    from `infra/graph.yml` and compares, which is what keeps the committed copy
    from going stale.
    """
    target = Path(path)
    target.write_text(json.dumps(schema_for(graph), indent=2) + "\n", encoding="utf-8")
    return target


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

        # The schema comes from the graph when there is one, so the tool actions
        # are exactly the tools this deployment has, and `schema_for` refuses a
        # tool id that collides with an action the schema writes itself.
        # `schema_path` is the override; its default is the committed file, and
        # an explicit `None` means no schema at all, which is a test's affordance
        # rather than a deployment's: nothing here validates that the action
        # exists, so a caller that wants that has to give a graph or a path.
        self.schema_path = Path(schema_path) if schema_path is not None else None
        if graph is not None:
            self._schema = cedarpy.Schema.from_json_str(json.dumps(schema_for(graph)))
            # The graph's schema is what was loaded, so the path would be a lie.
            self.schema_path = None
        elif schema_path is not None:
            self._schema = cedarpy.Schema.from_json_str(
                self.schema_path.read_text(encoding="utf-8")  # type: ignore[union-attr]
            )
        else:
            self._schema = None

        if self._schema is not None:
            # A policy that does not validate against the schema will not mean
            # what its author read. Validate once, here, so a typo in an action
            # id or an attribute name stops the process instead of quietly
            # denying (or quietly permitting) every call for the life of a run.
            validation = cedarpy.validate_policies(text, self._schema)
            if not validation.validation_passed:
                errors = "; ".join(str(error) for error in validation.errors)
                raise PolicyValidationError(
                    f"policies under {self.policies_dir} do not validate against the "
                    f"schema: {errors}"
                )

        self.graph = graph
        self._mode = Mode(mode) if mode is not None else config.current_mode()
        self._log = decision_log if decision_log is not None else DecisionLog()

    # The two methods a caller gets.

    @property
    def decision_log(self) -> DecisionLog:
        """The log this engine appends to, for a caller that writes beside it."""
        return self._log

    def evaluate(self, req: AuthzRequest) -> Decision:
        """Evaluate the request and return the decision, without logging it.

        The chain source lives on the chain, and every verdict path shares it.
        Setting it here rather than in each of `_evaluate`'s returns keeps the
        record honest when a new path is added. A caller that wants the line
        written calls `decide`, or appends the decision itself when it has
        something to add first, which is what the gateway does with an
        escalation's adjudication.
        """
        decision = self._evaluate(req)
        decision.chain_source = req.chain.source
        return decision

    def decide(self, req: AuthzRequest) -> Decision:
        """Evaluate the request and append the decision to the log."""
        decision = self.evaluate(req)
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
                mode=self._mode.value,
            )

        mismatch = self._action_kind_mismatch(req)
        if mismatch is not None:
            # The action kind selects which policies apply, so it cannot be the
            # caller's word when the graph holds the tool's own answer. A call
            # labelled with a cheaper kind would otherwise be authorized by that
            # kind's permits.
            return Decision(
                verdict=Verdict.deny,
                policy_ids=[],
                reasons=[mismatch],
                request=req,
                mode=self._mode.value,
            )

        # W24, the Jev provenance rule. `derived` is the classifier's answer to
        # "does this write derive from untrusted read content", computed by the
        # gateway before this call. It is a policy input, not the decision: this
        # deterministic rule reads the boolean, and only the `jev` ablation ever
        # sets it true. It refuses the write outright rather than escalating,
        # because text that first appeared outside the org is evidence rather
        # than a question, the same shape `tainted-content` has. Reads are not
        # candidates, so a read is never refused here.
        if req.derived and req.action_kind in (ActionKind.write, ActionKind.send):
            return Decision(
                verdict=Verdict.deny,
                policy_ids=[DERIVED_POLICY_ID],
                reasons=["the write derives from content read from an untrusted source"],
                request=req,
                mode=self._mode.value,
            )

        # The tool is the action: a rule can name one tool outright, and a rule
        # about a kind reads `action in Action::"write"`. The kind is still in
        # `context.actionKind` for the log and for a policy that wants it.
        real = self._ask(req, req.tool)
        if real.decision is cedarpy.Decision.Allow:
            # An erroring policy anywhere in the set is recorded even when a
            # permit matched, because the verdict may not be the one the policy
            # author intended and the log is where that shows. The decision
            # itself still follows Cedar: a matching permit allows.
            return Decision(
                verdict=Verdict.allow,
                policy_ids=real.policy_ids,
                reasons=_with_errors(_matched("permit", real), real),
                request=req,
                mode=self._mode.value,
            )
        if real.errors:
            # No permit matched and the set does not evaluate cleanly, so this is
            # an error rather than the ordinary default deny. Fail closed and do
            # not escalate: escalation asks a human to answer a policy's refusal,
            # and an error is not a refusal a human can answer.
            return Decision(
                verdict=Verdict.deny,
                policy_ids=real.policy_ids,
                reasons=["request could not be evaluated", *real.errors],
                request=req,
                mode=self._mode.value,
            )
        if real.decision is not cedarpy.Decision.Deny:
            # NoDecision: the request or the entity set failed schema parsing.
            # Fail closed and do not escalate, because escalation answers a deny.
            return Decision(
                verdict=Verdict.deny,
                policy_ids=[],
                reasons=["request could not be evaluated", *real.errors],
                request=req,
                mode=self._mode.value,
            )

        escalate = self._ask(req, ESCALATE_ACTION)
        if escalate.errors:
            return Decision(
                verdict=Verdict.deny,
                policy_ids=real.policy_ids,
                reasons=["request could not be evaluated", *escalate.errors],
                request=req,
                mode=self._mode.value,
            )
        if escalate.decision is cedarpy.Decision.Allow:
            # The deny that caused the escalation belongs in the record too: an
            # escalate line that names only the escalate permit cannot be read
            # back to why the action needed a human.
            # The tool is the real action now, so naming the kind here would name
            # something the agent never called. The kind is still in the line
            # beside it, and in `context.actionKind` for a policy.
            reasons = [f"real action denied: {req.tool} ({req.action_kind.value})"]
            reasons.extend(f"real action denied by: {policy_id}" for policy_id in real.policy_ids)
            reasons.extend(_matched("escalate permit", escalate))
            return Decision(
                verdict=Verdict.escalate,
                policy_ids=[*real.policy_ids, *escalate.policy_ids],
                reasons=reasons,
                request=req,
                mode=self._mode.value,
            )
        return Decision(
            verdict=Verdict.deny,
            policy_ids=real.policy_ids,
            reasons=_with_errors(_denied(real), escalate),
            request=req,
            mode=self._mode.value,
        )

    def _action_kind_mismatch(self, req: AuthzRequest) -> str | None:
        """A reason to refuse when the request's action kind is not the graph's.

        The graph is authoritative for what a tool does. A tool with no row is
        left to the policies: the shipped graph does not list every tool a
        deployment might call, and inventing a kind for it would be the same
        mistake in the other direction.
        """
        if self.graph is None:
            return None
        tool = self.graph.tool(req.tool)
        if tool is None:
            return None
        # The row holds the kind as text, so compare the values rather than the
        # enum and the string. Comparing them directly is always unequal, which
        # would have made this check a no-op.
        if tool.action_kind == req.action_kind.value:
            return None
        return (
            f"tool {req.tool!r} is a {tool.action_kind} tool in the graph, "
            f"but the request asks for {req.action_kind.value}"
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
        # Sorted, because Cedar returns the reasons as a set and the process hash
        # seed changes their order between runs. An audit line that lists the
        # same two policies in a different order on every run cannot be compared
        # to the run before it, and the grader reads this field.
        policy_ids = sorted(
            annotations.get(reason, reason) for reason in result.diagnostics.reasons
        )
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
            "taskScopes": list(req.chain.scopes),
            "groups": list(req.chain.groups),
            "incidentId": req.chain.incident_id or "",
            "onBehalfOf": _entity_ref(HUMAN, req.chain.sub),
            "justificationValid": self._justification_valid(req),
            "tokenExp": int(req.chain.token_exp.timestamp()),
            "argsTouchSecret": req.args_touch_secret,
            "targetOutsideTask": req.target_outside_task,
            "provenance": {
                "minTier": provenance.min_tier.value,
                "hasExternal": provenance.has_external,
                "hasCustomer": provenance.has_customer,
                "systems": sorted({source.system for source in provenance.sources}),
                "sourceIds": sorted({source.id for source in provenance.sources}),
                # `overlapSources` and `overlapExternal` are W11's content-taint
                # computation, and `argsTouchSecret` and `targetOutsideTask` are
                # its argument scan and target comparison. The gateway fills them
                # from the task's `TaskState`; a request built by hand, which is
                # what the policy table does, carries whatever it set. The default
                # claims no taint, which is the permissive direction rather than
                # the deny-safe one: a `False` here suppresses the rule instead of
                # firing it.
                "overlapSources": sorted(req.overlap_sources),
                "overlapExternal": req.overlap_external,
                # `count` is what lets a policy tell "nothing has been read yet"
                # from "only the owner's own material has been read", which the
                # summary alone cannot distinguish.
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
        if agent is None:
            return False
        return self._live_justification(agent, req.ts)

    def _entities(self, req: AuthzRequest) -> list[dict[str, Any]]:
        entities: dict[tuple[str, str], dict[str, Any]] = {}

        def add(entity_type: str, entity_id: str, attrs: dict[str, Any]) -> None:
            entities[(entity_type, entity_id)] = {
                "uid": {"type": entity_type, "id": entity_id},
                "attrs": attrs,
                "parents": [],
            }

        # The union of `allowed_tools` over the agents each human owns, built
        # once per request. This is the policy input that narrows the OBO
        # token's scopes to the person who asked rather than to the agent client.
        entitled = self._entitled_tools(req.ts)

        agent_row = self.graph.agent(req.chain.act) if self.graph is not None else None
        # An agent with no row, or a row with no owner, is not owned by whoever
        # asked. Filling the owner in from `sub` made every ownership permit
        # match, which is the opposite of what an unknown agent should mean.
        owner_id = (
            agent_row.owner_human_id
            if agent_row is not None and agent_row.owner_human_id
            else UNKNOWN_HUMAN
        )

        self._add_human(entities, add, req.chain.sub, entitled, fallback_groups=req.chain.groups)
        if owner_id != req.chain.sub:
            self._add_human(entities, add, owner_id, entitled)

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
            self._add_human(entities, add, resource_row.owner_human_id, entitled)
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
            # No row for this resource. `kind` and `sensitivity` are `unknown`,
            # and the owner is a sentinel that no human row can equal, so a
            # permit that keys on ownership cannot match a resource the graph
            # has never heard of.
            add(
                RESOURCE,
                req.resource,
                {
                    "kind": "unknown",
                    "name": req.resource,
                    "owner": _entity_ref(HUMAN, UNKNOWN_HUMAN),
                    "sensitivity": "unknown",
                },
            )
        return list(entities.values())

    def _entitled_tools(self, at: datetime) -> dict[str, list[str]]:
        """What each human may reach, as the union of the tools their live agents hold.

        The access graph records `allowed_tools` on an agent and the human who
        owns it. The union over the agents one person owns is the honest answer
        to "what may this person do". The permit looks it up for the human in
        `sub`, not for the agent's owner, so an agent owned by one person cannot
        carry that person's authority when somebody else invokes it.

        An agent whose justification is missing or expired confers nothing. Its
        own calls are refused by `orphan-agent`, so treating its allowlist as
        authority would let a person borrow a tool from an agent that may not
        act at all. `entitledTools` is sorted so the same graph gives the same
        entity set on every run, which a decision replayed from the log needs.
        """
        if self.graph is None:
            return {}
        entitled: dict[str, set[str]] = {}
        for agent in self.graph.agents():
            if not agent.owner_human_id or not self._live_justification(agent, at):
                continue
            entitled.setdefault(agent.owner_human_id, set()).update(agent.allowed_tools)
        return {human: sorted(tools) for human, tools in entitled.items()}

    @staticmethod
    def _live_justification(agent: Any, at: datetime) -> bool:
        """Whether one agent row carries a justification that is live at `at`.

        The rule lives in `warrant.graph` so the scenario schema's entitlement
        check reads the same function the baseline permit does.
        """
        return live_justification(agent, at)

    def _add_human(
        self,
        entities: dict[tuple[str, str], dict[str, Any]],
        add: Any,
        human_id: str,
        entitled: dict[str, list[str]],
        fallback_groups: list[str] | None = None,
    ) -> None:
        if (HUMAN, human_id) in entities:
            return
        if human_id == UNKNOWN_HUMAN:
            # The sentinel names no person, so no Human entity is registered for
            # it and `_entity_ref` to it cannot equal a real human's uid.
            return
        tools = list(entitled.get(human_id, []))
        row = self.graph.human(human_id) if self.graph is not None else None
        if row is not None:
            add(
                HUMAN,
                human_id,
                {"login": row.login, "groups": list(row.groups), "entitledTools": tools},
            )
        else:
            add(
                HUMAN,
                human_id,
                {
                    "login": human_id,
                    "groups": list(fallback_groups or []),
                    "entitledTools": tools,
                },
            )


class JevOnlyEngine:
    """W24's `jev-only` adapter: the Jev choice is the verdict, Cedar never runs.

    The gateway fills `request.jev_choice` with the classifier's answer before
    it calls this engine, because the choice is an `await` and the `PolicyEngine`
    surface is synchronous. The mapping is the whole engine: `allow`, `deny`, and
    `escalate` become the matching verdict, and anything else is a deny, which is
    the fail-closed answer for a classifier that could not be understood.

    There is no policy set and no `graph` here on purpose. The point of the
    column is to put a model with full context at the enforcement point and see
    what the deterministic rules were worth, so the engine must not add a second
    deterministic check beside the model.
    """

    def __init__(
        self,
        *,
        mode: Mode | None = None,
        decision_log: DecisionLog | None = None,
    ) -> None:
        self._mode = Mode(mode) if mode is not None else config.current_mode()
        self._log = decision_log if decision_log is not None else DecisionLog()

    @property
    def decision_log(self) -> DecisionLog:
        """The log this engine appends to, for a caller that writes beside it."""
        return self._log

    def evaluate(self, req: AuthzRequest) -> Decision:
        """Map the classifier's choice to a verdict."""
        choice = req.jev_choice
        if choice == Verdict.allow.value:
            verdict = Verdict.allow
            reasons = ["jev-only answered allow"]
        elif choice == Verdict.deny.value:
            verdict = Verdict.deny
            reasons = ["jev-only answered deny"]
        elif choice == Verdict.escalate.value:
            verdict = Verdict.escalate
            reasons = ["jev-only answered escalate"]
        else:
            # No classifier answer reached the engine. Fail closed rather than
            # let a call through that nothing decided.
            verdict = Verdict.deny
            reasons = ["jev-only returned no decision; failing closed"]
        return Decision(
            verdict=verdict,
            policy_ids=[f"{JEV_ONLY_POLICY_PREFIX}{choice or 'no-answer'}"],
            reasons=reasons,
            request=req,
            mode=self._mode.value,
            chain_source=req.chain.source,
        )

    def decide(self, req: AuthzRequest) -> Decision:
        """Evaluate the request and append the decision to the log."""
        decision = self.evaluate(req)
        self._log.append(decision)
        return decision

    def explain(self, req: AuthzRequest) -> str:
        """Render the classifier's answer and the verdict it produced."""
        decision = self.evaluate(req)
        lines = [
            f"mode: {self._mode.value}",
            "engine: jev-only, no Cedar policy was evaluated",
            (
                f"chain: sub={req.chain.sub} act={req.chain.act} task={req.chain.task_id} "
                f"scopes={req.chain.scopes} groups={req.chain.groups} "
                f"token_exp={req.chain.token_exp.isoformat()}"
            ),
            (
                f"call: tool={req.tool} action={req.action_kind.value} "
                f"resource={req.resource} args_digest={req.args_digest} at={req.ts.isoformat()}"
            ),
            f"jev_choice: {req.jev_choice}",
        ]
        for call in req.jev_calls:
            lines.append(
                f"jev_call: rule={call.rule} model={call.model} latency_ms={call.latency_ms} "
                f"input_tokens={call.input_tokens} output_tokens={call.output_tokens} "
                f"choice={call.choice} confidence={call.confidence} error={call.error}"
            )
        lines.append(f"verdict: {decision.verdict.value}")
        lines.append(f"policy_ids: {decision.policy_ids}")
        lines.append("reasons:")
        lines.extend(f"  - {reason}" for reason in decision.reasons)
        return "\n".join(lines)


def _matched(verb: str, outcome: _Outcome) -> list[str]:
    if outcome.policy_ids:
        return [f"{verb} matched: {policy_id}" for policy_id in outcome.policy_ids]
    return [f"{verb} path reached with no policy id reported"]


def _with_errors(reasons: list[str], outcome: _Outcome) -> list[str]:
    """The reasons so far, plus any evaluation error from `outcome`.

    A permit that matches and an erroring policy can be in the same policy set,
    and the error still matters: it says the set does not evaluate cleanly, so
    the verdict may not be the one the policy author intended. Dropping it when
    some policy id was present made a broken policy invisible in three of the
    four paths through `_evaluate`.
    """
    if not outcome.errors:
        return reasons
    return [*reasons, *(f"evaluation error: {error}" for error in outcome.errors)]


def _denied(outcome: _Outcome) -> list[str]:
    if outcome.policy_ids:
        return [f"forbid matched: {policy_id}" for policy_id in outcome.policy_ids]
    reasons = ["no permit matched (Cedar default deny)"]
    reasons.extend(outcome.errors)
    return reasons
