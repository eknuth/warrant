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
* context: the provenance summary (`minTier`, `hasExternal`, `systems`,
  `count`), the task id, the token scopes, the human's groups, the action kind,
  the args digest, `justificationValid`, and `tokenExp`.

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
ESCALATE_ACTION = "escalate"

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
                        "hasExternal": {"type": "Boolean"},
                        "minTier": {"type": "String"},
                        "systems": {"type": "Set", "element": {"type": "String"}},
                    },
                },
                "RequestContext": {
                    "type": "Record",
                    "attributes": {
                        "actionKind": {"type": "String"},
                        "argsDigest": {"type": "String"},
                        "groups": {"type": "Set", "element": {"type": "String"}},
                        "justificationValid": {"type": "Boolean"},
                        "provenance": {"type": "ProvenanceSummary"},
                        "scopes": {"type": "Set", "element": {"type": "String"}},
                        "taskId": {"type": "String"},
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

        self.graph = graph
        self._mode = Mode(mode) if mode is not None else config.current_mode()
        self._log = decision_log if decision_log is not None else DecisionLog()

    # The two methods a caller gets.

    @property
    def decision_log(self) -> DecisionLog:
        """The log this engine appends to, for a caller that writes beside it."""
        return self._log

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
        # An agent with no row, or a row with no owner, is not owned by whoever
        # asked. Filling the owner in from `sub` made every ownership permit
        # match, which is the opposite of what an unknown agent should mean.
        owner_id = (
            agent_row.owner_human_id
            if agent_row is not None and agent_row.owner_human_id
            else UNKNOWN_HUMAN
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

    def _add_human(
        self,
        entities: dict[tuple[str, str], dict[str, Any]],
        add: Any,
        human_id: str,
        fallback_groups: list[str] | None = None,
    ) -> None:
        if (HUMAN, human_id) in entities:
            return
        if human_id == UNKNOWN_HUMAN:
            # The sentinel names no person, so no Human entity is registered for
            # it and `_entity_ref` to it cannot equal a real human's uid.
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
