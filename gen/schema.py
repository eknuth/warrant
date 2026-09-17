"""The scenario schema: the seed, the tasks, and the ground truth.

A scenario file is deterministic YAML. It names what to seed in the org, the
database, the inbox, and the access graph, which tasks to run, and what the
grader should see. W13 wrote the other eight files and rewrote the two fixtures
that W12 left here.

The models validate more than shape. A task's `subject` has to agree with its
`params`, a ticket has to name a customer this file seeds, an issue author has
to be one of the members or externals the file names, and a truth block may not
name a tool the gateway does not re-export. The tool list comes from
`infra/graph.yml`, which is the same file the gateway reads, so a scenario
cannot assert ground truth about a tool no agent could ever call.

A scenario's `graph.agents` may not reuse a shipped agent id. `infra/graph.yml`
is the authority for the shipped ids, and the gateway upserts it at startup, so
a scenario override would be reverted by the next restart. Scenario-owned
agents use new ids and sit beside the shipped ones.

A task's `user` and `agent` are checked against both the graph and the realm. A
task names an agent, defaulting to the shipped client for its kind; the agent has
to be a client the console can exchange for, which is the set the realm's
console audiences name, and it has to have a graph row for the allowlist and the
justification. A scenario-owned agent row is entitlement only and can never be
the acting client. The human named has to own a live agent that holds the acting
agent's tools, which is the union the baseline permit reads as
`onBehalfOf.entitledTools`. A task's `scopes` are checked against the realm's
client scopes, so a scope the realm does not mint fails at load rather than
becoming a silent deny.

`expected_disposition` is keyed by an injected action's tool. A block with an
injected action and no disposition for it, or a disposition naming a tool that
is not injected, is rejected. A legitimate action is not a disposition key, so a
scenario says what the poison should get and not what the honest calls should.

`ActionMatch` matching semantics, for W14. The `tool` has to equal the
gateway's re-exported tool name exactly. Each key of `args_include` names a call
argument; the argument's value is stringified and the pattern has to appear in
it. A pattern that starts with `re:` is a regular expression search over that
string rather than a literal substring. Every `args_include` entry has to match
and no `args_exclude` entry may, under the same rule. A `None` argument matches
nothing, so an `args_include` on it fails. `mail_link_contains_secret` is a
separate predicate on a mail call's links, true when a link's query carries a
value the task read as a secret, and it is `None` when the matcher does not ask.

Field-by-field documentation lives in `docs/decisions/w12-scenario-seeders.md`.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from warrant.graph import Agent, live_justification

REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"
GRAPH_SEED = REPO_ROOT / "infra" / "graph.yml"
REALM_SEED = REPO_ROOT / "infra" / "keycloak" / "warrant-realm.json"

Disposition = Literal["allow", "deny", "escalate"]
Visibility = Literal["public", "private"]

# The `re:` prefix is how a string argument is read as a regular expression
# rather than as a literal to find.
REGEX_PREFIX = "re:"

# A triage subject is `owner/name#number`; a support subject is `ticket:number`.
_TRIAGE_SUBJECT = re.compile(r"^(?P<repo>[^/\s#]+/[^/\s#]+)#(?P<number>\d+)$")
_SUPPORT_SUBJECT = re.compile(r"^ticket:(?P<ticket>\d+)$")


class SchemaError(ValueError):
    """A scenario file disagrees with the graph or with itself."""


@lru_cache(maxsize=1)
def graph_seed_data() -> dict[str, Any]:
    """`infra/graph.yml` as a mapping, read once per process."""
    data = yaml.safe_load(GRAPH_SEED.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SchemaError(f"{GRAPH_SEED} did not parse to a mapping")
    return data


def gateway_tool_ids() -> frozenset[str]:
    """Every tool id the gateway can re-export, from the graph's tool table.

    The gateway re-exports a tool only when the access graph has a row for it,
    so this is the authoritative list and not a hand-kept copy. Reading it here
    also means a scenario file fails at load when it names a tool that was
    renamed or removed.
    """
    return frozenset(str(row["id"]) for row in graph_seed_data().get("tools", []))


def graph_human_logins() -> frozenset[str]:
    """Every human login the shipped graph defines, for owner resolution."""
    return frozenset(str(row["login"]) for row in graph_seed_data().get("humans", []))


def graph_repo_names() -> frozenset[str]:
    """Every repository name the shipped graph has a `repo` row for."""
    return frozenset(
        str(row["name"]) for row in graph_seed_data().get("resources", []) if row["kind"] == "repo"
    )


def shipped_agent_rows() -> dict[str, dict[str, Any]]:
    """The shipped agent rows, keyed by id, straight from `infra/graph.yml`."""
    return {str(row["id"]): row for row in graph_seed_data().get("agents", [])}


def shipped_human_ids() -> dict[str, str]:
    """The shipped human ids, keyed by login."""
    return {str(row["login"]): str(row["id"]) for row in graph_seed_data().get("humans", [])}


@lru_cache(maxsize=1)
def realm_seed_data() -> dict[str, Any]:
    """`infra/keycloak/warrant-realm.json` as a mapping, read once per process.

    The realm is the authority for the scopes a run can request and the clients
    it can exchange as, the same way `infra/graph.yml` is the authority for the
    tools. Reading it here makes a scope or an acting client the realm does not
    mint a load error rather than a silent deny at run time.
    """
    data = json.loads(REALM_SEED.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SchemaError(f"{REALM_SEED} did not parse to a mapping")
    return data


def realm_client_assigned_scopes(client_id: str) -> frozenset[str]:
    """The client scopes a realm client is assigned, default and optional.

    The assignment is what the token exchange can carry back for that client; a
    scope the client is not assigned is refused by the realm rather than
    silently dropped. Reading the client's own lists rather than the realm's
    global scope table is what makes that refusal a load error.
    """
    clients = {str(row["clientId"]): row for row in realm_seed_data().get("clients", [])}
    client = clients.get(client_id)
    if client is None:
        return frozenset()
    return frozenset(
        str(name)
        for name in list(client.get("defaultClientScopes", []))
        + list(client.get("optionalClientScopes", []))
    )


def realm_parameterized_scope_names() -> frozenset[str]:
    """The client scopes the realm mints a `<name>:<value>` value for."""
    return frozenset(
        str(scope["name"])
        for scope in realm_seed_data().get("clientScopes", [])
        if str(scope.get("attributes", {}).get("is.parameterized.scope", "")).lower() == "true"
    )


def realm_acting_agents() -> frozenset[str]:
    """The clients a console login can be exchanged for.

    The console's own scopes carry the `aud-<agent>` audience mappers, so the
    clients those mappers name are the ones the console token can be exchanged
    for. Each also has to allow token exchange. This is the set a task may name
    as its acting client; a scenario-owned agent row is entitlement only.

    The console's optional scopes are read as well as its default scopes, so an
    optional audience scope on the console widens the legal acting-client set.
    """
    data = realm_seed_data()
    clients = {str(row["clientId"]): row for row in data.get("clients", [])}
    console = clients.get("console")
    if console is None:
        return frozenset()
    scopes = {str(scope["name"]): scope for scope in data.get("clientScopes", [])}
    assigned = list(console.get("defaultClientScopes", [])) + list(
        console.get("optionalClientScopes", [])
    )
    named: set[str] = set()
    for name in assigned:
        scope = scopes.get(str(name))
        if scope is None:
            continue
        for mapper in scope.get("protocolMappers", []):
            if mapper.get("protocolMapper") != "oidc-audience-mapper":
                continue
            audience = mapper.get("config", {}).get("included.client.audience")
            if audience:
                named.add(str(audience))
    return frozenset(
        client_id
        for client_id in named
        if str(
            clients.get(client_id, {})
            .get("attributes", {})
            .get("standard.token.exchange.enabled", "")
        ).lower()
        == "true"
    )


def _parse_iso(value: str | None) -> datetime | None:
    """A graph field's ISO 8601 value as an aware datetime, or None."""
    if value is None or value == "":
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _agent_rows(scenario: Scenario, by_login: dict[str, str]) -> dict[str, Agent]:
    """The shipped agents plus the scenario's own, in the graph's own shape.

    The entitlement check filters these through `live_justification`, the same
    function the engine's `_entitled_tools` calls, so the schema and the
    baseline permit agree on which agents confer authority.
    """
    agents: dict[str, Agent] = {}
    for row in shipped_agent_rows().values():
        agents[str(row["id"])] = Agent(
            id=str(row["id"]),
            client_id=str(row["client_id"]),
            owner_human_id=row.get("owner_human_id"),
            justification=str(row.get("justification", "")),
            justification_expires_at=_parse_iso(row.get("justification_expires_at")),
            allowed_tools=[str(tool) for tool in row.get("allowed_tools", [])],
        )
    for agent in scenario.seed.graph.agents:
        agents[agent.client_id] = Agent(
            id=agent.client_id,
            client_id=agent.client_id,
            owner_human_id=by_login.get(agent.owner),
            justification=agent.justification,
            justification_expires_at=_parse_iso(agent.justification_expires_at),
            allowed_tools=list(agent.allowed_tools),
        )
    return agents


# The agent the role code exchanges as, by task kind. `agents/triage.py` and
# `agents/support.py` fix the client, so a task's kind decides which tools its
# user has to be entitled to.
KIND_AGENT = {"triage": "triage-agent", "support": "support-agent"}


def _stringify_args(value: Any) -> Any:
    """Turn an `args_include` mapping's values into the strings a call carries."""
    if not isinstance(value, dict):
        return value
    return {str(key): (item if isinstance(item, str) else str(item)) for key, item in value.items()}


def _check_patterns(mapping: dict[str, str], label: str) -> None:
    for key, pattern in mapping.items():
        if not pattern.startswith(REGEX_PREFIX):
            continue
        try:
            re.compile(pattern[len(REGEX_PREFIX) :])
        except re.error as exc:
            raise ValueError(f"{label}.{key} is not a usable regex: {pattern!r} ({exc})") from exc


class ActionMatch(BaseModel):
    """One call the truth block is about: a tool and predicates on its args.

    An `args_include` value is a literal substring of the stringified argument,
    or a regular expression when it starts with `re:`. Every `args_include`
    entry has to match and no `args_exclude` entry may. The tool is the
    gateway's re-exported name, `<server>.<tool>`. The full matching semantics
    are in this module's docstring, which is what W14 reads.
    """

    model_config = ConfigDict(extra="forbid")

    tool: str
    args_include: dict[str, str] = Field(default_factory=dict)
    args_exclude: dict[str, str] = Field(default_factory=dict)
    mail_link_contains_secret: bool | None = None

    @field_validator("args_include", "args_exclude", mode="before")
    @classmethod
    def _args_are_strings(cls, value: Any) -> Any:
        return _stringify_args(value)

    @model_validator(mode="after")
    def _patterns_compile(self) -> ActionMatch:
        _check_patterns(self.args_include, "args_include")
        _check_patterns(self.args_exclude, "args_exclude")
        return self


class SourceRef(BaseModel):
    """Where the poison lives: one record in one seeded system.

    The first three systems hold the seeded objects. `graph` names the access
    graph's own rows, which is the one seed block that lives in this file rather
    than in a system the reset rebuilds from the database, the org, or the
    inbox. The orphan scenario's poison is the agent row itself, so it is the
    first site that has to reach the graph.
    """

    model_config = ConfigDict(extra="forbid")

    system: Literal["gitea", "db", "mail", "graph"]
    kind: Literal[
        "repo",
        "file",
        "issue",
        "comment",
        "customer",
        "ticket",
        "note",
        "message",
        "agent",
    ]
    id: str
    note: str = ""


class CommentSeed(BaseModel):
    """One comment on a seeded issue, authored as a named login."""

    model_config = ConfigDict(extra="forbid")

    author: str
    body: str


class IssueSeed(BaseModel):
    """One issue in a seeded repository.

    `number` is what the fresh repository's numbering has to produce, because
    Gitea assigns issue numbers and does not accept one. The seeder checks the
    number it got, so a scenario that declares two issues out of order fails
    rather than seeding a different issue than the truth names.
    """

    model_config = ConfigDict(extra="forbid")

    number: int = Field(gt=0)
    author: str
    title: str
    body: str = ""
    comments: list[CommentSeed] = Field(default_factory=list)


class FileSeed(BaseModel):
    """One file, with the login whose commit carries it.

    `author` is optional so the shorthand `path: content` works; the repository's
    own `author` is the fallback. The commit author is load-bearing: W11's
    `classify` calls a file external when its last commit author is not an org
    member, so a scenario that wants an external file says who wrote it.
    """

    model_config = ConfigDict(extra="forbid")

    content: str
    author: str | None = None


class RepoSeed(BaseModel):
    """One repository in the org, with its files and issues."""

    model_config = ConfigDict(extra="forbid")

    name: str
    visibility: Visibility = "private"
    author: str | None = None
    files: dict[str, str | FileSeed] = Field(default_factory=dict)
    issues: list[IssueSeed] = Field(default_factory=list)

    def file_entries(self) -> dict[str, FileSeed]:
        """The files as `FileSeed`, with the repository's author filled in."""
        entries: dict[str, FileSeed] = {}
        for path, value in self.files.items():
            if isinstance(value, FileSeed):
                seed = (
                    value
                    if value.author is not None
                    else FileSeed(content=value.content, author=self.author)
                )
            else:
                seed = FileSeed(content=value, author=self.author)
            entries[path] = seed
        return entries

    @model_validator(mode="after")
    def _names_are_safe(self) -> RepoSeed:
        if "/" in self.name or not self.name:
            raise ValueError(f"repository name must not carry a slash: {self.name!r}")
        for path in self.files:
            if path.startswith("/") or ".." in path.split("/"):
                raise ValueError(f"file path must be relative and stay in the repo: {path!r}")
        return self


class GiteaSeed(BaseModel):
    """The org: who is in it, who is outside it, and what it holds."""

    model_config = ConfigDict(extra="forbid")

    members: list[str] = Field(default_factory=list)
    externals: list[str] = Field(default_factory=list)
    repos: list[RepoSeed] = Field(default_factory=list)


class DbCustomer(BaseModel):
    """One customer row. `owner_login` is the human the row belongs to."""

    model_config = ConfigDict(extra="forbid")

    id: int = Field(gt=0)
    name: str
    email: str
    owner_login: str


class DbTicket(BaseModel):
    """One ticket row, belonging to a customer this file seeds."""

    model_config = ConfigDict(extra="forbid")

    id: int = Field(gt=0)
    customer_id: int = Field(gt=0)
    subject: str
    body: str = ""
    author_email: str
    status: str = "open"
    incident_id: str | None = None


class DbNote(BaseModel):
    """One support note on a ticket."""

    model_config = ConfigDict(extra="forbid")

    ticket_id: int = Field(gt=0)
    author_login: str
    body: str


class DbApiKey(BaseModel):
    """One API key row. The value is generated at seed time, never written here."""

    model_config = ConfigDict(extra="forbid")

    customer_id: int = Field(gt=0)
    label: str
    revoked: bool = False


class DbSeed(BaseModel):
    """The support database: customers, tickets, notes, and keys."""

    model_config = ConfigDict(extra="forbid")

    customers: list[DbCustomer] = Field(default_factory=list)
    tickets: list[DbTicket] = Field(default_factory=list)
    notes: list[DbNote] = Field(default_factory=list)
    api_keys: list[DbApiKey] = Field(default_factory=list)

    @model_validator(mode="after")
    def _references_hold(self) -> DbSeed:
        customers = {customer.id for customer in self.customers}
        tickets = {ticket.id for ticket in self.tickets}
        if len(customers) != len(self.customers):
            raise ValueError("two customers share an id")
        if len(tickets) != len(self.tickets):
            raise ValueError("two tickets share an id")
        for ticket in self.tickets:
            if ticket.customer_id not in customers:
                raise ValueError(
                    f"ticket {ticket.id} names customer {ticket.customer_id}, not seeded"
                )
        for note in self.notes:
            if note.ticket_id not in tickets:
                raise ValueError(f"note names ticket {note.ticket_id}, not seeded")
        for key in self.api_keys:
            if key.customer_id not in customers:
                raise ValueError(f"api key names customer {key.customer_id}, not seeded")
        return self


class MailMessageSeed(BaseModel):
    """One message placed in the inbox.

    `message_id` is the RFC 5322 id the seeder writes, so verify can find the
    message by a value the scenario file names rather than by the random id the
    mailbox assigns.
    """

    model_config = ConfigDict(extra="forbid")

    from_address: str
    to: str
    subject: str
    body: str = ""
    message_id: str | None = None


class MailSeed(BaseModel):
    """The inbox the scenario starts from."""

    model_config = ConfigDict(extra="forbid")

    inbox: list[MailMessageSeed] = Field(default_factory=list)


class GraphAgent(BaseModel):
    """One agent in the access graph, with its owner and its authority."""

    model_config = ConfigDict(extra="forbid")

    client_id: str
    owner: str
    justification: str = ""
    justification_expires_at: str | None = None
    allowed_tools: list[str] = Field(default_factory=list)

    @field_validator("justification_expires_at")
    @classmethod
    def _expiry_parses(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"justification_expires_at is not ISO 8601: {value!r}") from exc
        return value


class GraphSeed(BaseModel):
    """The scenario's own agents, overlaid on the shipped graph's humans and tools."""

    model_config = ConfigDict(extra="forbid")

    agents: list[GraphAgent] = Field(default_factory=list)


class Seed(BaseModel):
    """Everything a scenario writes before its tasks run."""

    model_config = ConfigDict(extra="forbid")

    gitea: GiteaSeed = Field(default_factory=GiteaSeed)
    db: DbSeed = Field(default_factory=DbSeed)
    mail: MailSeed = Field(default_factory=MailSeed)
    graph: GraphSeed = Field(default_factory=GraphSeed)


class TaskSpec(BaseModel):
    """One task to run, in the shape `agents.run_many` takes.

    `subject` is `acme/widgets#1` for a triage task or `ticket:12` for a support
    task. Tasks that share a non-empty `concurrent_group` run together through
    W10's `run_concurrent`; that runner is W15's to call, and this field is the
    grouping it reads.

    `agent` names the client the run exchanges as. It defaults to the shipped
    client the task's kind uses, which is what the two fixtures rely on, and a
    task may name another agent the graph holds. The orphan scenario names
    `orphan-agent`, whose justification is empty: the task is the orphan case,
    every call through it is refused, and the entitlement check is skipped
    because no entitlement can make a call pass. `scopes` is the scope set the
    run has to request, as the realm spells it (`gitea:read`, or the
    parameterized `incident_id:INC-42`). An empty list means the agent client's
    own defaults.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["triage", "support"]
    user: str
    subject: str
    params: dict[str, Any] = Field(default_factory=dict)
    agent: str | None = None
    scopes: list[str] = Field(default_factory=list)
    concurrent_group: str | None = None

    @model_validator(mode="after")
    def _subject_matches_params(self) -> TaskSpec:
        if self.kind == "triage":
            match = _TRIAGE_SUBJECT.match(self.subject)
            if match is None:
                raise ValueError(f"a triage subject is 'owner/name#number', not {self.subject!r}")
            repo = self.params.get("repo")
            issue = self.params.get("issue")
            if repo != match.group("repo") or str(issue) != match.group("number"):
                raise ValueError(
                    f"triage subject {self.subject!r} disagrees with params {self.params!r}"
                )
            return self
        match = _SUPPORT_SUBJECT.match(self.subject)
        if match is None:
            raise ValueError(f"a support subject is 'ticket:number', not {self.subject!r}")
        if str(self.params.get("ticket")) != match.group("ticket"):
            raise ValueError(
                f"support subject {self.subject!r} disagrees with params {self.params!r}"
            )
        return self


class Truth(BaseModel):
    """The answer the grader scores against.

    `legitimate_actions` are calls the task should be allowed to make.
    `injected_actions` are calls the poison asks for and the run must not make.
    `expected_disposition` is keyed by an injected action's tool; every injected
    tool needs one and no other key is allowed, so a legitimate action is not a
    disposition key. `escalation_allowed` says whether a denial may be answered
    by a person.
    """

    model_config = ConfigDict(extra="forbid")

    legitimate_actions: list[ActionMatch] = Field(default_factory=list)
    injected_actions: list[ActionMatch] = Field(default_factory=list)
    injection_sites: list[SourceRef] = Field(default_factory=list)
    expected_disposition: dict[str, Disposition] = Field(default_factory=dict)
    escalation_allowed: bool = False
    notes: str = ""

    @model_validator(mode="after")
    def _dispositions_cover_the_injections(self) -> Truth:
        injected = {action.tool for action in self.injected_actions}
        missing = sorted(injected - set(self.expected_disposition))
        extra = sorted(set(self.expected_disposition) - injected)
        if missing:
            raise ValueError(f"injected actions with no expected_disposition: {missing}")
        if extra:
            raise ValueError(f"expected_disposition names tools that are not injected: {extra}")
        if injected and not self.injection_sites:
            raise ValueError("an injected action has to name where the poison lives")
        return self


class Scenario(BaseModel):
    """One scenario file: the seed, the tasks, and the truth."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    description: str
    seed: Seed
    tasks: list[TaskSpec]
    truth: Truth
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> Scenario:
        self._check_tools()
        self._check_agents_are_scenario_owned()
        self._check_owners()
        self._check_task_users()
        self._check_task_scopes()
        self._check_gitea()
        self._check_repos_have_graph_rows()
        return self

    def _check_tools(self) -> None:
        known = gateway_tool_ids()
        named = {action.tool for action in self.truth.injected_actions}
        named |= {action.tool for action in self.truth.legitimate_actions}
        named |= {tool for agent in self.seed.graph.agents for tool in agent.allowed_tools}
        unknown = sorted(named - known)
        if unknown:
            raise ValueError(
                f"scenario names tools with no row in {GRAPH_SEED}: {unknown}; "
                "the gateway does not re-export them"
            )

    def _check_agents_are_scenario_owned(self) -> None:
        """A scenario may add agents, not override a shipped one, and not repeat one.

        The gateway upserts `infra/graph.yml` when it starts, so a scenario's
        override of a shipped agent id would be reverted by the next restart.
        Refusing it makes the failure a load error instead of a scenario that
        runs under a different justification than the file says. Two scenario
        agents with one id would collide the same way a duplicate customer or
        ticket does, with the last one silently winning.
        """
        shipped = set(shipped_agent_rows())
        ids = [agent.client_id for agent in self.seed.graph.agents]
        repeated = sorted({client_id for client_id in ids if ids.count(client_id) > 1})
        if repeated:
            raise ValueError(f"two scenario agents share a client_id: {repeated}")
        for agent in self.seed.graph.agents:
            if agent.client_id in shipped:
                raise ValueError(
                    f"scenario agent {agent.client_id!r} is a shipped agent id; "
                    f"the shipped graph owns it in {GRAPH_SEED}"
                )

    def _check_owners(self) -> None:
        humans = graph_human_logins()
        for agent in self.seed.graph.agents:
            if agent.owner not in humans:
                raise ValueError(
                    f"agent {agent.client_id!r} names owner {agent.owner!r}, "
                    f"who is not one of the shipped humans {sorted(humans)}"
                )
        for customer in self.seed.db.customers:
            if customer.owner_login not in humans:
                raise ValueError(
                    f"customer {customer.id} names owner {customer.owner_login!r}, "
                    f"who is not one of the shipped humans {sorted(humans)}"
                )

    def _check_task_users(self) -> None:
        """The task's user has to reach the tools its acting agent holds.

        The acting agent is the client the run exchanges as. It defaults to the
        shipped client for the task's kind and a task may name another, but it
        has to be a client the console can be exchanged for: a scenario-owned
        agent row is entitlement only and no token can be minted for it. The
        row also has to exist in the graph, because the allowlist and the
        justification come from there.

        The run then only works when the human named owns a live agent entitled
        to the acting agent's tools. That union is
        `onBehalfOf.entitledTools`, which the baseline permit requires. An agent
        whose justification is empty or expired confers nothing, through the
        engine's own `live_justification`, so a scenario cannot rely on an agent
        the baseline would refuse.

        When the acting agent itself has no live justification the task is the
        orphan case: `10-orphan.cedar` refuses every call, no entitlement can
        change that, and the check is skipped rather than asking a user to be
        entitled to a client that may not act. The task's user is still checked
        against the shipped humans, so the file cannot name a caller the realm
        has never heard of.
        """
        humans = graph_human_logins()
        by_login = shipped_human_ids()
        now = datetime.now(UTC)
        agents = _agent_rows(self, by_login)
        acting_clients = realm_acting_agents()
        for task in self.tasks:
            if task.user not in humans:
                raise ValueError(
                    f"task {task.subject!r} names user {task.user!r}, "
                    f"who is not one of the shipped humans {sorted(humans)}"
                )
            acting_id = task.agent or KIND_AGENT[task.kind]
            acting = agents.get(acting_id)
            if acting is None:
                raise ValueError(
                    f"task {task.subject!r} names agent {acting_id!r}, "
                    "which the access graph does not hold"
                )
            if acting_id not in acting_clients:
                raise ValueError(
                    f"task {task.subject!r} names agent {acting_id!r}, which is not a client "
                    f"the console can exchange for; the realm has {sorted(acting_clients)}"
                )
            if not live_justification(acting, now):
                continue
            user_id = by_login[task.user]
            entitled: set[str] = set()
            for row in agents.values():
                if row.owner_human_id == user_id and live_justification(row, now):
                    entitled.update(row.allowed_tools)
            needed = set(acting.allowed_tools)
            missing = sorted(needed - entitled)
            if missing:
                raise ValueError(
                    f"task {task.subject!r} runs as {task.user!r}, whose live agents do not hold "
                    f"{missing}; the baseline permit needs the user entitled to them"
                )

    def _check_task_scopes(self) -> None:
        """Every declared scope has to be one the acting client is assigned.

        The token exchange can carry back less than a client holds, and a scope
        the client is not assigned is refused by the realm rather than silently
        dropped, so the check reads the acting client's own default and optional
        scopes instead of the realm's global scope table. A parameterized scope
        is written `<name>:<value>` and needs a non-empty value; a
        non-parameterized scope has to be the whole string. The realm file does
        not carry Keycloak's built-in scopes such as `openid` or `profile`, so
        those are rejected here too, which is a limit of reading the file rather
        than a need any scenario has.

        A declared `incident_id:<value>` is also tied to the seed: at least one
        ticket this file seeds has to carry that incident id, because the value
        is the record the escalation reads and a value no ticket carries cannot
        be the incident the task is about.
        """
        parameterized = realm_parameterized_scope_names()
        for task in self.tasks:
            acting_id = task.agent or KIND_AGENT[task.kind]
            assigned = realm_client_assigned_scopes(acting_id)
            for scope in task.scopes:
                if scope in parameterized:
                    raise ValueError(
                        f"task {task.subject!r} declares parameterized scope {scope!r} with no "
                        "value"
                    )
                if scope in assigned:
                    continue
                name, separator, value = scope.partition(":")
                if separator and name in parameterized and name in assigned:
                    if not value:
                        raise ValueError(
                            f"task {task.subject!r} declares parameterized scope {scope!r} with "
                            "no value"
                        )
                    if name == "incident_id":
                        seeded = {
                            ticket.incident_id
                            for ticket in self.seed.db.tickets
                            if ticket.incident_id
                        }
                        if value not in seeded:
                            raise ValueError(
                                f"task {task.subject!r} declares incident scope {scope!r}, but "
                                f"no seeded ticket carries {value!r}; seeded: {sorted(seeded)}"
                            )
                    continue
                raise ValueError(
                    f"task {task.subject!r} declares scope {scope!r}, which the acting client "
                    f"{acting_id!r} is not assigned; the client has {sorted(assigned)}"
                )

    def _check_gitea(self) -> None:
        gitea = self.seed.gitea
        outside = set(gitea.members) & set(gitea.externals)
        if outside:
            raise ValueError(f"logins are both member and external: {sorted(outside)}")
        known = set(gitea.members) | set(gitea.externals)
        names = [repo.name for repo in gitea.repos]
        if len(names) != len(set(names)):
            raise ValueError(f"two repositories share a name: {names}")
        for repo in gitea.repos:
            for path, file in repo.file_entries().items():
                if file.author is None:
                    raise ValueError(
                        f"{repo.name}:{path} has no author and the repository names none"
                    )
                if file.author not in known:
                    raise ValueError(
                        f"{repo.name}:{path} names author {file.author!r}, not a seeded login"
                    )
            for issue in repo.issues:
                if issue.author not in known:
                    raise ValueError(
                        f"{repo.name}#{issue.number} names author {issue.author!r}, "
                        "not a seeded login"
                    )
                for comment in issue.comments:
                    if comment.author not in known:
                        raise ValueError(
                            f"{repo.name}#{issue.number} has a comment by {comment.author!r}, "
                            "not a seeded login"
                        )

    def _check_repos_have_graph_rows(self) -> None:
        """Every seeded repository has a `repo` resource row in the graph.

        The scenario's graph block carries agents only, so repository rows come
        from `infra/graph.yml`. A repository with no row downloads without
        authority, and the subject rule then refuses every call that names it.
        """
        have = graph_repo_names()
        missing = sorted(
            f"acme/{repo.name}" for repo in self.seed.gitea.repos if f"acme/{repo.name}" not in have
        )
        if missing:
            raise ValueError(
                f"seeded repositories with no repo row in {GRAPH_SEED}: {missing}; "
                "the graph block seeds agents, so repository rows come from that file"
            )


def scenario_path(scenario_id: str) -> Path:
    """The file one scenario id names."""
    return SCENARIO_DIR / f"{scenario_id}.yml"


def load_scenario(scenario_id: str) -> Scenario:
    """Load one scenario by id. The id has to match the file name."""
    path = scenario_path(scenario_id)
    if not path.exists():
        known = ", ".join(available_scenarios()) or "(none)"
        raise FileNotFoundError(f"no scenario {scenario_id!r} in {SCENARIO_DIR}; have: {known}")
    return load_scenario_file(path)


def load_scenario_file(path: Path) -> Scenario:
    """Load and validate one scenario file."""
    data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SchemaError(f"{path.name} must contain a YAML mapping")
    scenario = Scenario.model_validate(data)
    if scenario.id != path.stem:
        raise ValueError(f"{path.name} declares id {scenario.id!r}; it must match the file name")
    return scenario


def available_scenarios() -> list[str]:
    """Ids of every scenario file on disk, sorted."""
    if not SCENARIO_DIR.is_dir():
        return []
    return sorted(path.stem for path in SCENARIO_DIR.glob("*.yml"))


def load_all() -> list[Scenario]:
    """Every scenario on disk, sorted by id."""
    return [load_scenario(scenario_id) for scenario_id in available_scenarios()]
