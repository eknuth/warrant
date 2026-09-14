"""The committed realm file, held to what the token exchange needs.

`make reset` imports `infra/keycloak/warrant-realm.json` into a clean store, so
that file is the system of record for every client, scope, mapper, and user.
These checks are the invariants the exchange depends on and that a reviewer
would otherwise verify by hand in the admin console: each agent's `act` mapper
sits on a scope only that agent has, triage holds no DB audience, the task id
scope is parameterized, every committed secret is a placeholder, and the
access token lifetime is the five minutes the ticket names.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
REALM: dict[str, Any] = json.loads((REPO / "infra/keycloak/warrant-realm.json").read_text())
REALM_SCOPE_NAMES = {scope["name"] for scope in REALM["clientScopes"]}

AGENTS = ("triage-agent", "support-agent", "orphan-agent")
RESOURCE_SERVERS = ("gitea-mcp", "postgres-mcp", "mail-mcp")


def client(client_id: str) -> dict[str, Any]:
    return next(c for c in REALM["clients"] if c["clientId"] == client_id)


def client_scope(name: str) -> dict[str, Any]:
    return next(s for s in REALM["clientScopes"] if s["name"] == name)


def assigned_scopes(client_id: str) -> list[dict[str, Any]]:
    model = client(client_id)
    names = model.get("defaultClientScopes", []) + model.get("optionalClientScopes", [])
    return [client_scope(name) for name in names]


def mappers(client_scope_model: dict[str, Any]) -> list[dict[str, Any]]:
    return client_scope_model.get("protocolMappers", [])


def client_mappers(client_id: str) -> list[dict[str, Any]]:
    """Mappers on the client itself, which apply to every token it gets."""
    return client(client_id).get("protocolMappers", [])


def is_act_mapper(mapper: dict[str, Any]) -> bool:
    return mapper["protocolMapper"] == "oidc-hardcoded-claim-mapper" and (
        mapper["config"].get("claim.name") == "act"
    )


def audience_mappers(client_id: str) -> list[str]:
    found = [
        mapper["config"]["included.client.audience"]
        for scope in assigned_scopes(client_id)
        for mapper in mappers(scope)
        if mapper["protocolMapper"] == "oidc-audience-mapper"
    ]
    # A client-level mapper widens the audience the same way, so it counts.
    found += [
        mapper["config"]["included.client.audience"]
        for mapper in client_mappers(client_id)
        if mapper["protocolMapper"] == "oidc-audience-mapper"
    ]
    return found


def act_mappers(client_id: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    found = []
    for scope in assigned_scopes(client_id):
        for mapper in mappers(scope):
            if is_act_mapper(mapper):
                found.append((scope, mapper))
    for mapper in client_mappers(client_id):
        if is_act_mapper(mapper):
            model = client(client_id)
            owner = {"name": model["clientId"], "protocolMappers": model["protocolMappers"]}
            found.append((owner, mapper))
    return found


def test_the_realm_issues_five_minute_access_tokens() -> None:
    assert REALM["realm"] == "warrant"
    assert REALM["enabled"] is True
    assert REALM["accessTokenLifespan"] == 300


def test_the_compose_image_is_the_version_the_decision_doc_names() -> None:
    import yaml

    compose = yaml.safe_load((REPO / "compose.yml").read_text())
    keycloak = compose["services"]["keycloak"]

    assert keycloak["image"] == "quay.io/keycloak/keycloak:26.7.3"
    assert "start-dev" in keycloak["command"]
    assert "--import-realm" in keycloak["command"]
    assert any("/opt/keycloak/data/import" in volume for volume in keycloak["volumes"])


def test_the_three_users_carry_their_groups() -> None:
    users = {user["username"]: user for user in REALM["users"]}

    assert set(users) == {"alice", "bob", "mallory"}
    assert users["alice"]["groups"] == ["/owners"]
    assert users["bob"]["groups"] == ["/engineers"]
    assert "groups" not in users["mallory"]


def test_user_passwords_are_realm_import_placeholders() -> None:
    for user in REALM["users"]:
        for credential in user["credentials"]:
            assert credential["type"] == "password"
            assert credential["value"] == "${WARRANT_USER_PASSWORD}"


def test_console_is_a_public_pkce_client_without_implicit_flow() -> None:
    console = client("console")

    assert console["publicClient"] is True
    assert console["standardFlowEnabled"] is True
    assert console["implicitFlowEnabled"] is False
    assert console["attributes"]["pkce.code.challenge.method"] == "S256"


def test_agent_clients_are_confidential_and_may_exchange() -> None:
    for agent in AGENTS:
        model = client(agent)
        assert model["publicClient"] is False
        assert model["secret"] == "${WARRANT_AGENT_CLIENT_SECRET}"
        assert model["attributes"]["standard.token.exchange.enabled"] == "true"


def test_resource_servers_are_bearer_only() -> None:
    for name in RESOURCE_SERVERS:
        assert client(name)["bearerOnly"] is True


def test_permission_scopes_are_assigned_as_the_ticket_says() -> None:
    required = {"gitea:read", "gitea:write", "db:read", "db:write", "mail:send"}
    assert required <= REALM_SCOPE_NAMES
    triage = set(client("triage-agent")["defaultClientScopes"])
    support = set(client("support-agent")["defaultClientScopes"])

    assert {"gitea:read", "gitea:write"} <= triage
    assert {"db:read", "db:write", "mail:send"} <= support
    assert not {"db:read", "db:write", "mail:send"} & triage


def test_each_agent_has_an_act_mapper_on_a_scope_only_it_has() -> None:
    for agent in AGENTS:
        found = act_mappers(agent)
        assert len(found) == 1, agent
        holding_scope, mapper = found[0]

        config = mapper["config"]
        assert config["jsonType.label"] == "JSON"
        assert config["access.token.claim"] == "true"
        # The value must decode to an object, not a JSON string. Whether a
        # string decodes as an object is exactly what this check pins.
        assert json.loads(config["claim.value"]) == {"sub": agent}

        others = [name for name in AGENTS if name != agent]
        for other in others:
            other_scope_names = {scope["name"] for scope in assigned_scopes(other)}
            assert holding_scope["name"] not in other_scope_names, (agent, other)


def test_triage_holds_only_the_gitea_audience() -> None:
    assert set(audience_mappers("triage-agent")) == {"gitea-mcp"}


def test_no_client_but_the_agents_carries_an_act_mapper() -> None:
    """The act claim is written by the realm, so every writer has to be known.

    A client-level mapper is the other place one can hide: the scans above read
    client scopes, and a mapper added on a client itself applies to every token
    that client gets.
    """
    writers = set()
    for scope in REALM["clientScopes"]:
        if any(is_act_mapper(mapper) for mapper in mappers(scope)):
            writers.add(scope["name"])
    for model in REALM["clients"]:
        if any(is_act_mapper(mapper) for mapper in client_mappers(model["clientId"])):
            writers.add(model["clientId"])

    expected = {f"{agent}-obo" for agent in AGENTS}
    detail = f"act mappers are written by {sorted(writers)}, expected {sorted(expected)}"
    assert writers == expected, detail


def test_an_agent_holds_no_scope_beyond_the_ones_named_for_it() -> None:
    """Optional scopes are a second way to widen an agent, so they are pinned.

    The default-scope check below would not see `db:read` added as an optional
    scope, and Keycloak honors an optional scope the caller asks for.
    """
    triage_optional = set(client("triage-agent").get("optionalClientScopes", []))
    support_optional = set(client("support-agent").get("optionalClientScopes", []))

    assert triage_optional == {"task-id"}
    assert support_optional == {"task-id"}
    assert not {"postgres-mcp", "mail-mcp"} & set(audience_mappers("triage-agent"))


def test_triage_cannot_be_granted_the_db_or_mail_audience_by_scope_mapping() -> None:
    """A scope mapping is a third way, and the realm grants no scope mappings."""
    triage = client("triage-agent")

    assert not triage.get("scopeMappings")
    assert not triage.get("clientScopeMappings")
    for model in REALM["clients"]:
        assert not model.get("clientScopeMappings", {}).get("triage-agent"), model["clientId"]


def test_support_holds_the_db_and_mail_audiences() -> None:
    assert set(audience_mappers("support-agent")) == {"postgres-mcp", "mail-mcp"}


def test_the_task_id_scope_is_parameterized_and_optional_for_every_agent() -> None:
    task_scope = client_scope("task-id")

    assert task_scope["attributes"]["is.parameterized.scope"] == "true"
    task_mappers = [
        mapper
        for mapper in mappers(task_scope)
        if mapper["protocolMapper"] == "oidc-parameterized-scope-mapper"
    ]
    assert len(task_mappers) == 1
    assert task_mappers[0]["config"]["claim.name"] == "task_id"
    assert task_mappers[0]["config"]["access.token.claim"] == "true"

    for agent in AGENTS:
        assert "task-id" in client(agent).get("optionalClientScopes", []), agent


def test_every_committed_secret_is_a_placeholder() -> None:
    """No live value may enter the realm file; `.env` is the only place one lives."""
    for model in REALM["clients"]:
        if "secret" in model:
            assert model["secret"] == "${WARRANT_AGENT_CLIENT_SECRET}", model["clientId"]
    for user in REALM["users"]:
        for credential in user["credentials"]:
            assert credential["value"].startswith("${")
