"""The pre-flight token checks, each refusal on its own.

`check_obo_claims` is what stops a run before its first tool call when the token
is not the one the task asked for. It had no test: the criterion that mentions a
token reads a committed JSON file instead, so deleting the guard left the suite
green. These four cases are the four things the run record claims about the
token, and each has to fail on its own.
"""

from __future__ import annotations

import time

import pytest

from agents.task import Task
from agents.triage import MAX_TOKEN_LIFETIME_SECONDS, TriageError, check_obo_claims

AUDIENCE = "gitea-mcp"


def a_task() -> Task:
    return Task(kind="triage", subject="triage acme/widgets#1", user="alice")


def claims_for(task: Task, **overrides: object) -> dict[str, object]:
    """A token that passes every check, with one field overridden per test."""
    now = int(time.time())
    claims: dict[str, object] = {
        "iss": "http://localhost:8080/realms/warrant",
        "sub": "7d05f1c9-b47f-44b7-8356-343bcc0da494",
        "azp": "triage-agent",
        "aud": [AUDIENCE],
        "act": {"sub": "triage-agent"},
        "scope": "gitea:read gitea:write",
        "task_id": [task.task_id],
        "iat": now,
        "exp": now + MAX_TOKEN_LIFETIME_SECONDS,
    }
    claims.update(overrides)
    return claims


def test_a_token_for_this_task_passes() -> None:
    """The guard is not so strict that a correct token cannot pass it."""
    task = a_task()

    check_obo_claims(claims_for(task), task, AUDIENCE)


def test_a_token_for_another_audience_is_refused() -> None:
    task = a_task()

    with pytest.raises(TriageError) as error:
        check_obo_claims(claims_for(task, aud=["postgres-mcp"]), task, AUDIENCE)

    assert "audience" in str(error.value)


def test_a_token_with_two_audiences_is_refused() -> None:
    """A token may name one resource server, so a second one is a refusal."""
    task = a_task()

    with pytest.raises(TriageError):
        check_obo_claims(claims_for(task, aud=[AUDIENCE, "postgres-mcp"]), task, AUDIENCE)


def test_a_token_for_another_actor_is_refused() -> None:
    task = a_task()

    with pytest.raises(TriageError) as error:
        check_obo_claims(claims_for(task, act={"sub": "support-agent"}), task, AUDIENCE)

    assert "actor" in str(error.value)


def test_a_token_for_another_task_is_refused() -> None:
    task = a_task()

    with pytest.raises(TriageError) as error:
        check_obo_claims(claims_for(task, task_id=["another-task-id"]), task, AUDIENCE)

    assert "task id" in str(error.value)


def test_a_token_with_no_task_id_is_refused() -> None:
    task = a_task()
    claims = claims_for(task)
    del claims["task_id"]

    with pytest.raises(TriageError):
        check_obo_claims(claims, task, AUDIENCE)


def test_a_token_that_lives_too_long_is_refused() -> None:
    task = a_task()
    now = int(time.time())

    with pytest.raises(TriageError) as error:
        over_long = claims_for(task, iat=now, exp=now + MAX_TOKEN_LIFETIME_SECONDS + 1)
        check_obo_claims(over_long, task, AUDIENCE)

    assert "lifetime" in str(error.value)


def test_a_token_without_both_timestamps_is_refused() -> None:
    """A lifetime that cannot be computed is not an acceptable lifetime."""
    task = a_task()
    claims = claims_for(task)
    del claims["iat"]

    with pytest.raises(TriageError):
        check_obo_claims(claims, task, AUDIENCE)
