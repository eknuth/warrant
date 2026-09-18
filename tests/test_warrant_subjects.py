"""The subject fetch: which ledger source is the subject, and how it is read.

The database fetch needs the stack, so what is tested here is the dispatch and
the forge read over a mock transport. The ticket read is refused without a
credential before it reaches the network, which is the fail-closed direction.
"""

from __future__ import annotations

import httpx
import pytest

from warrant.models import Provenance, Source, Tier
from warrant.subjects import (
    SUBJECT_TEXT_LIMIT,
    TRUNCATION_MARK,
    SubjectSettings,
    fetch_subject,
    subject_ref,
    truncate,
)


def source(**overrides: object) -> Source:
    data: dict[str, object] = {
        "system": "gitea",
        "kind": "issue",
        "id": "acme/widgets#1",
        "author": "bob",
        "author_tier": Tier.member,
        "digest": "sha256:issue",
    }
    data.update(overrides)
    return Source.model_validate(data)


def test_the_first_ticket_or_issue_is_the_subject() -> None:
    provenance = Provenance(
        task_id="task-1",
        sources=[
            source(system="gitea", kind="repo", id="acme/widgets"),
            source(),
            source(system="db", kind="ticket", id="42"),
        ],
    )

    ref = subject_ref(provenance)

    assert ref is not None
    assert ref.id == "acme/widgets#1"
    assert ref.kind == "issue"
    assert ref.tier is Tier.member


def test_a_ledger_with_no_subject_has_no_ref() -> None:
    provenance = Provenance(task_id="task-1", sources=[source(kind="repo", id="acme/widgets")])

    assert subject_ref(provenance) is None


def test_truncate_marks_the_cut() -> None:
    long = "x" * (SUBJECT_TEXT_LIMIT + 10)

    cut = truncate(long)

    assert len(cut) == SUBJECT_TEXT_LIMIT + len(TRUNCATION_MARK)
    assert cut.endswith(TRUNCATION_MARK)
    assert truncate("short") == "short"


async def test_a_ticket_without_a_credential_is_not_fetched() -> None:
    ref = subject_ref(
        Provenance(task_id="t", sources=[source(system="db", kind="ticket", id="42")])
    )
    assert ref is not None

    assert await fetch_subject(ref, settings=SubjectSettings(postgres_password="")) is None


async def test_an_issue_is_read_over_the_forge_api() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "token test-token"
        assert request.url.path == "/api/v1/repos/acme/widgets/issues/1"
        return httpx.Response(
            200,
            json={
                "title": "README says 8080, the code uses 8081",
                "body": "Please fix the disagreement.",
                "user": {"login": "bob"},
            },
        )

    ref = subject_ref(Provenance(task_id="t", sources=[source()]))
    assert ref is not None
    settings = SubjectSettings(gitea_admin_token="test-token", gitea_url="http://forge.test")

    doc = await fetch_subject(ref, settings=settings, transport=httpx.MockTransport(handler))

    assert doc is not None
    assert doc.id == "acme/widgets#1"
    assert doc.title == "README says 8080, the code uses 8081"
    assert doc.author == "bob"
    assert doc.tier is Tier.member


async def test_a_refused_issue_is_no_subject() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(404, json={}))
    ref = subject_ref(Provenance(task_id="t", sources=[source()]))
    assert ref is not None

    doc = await fetch_subject(
        ref,
        settings=SubjectSettings(gitea_admin_token="t", gitea_url="http://forge.test"),
        transport=transport,
    )

    assert doc is None


async def test_an_unknown_system_is_no_subject() -> None:
    ref = subject_ref(
        Provenance(task_id="t", sources=[source(system="mail", kind="ticket", id="1")])
    )
    assert ref is not None

    assert await fetch_subject(ref, settings=SubjectSettings()) is None


@pytest.mark.parametrize("identifier", ["acme/widgets", "#1", "not-a-number"])
async def test_an_issue_id_that_is_not_a_reference_is_refused(identifier: str) -> None:
    ref = subject_ref(Provenance(task_id="t", sources=[source(id=identifier)]))
    assert ref is not None

    doc = await fetch_subject(
        ref, settings=SubjectSettings(gitea_admin_token="t", gitea_url="http://forge.test")
    )

    assert doc is None
