"""The records every forge returns, one shape for gitea and github.

These are the MCP tools' structured output as well as the `Forge` protocol's
return values, so the tool layer never sees a forge-specific field. W21's
`GitHubForge` returns these same models; only `Source.system` changes.

`Source` is the provenance block W11 consumes: which system the record came
from, what kind of record it is, a stable id, the author, and the author's tier
in the organization. The tier is derived from organization membership:
`owner` for a member of the org's owner team, `member` for any other org
member, `external` for someone outside it, and `unknown` when the record has no
resolvable author (a git commit whose author is not a Gitea user). A repo
collaborator who is not an org member is `external` in `author_tier` and
`collaborator` in `author_membership`; the two fields answer different
questions, and the enum W11 reads has no collaborator value.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

# Where an author sits relative to the organization. `unknown` exists for
# records whose author cannot be resolved to a forge user at all.
AuthorTier = Literal["owner", "member", "external", "unknown"]

# Where an author sits relative to one repository. `member` is an org member,
# `collaborator` has repo access without org membership, `external` has neither.
AuthorMembership = Literal["member", "collaborator", "external"]

SourceKind = Literal["issue", "comment", "file", "repo"]

Visibility = Literal["public", "private"]


class Source(BaseModel):
    """Where a returned record came from, for provenance."""

    system: str
    kind: SourceKind
    id: str
    author: str
    author_tier: AuthorTier


class Repo(BaseModel):
    name: str
    full_name: str
    description: str = ""
    private: bool
    default_branch: str
    html_url: str = ""
    source: Source


class Comment(BaseModel):
    id: str
    body: str
    author: str
    author_membership: AuthorMembership
    created_at: datetime | None = None
    source: Source


class Issue(BaseModel):
    number: int
    title: str
    body: str = ""
    state: str
    author: str
    author_membership: AuthorMembership
    labels: list[str] = Field(default_factory=list)
    comments: list[Comment] = Field(default_factory=list)
    html_url: str = ""
    source: Source


class FileContent(BaseModel):
    path: str
    ref: str
    content: str
    sha: str | None = None
    source: Source


class CodeMatch(BaseModel):
    path: str
    line: int
    snippet: str
    source: Source


class SearchResult(BaseModel):
    """The result of a code search.

    `truncated` is true when the scan stopped early, either because the tree was
    truncated by the forge or because the scan's own limits were reached. A
    caller that needs to know its search was exhaustive has to check it.
    """

    query: str
    matches: list[CodeMatch] = Field(default_factory=list)
    truncated: bool = False


class Branch(BaseModel):
    name: str
    sha: str = ""
    source: Source


class Commit(BaseModel):
    sha: str
    path: str
    branch: str
    message: str
    html_url: str = ""
    source: Source


class PullRequest(BaseModel):
    number: int
    title: str
    body: str = ""
    head: str
    base: str
    state: str
    html_url: str = ""
    source: Source
