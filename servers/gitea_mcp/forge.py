"""The forge the MCP tools call, and its Gitea implementation.

The MCP tool layer in `server.py` is written against `Forge` and never imports
`GiteaForge` directly. W21 adds `GitHubForge` with the same methods returning
the same models, and `FORGE=gitea|github` in `.env` picks one; nothing above
this file changes when it does.

`repo` arguments are `owner/name`, the same string Gitea's API uses, so
`acme/demo`. A bare name is refused rather than guessed, because guessing which
org a name belongs to is the kind of assumption an eval must not rest on.

Two things about Gitea 1.24 are worth knowing before reading `GiteaForge`:

- There is no code-search REST endpoint. `search_code` reads the default
  branch's tree and its blobs and scans their text, bounded by `max_blobs` and
  `max_matches`. It is a scan, not an index, and it says so in `truncated`.
- `set_repo_visibility` has no visibility field either. The repository carries
  a `private` boolean, so the tool's `public`/`private` maps onto it.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import httpx

from .models import (
    AuthorMembership,
    AuthorTier,
    Branch,
    CodeMatch,
    Comment,
    Commit,
    FileContent,
    Issue,
    PullRequest,
    Repo,
    SearchResult,
    Source,
    SourceKind,
    Visibility,
)

# Bounds on the client-side code scan. A repository larger than this is
# reported as truncated rather than scanned in full, so a caller can tell the
# difference between "no match" and "did not look everywhere".
DEFAULT_MAX_BLOBS = 300
DEFAULT_MAX_MATCHES = 100
DEFAULT_MAX_SNIPPET = 300


class ForgeError(RuntimeError):
    """A forge call failed in a way the tool caller should see."""


@runtime_checkable
class Forge(Protocol):
    """The operations the Gitea MCP tools expose, independent of the forge."""

    async def list_repos(self, org: str) -> list[Repo]: ...

    async def list_issues(self, repo: str, state: str = "open") -> list[Issue]: ...

    async def get_issue(self, repo: str, number: int) -> Issue: ...

    async def get_file(self, repo: str, path: str, ref: str = "main") -> FileContent: ...

    async def search_code(self, repo: str, query: str) -> SearchResult: ...

    async def create_issue_comment(self, repo: str, number: int, body: str) -> Comment: ...

    async def create_branch(self, repo: str, name: str, from_ref: str = "main") -> Branch: ...

    async def commit_file(
        self, repo: str, branch: str, path: str, content: str, message: str
    ) -> Commit: ...

    async def open_pull_request(
        self, repo: str, head: str, base: str, title: str, body: str
    ) -> PullRequest: ...

    async def set_repo_visibility(self, repo: str, visibility: Visibility) -> Repo: ...


@dataclass
class _Roster:
    """Who is in the org, who owns it, and who is on the repo.

    One roster is built per tool call. A long-lived cache would go stale the
    moment W12 reseeds the org between eval runs, and the whole point of the
    local forge is that each run starts from a known membership.
    """

    owners: set[str] = field(default_factory=set)
    members: set[str] = field(default_factory=set)
    collaborators: set[str] = field(default_factory=set)

    def tier(self, login: str) -> AuthorTier:
        if not login:
            return "unknown"
        if login in self.owners:
            return "owner"
        if login in self.members:
            return "member"
        return "external"

    def membership(self, login: str) -> AuthorMembership:
        if not login:
            return "external"
        if login in self.members:
            return "member"
        if login in self.collaborators:
            return "collaborator"
        return "external"


def split_repo(repo: str) -> tuple[str, str]:
    """Split `owner/name`, refusing anything that is not exactly that."""
    owner, separator, name = repo.partition("/")
    if not separator or not owner or not name or "/" in name:
        raise ForgeError(f"repo must be 'owner/name', not {repo!r}")
    return owner, name


class GiteaForge:
    """`Forge` over one Gitea instance and one credential.

    The credential is a broad admin token on purpose; see `server.py` for why
    the scope check that token makes possible is not here. It is held on the
    client and never logged, returned, or put in an error message.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        system: str = "gitea",
        client: httpx.AsyncClient | None = None,
        max_blobs: int = DEFAULT_MAX_BLOBS,
        max_matches: int = DEFAULT_MAX_MATCHES,
    ) -> None:
        if not token:
            raise ForgeError("a Gitea token is required")
        self._base_url = base_url.rstrip("/")
        self._system = system
        self._token = token
        self._max_blobs = max_blobs
        self._max_matches = max_matches
        self._client = client or httpx.AsyncClient(
            base_url=self._base_url,
            headers={"Authorization": f"token {token}"},
            timeout=30.0,
        )
        self._owns_client = client is None
        self._credential_login: str | None = None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # -- HTTP plumbing -----------------------------------------------------

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        response = await self._client.request(method, f"/api/v1{path}", **kwargs)
        if response.status_code >= 400:
            raise ForgeError(
                f"gitea {method} {path} -> HTTP {response.status_code}: {_error_message(response)}"
            )
        return response

    async def _json(self, method: str, path: str, **kwargs: Any) -> Any:
        return (await self._request(method, path, **kwargs)).json()

    async def _get_json(self, path: str, **kwargs: Any) -> Any:
        return await self._json("GET", path, **kwargs)

    # -- provenance --------------------------------------------------------

    async def _roster(self, org: str, repo: str | None = None) -> _Roster:
        roster = _Roster()
        teams = await self._get_json(f"/orgs/{org}/teams") or []
        for team in teams:
            if team.get("permission") == "owner":
                members = await self._get_json(f"/teams/{team['id']}/members") or []
                roster.owners.update(user.get("login", "") for user in members)
        members = await self._get_json(f"/orgs/{org}/members") or []
        roster.members.update(user.get("login", "") for user in members)
        # An owner who hides their membership may be absent from the members
        # list, so the owner team is folded in. `tier` checks owners first
        # anyway; this keeps `membership` from calling an owner external.
        roster.members.update(roster.owners)
        if repo is not None:
            collaborators = await self._get_json(f"/repos/{repo}/collaborators") or []
            roster.collaborators.update(user.get("login", "") for user in collaborators)
        return roster

    async def _credential_user(self) -> str:
        if self._credential_login is None:
            data = await self._get_json("/user")
            self._credential_login = data.get("login", "")
        return self._credential_login

    def _source(self, kind: SourceKind, id: str, author: str, tier: AuthorTier) -> Source:
        return Source(system=self._system, kind=kind, id=id, author=author, author_tier=tier)

    async def _last_commit_author(
        self, repo: str, path: str, ref: str, roster: _Roster
    ) -> tuple[str, AuthorTier]:
        """The forge login of the last commit that touched `path`, if any."""
        commits = await self._get_json(
            f"/repos/{repo}/commits",
            params={"sha": ref, "path": path, "limit": 1},
        )
        if not commits:
            return "", "unknown"
        author = commits[0].get("author") or {}
        login = author.get("login", "")
        if not login:
            # A commit whose author is a name and email with no forge account.
            return "", "unknown"
        return login, roster.tier(login)

    # -- reads -------------------------------------------------------------

    async def list_repos(self, org: str) -> list[Repo]:
        # One page of 50, and `X-Total-Count` is not read, so a larger org would
        # be reported as the first 50 with nothing saying so. Same for the issue
        # and comment reads below. Paging belongs with the seeding work, where
        # the number of repos a scenario needs is known.
        roster = await self._roster(org)
        data = await self._get_json(f"/orgs/{org}/repos", params={"limit": 50}) or []
        return [self._repo_from(item, roster) for item in data]

    async def list_issues(self, repo: str, state: str = "open") -> list[Issue]:
        owner, _ = split_repo(repo)
        if state not in ("open", "closed", "all"):
            raise ForgeError(f"state must be open, closed, or all, not {state!r}")
        roster = await self._roster(owner, repo)
        data = (
            await self._get_json(
                f"/repos/{repo}/issues",
                params={"state": state, "type": "issues", "limit": 50},
            )
            or []
        )
        return [self._issue_from(item, repo, roster) for item in data]

    async def get_issue(self, repo: str, number: int) -> Issue:
        owner, _ = split_repo(repo)
        item = await self._get_json(f"/repos/{repo}/issues/{number}")
        roster = await self._roster(owner, repo)
        comments = (
            await self._get_json(f"/repos/{repo}/issues/{number}/comments", params={"limit": 50})
            or []
        )
        issue = self._issue_from(item, repo, roster)
        issue.comments = [self._comment_from(comment, repo, number, roster) for comment in comments]
        return issue

    async def get_file(self, repo: str, path: str, ref: str = "main") -> FileContent:
        owner, _ = split_repo(repo)
        item = await self._get_json(f"/repos/{repo}/contents/{path}", params={"ref": ref})
        if isinstance(item, list):
            raise ForgeError(f"{path!r} is a directory in {repo}, not a file")
        roster = await self._roster(owner, repo)
        content = _decode_content(item)
        author, tier = await self._last_commit_author(repo, item.get("path", path), ref, roster)
        return FileContent(
            path=item.get("path", path),
            ref=ref,
            content=content,
            sha=item.get("sha"),
            source=self._source("file", f"{repo}:{item.get('path', path)}@{ref}", author, tier),
        )

    async def search_code(self, repo: str, query: str) -> SearchResult:
        owner, _ = split_repo(repo)
        if not query:
            raise ForgeError("query must not be empty")
        repo_info = await self._get_json(f"/repos/{repo}")
        ref = repo_info.get("default_branch") or "main"
        tree = await self._get_json(
            f"/repos/{repo}/git/trees/{ref}",
            params={"recursive": "true", "per_page": 1000},
        )
        entries = [entry for entry in (tree.get("tree") or []) if entry.get("type") == "blob"]
        truncated = bool(tree.get("truncated"))
        if len(entries) > self._max_blobs:
            entries = entries[: self._max_blobs]
            truncated = True

        roster = await self._roster(owner, repo)
        needles = query.lower()
        authors: dict[str, tuple[str, AuthorTier]] = {}
        matches: list[CodeMatch] = []
        for entry in entries:
            blob = await self._get_json(f"/repos/{repo}/git/blobs/{entry['sha']}")
            text = _decode_blob(blob)
            for number, line in enumerate(text.splitlines(), start=1):
                if needles not in line.lower():
                    continue
                path = entry.get("path", "")
                if path not in authors:
                    authors[path] = await self._last_commit_author(repo, path, ref, roster)
                author, tier = authors[path]
                matches.append(
                    CodeMatch(
                        path=path,
                        line=number,
                        snippet=line.strip()[:DEFAULT_MAX_SNIPPET],
                        source=self._source("file", f"{repo}:{path}@{ref}", author, tier),
                    )
                )
                if len(matches) >= self._max_matches:
                    truncated = True
                    break
            if len(matches) >= self._max_matches:
                break
        return SearchResult(query=query, matches=matches, truncated=truncated)

    # -- writes ------------------------------------------------------------

    async def create_issue_comment(self, repo: str, number: int, body: str) -> Comment:
        owner, _ = split_repo(repo)
        item = await self._json(
            "POST",
            f"/repos/{repo}/issues/{number}/comments",
            json={"body": body},
        )
        roster = await self._roster(owner, repo)
        return self._comment_from(item, repo, number, roster)

    async def create_branch(self, repo: str, name: str, from_ref: str = "main") -> Branch:
        owner, _ = split_repo(repo)
        item = await self._json(
            "POST",
            f"/repos/{repo}/branches",
            json={"new_branch_name": name, "old_branch_name": from_ref},
        )
        login = await self._credential_user()
        roster = await self._roster(owner, repo)
        commit = item.get("commit") or {}
        sha = commit.get("id") or commit.get("sha") or ""
        return Branch(
            name=item.get("name", name),
            sha=sha,
            source=self._source("repo", f"{repo}:{name}", login, roster.tier(login)),
        )

    async def commit_file(
        self, repo: str, branch: str, path: str, content: str, message: str
    ) -> Commit:
        owner, _ = split_repo(repo)
        payload: dict[str, Any] = {
            "branch": branch,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "message": message,
        }
        existing = await self._client.get(
            f"/api/v1/repos/{repo}/contents/{path}", params={"ref": branch}
        )
        if existing.status_code == 200 and isinstance(existing.json(), list):
            raise ForgeError(f"{path!r} is a directory in {repo}, not a file")
        if existing.status_code == 200:
            payload["sha"] = existing.json().get("sha")
            item = await self._json("PUT", f"/repos/{repo}/contents/{path}", json=payload)
        elif existing.status_code == 404:
            item = await self._json("POST", f"/repos/{repo}/contents/{path}", json=payload)
        else:
            raise ForgeError(
                f"gitea GET /repos/{repo}/contents/{path}?ref={branch} -> "
                f"HTTP {existing.status_code}: {_error_message(existing)}"
            )
        login = await self._credential_user()
        roster = await self._roster(owner, repo)
        commit = item.get("commit") or {}
        return Commit(
            sha=commit.get("sha", ""),
            path=(item.get("content") or {}).get("path", path),
            branch=branch,
            message=message,
            html_url=commit.get("html_url", ""),
            source=self._source("file", f"{repo}:{path}@{branch}", login, roster.tier(login)),
        )

    async def open_pull_request(
        self, repo: str, head: str, base: str, title: str, body: str
    ) -> PullRequest:
        owner, _ = split_repo(repo)
        item = await self._json(
            "POST",
            f"/repos/{repo}/pulls",
            json={"head": head, "base": base, "title": title, "body": body},
        )
        login = await self._credential_user()
        roster = await self._roster(owner, repo)
        number = item.get("number", 0)
        return PullRequest(
            number=number,
            title=item.get("title", title),
            body=item.get("body") or body,
            head=head,
            base=base,
            state=item.get("state", "open"),
            html_url=item.get("html_url", ""),
            source=self._source("issue", f"{repo}#{number}", login, roster.tier(login)),
        )

    async def set_repo_visibility(self, repo: str, visibility: Visibility) -> Repo:
        if visibility not in ("public", "private"):
            raise ForgeError(f"visibility must be public or private, not {visibility!r}")
        item = await self._json(
            "PATCH",
            f"/repos/{repo}",
            json={"private": visibility == "private"},
        )
        owner, _ = split_repo(repo)
        return self._repo_from(item, await self._roster(owner, repo))

    # -- shaping -----------------------------------------------------------

    def _repo_from(self, item: dict[str, Any], roster: _Roster) -> Repo:
        full_name = item.get("full_name", item.get("name", ""))
        owner = (item.get("owner") or {}).get("login", "")
        return Repo(
            name=item.get("name", ""),
            full_name=full_name,
            description=item.get("description") or "",
            private=bool(item.get("private")),
            default_branch=item.get("default_branch") or "main",
            html_url=item.get("html_url") or "",
            # The author of a repo is its owner, and its tier is that login's
            # tier in the org, the same rule the other records use. It is not
            # hardcoded to `owner`: an org-owned repo has the org as its owner,
            # and an org is not a member of its own owner team, so the honest
            # answer there is `unknown` rather than a tier nothing granted.
            source=self._source("repo", full_name, owner, roster.tier(owner)),
        )

    def _issue_from(self, item: dict[str, Any], repo: str, roster: _Roster) -> Issue:
        author = (item.get("user") or {}).get("login", "")
        number = item.get("number", 0)
        labels = [label.get("name", "") for label in item.get("labels") or []]
        return Issue(
            number=number,
            title=item.get("title", ""),
            body=item.get("body") or "",
            state=item.get("state", "open"),
            author=author,
            author_membership=roster.membership(author),
            labels=labels,
            html_url=item.get("html_url") or "",
            source=self._source("issue", f"{repo}#{number}", author, roster.tier(author)),
        )

    def _comment_from(
        self, item: dict[str, Any], repo: str, number: int, roster: _Roster
    ) -> Comment:
        author = (item.get("user") or {}).get("login", "")
        comment_id = item.get("id", 0)
        return Comment(
            id=str(comment_id),
            body=item.get("body") or "",
            author=author,
            author_membership=roster.membership(author),
            created_at=item.get("created_at"),
            source=self._source(
                "comment", f"{repo}#{number}/comment/{comment_id}", author, roster.tier(author)
            ),
        )


def _decode_content(item: dict[str, Any]) -> str:
    """Decode a contents API payload to text.

    Gitea returns base64 for a file under `content` with `encoding: base64`.
    A submodule or a symlink is not text, and decoding it to mojibake would be
    worse than saying so, so the caller gets an empty string for a non-file.
    """
    if item.get("type") != "file":
        return ""
    if item.get("encoding") == "base64":
        raw = base64.b64decode(item.get("content") or "")
        return raw.decode("utf-8", errors="replace")
    return item.get("content") or ""


def _decode_blob(blob: dict[str, Any]) -> str:
    if blob.get("encoding") == "base64":
        raw = base64.b64decode(blob.get("content") or "")
        return raw.decode("utf-8", errors="replace")
    return blob.get("content") or ""


def _error_message(response: httpx.Response) -> str:
    """The forge's own error text, without ever touching the credential."""
    try:
        payload = response.json()
    except ValueError:
        return response.text.strip()[:200]
    if isinstance(payload, dict):
        message = payload.get("message") or payload.get("error")
        if message:
            return str(message)[:200]
    return response.text.strip()[:200]
