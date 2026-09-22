"""`Forge` over `api.github.com`, for the throwaway org the recording runs on.

`server.py` builds this when `FORGE=github`. It returns the same models
`GiteaForge` does and the tool layer above it is unchanged, so the recording
shows the 2025 GitHub MCP shape without moving a single tool name, policy, or
scenario. `Source.system` is `github`; the rules that read a repo path accept
both systems (see `warrant.provenance` and `warrant.taint`).

Three GitHub facts shape this file:

- Membership is two facts, not one. `GET /orgs/{org}/members/{user}` answers
  204 for a member and 404 for anyone else, and `GET /orgs/{org}/memberships/{user}`
  carries the role, with `admin` being the owner team. The tier is the combine
  of the two.
- The contents API has no create-versus-update split: both go through `PUT`,
  and an update carries the existing blob sha.
- A primary rate limit is a `403` with `X-RateLimit-Remaining: 0` and
  `X-RateLimit-Reset` as epoch seconds. There is no point raising that to the
  caller, because waiting it out is the only move, so `_send` sleeps until the
  reset and retries.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from .forge import (
    DEFAULT_MAX_BLOBS,
    DEFAULT_MAX_MATCHES,
    DEFAULT_MAX_SNIPPET,
    ForgeError,
    _decode_blob,
    _decode_content,
    _error_message,
    split_repo,
)
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

logger = logging.getLogger("gitea_mcp.github")

# The public GitHub REST API. Overridable for a recorded transport or an
# enterprise host, but the shipped value is the one the recording uses.
GITHUB_API_URL = "https://api.github.com"

# The page size on every list read. GitHub caps at 100.
GITHUB_PER_PAGE = 100

# A sleep function, injectable so the rate-limit test does not wait.
Sleeper = Callable[[float], Awaitable[None]]


def rate_limit_delay(response: httpx.Response, *, now: float | None = None) -> float:
    """Seconds to wait before retrying a rate-limited response.

    `X-RateLimit-Reset` is epoch seconds, so the wait is the time left until
    it. `Retry-After` is the fallback for a 429 secondary limit, and a minute
    is the last resort. A reset already in the past is a zero wait: the limit
    is back and the retry should go now.
    """
    now = time.time() if now is None else now
    reset = response.headers.get("X-RateLimit-Reset")
    if reset and reset.strip().lstrip("-").isdigit():
        return max(0.0, float(reset) - now)
    retry = response.headers.get("Retry-After")
    if retry and retry.strip().isdigit():
        return float(retry)
    return 60.0


def is_rate_limited(response: httpx.Response) -> bool:
    """Whether GitHub refused this request because the primary limit is spent."""
    return response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0"


class GitHubForge:
    """`Forge` over one GitHub org and one admin credential.

    The credential is a fine-grained PAT or an app installation token with
    admin on the org, held on purpose the same way the Gitea admin token is. It
    is never logged, returned, or put in an error message.
    """

    def __init__(
        self,
        org: str,
        token: str,
        *,
        base_url: str = GITHUB_API_URL,
        system: str = "github",
        client: httpx.AsyncClient | None = None,
        max_blobs: int = DEFAULT_MAX_BLOBS,
        max_matches: int = DEFAULT_MAX_MATCHES,
        sleep: Sleeper = asyncio.sleep,
    ) -> None:
        if not token:
            raise ForgeError("a GitHub token is required")
        if not org:
            raise ForgeError("a GitHub org is required")
        self._org = org
        self._base_url = base_url.rstrip("/")
        self._system = system
        self._token = token
        self._max_blobs = max_blobs
        self._max_matches = max_matches
        self._sleep = sleep
        self._client = client or httpx.AsyncClient(
            base_url=self._base_url,
            headers=_github_headers(token),
            timeout=30.0,
        )
        self._owns_client = client is None
        self._credential_login: str | None = None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # -- HTTP plumbing -----------------------------------------------------

    async def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """One request, waiting out a spent primary rate limit and retrying."""
        while True:
            response = await self._client.request(method, path, **kwargs)
            if not is_rate_limited(response):
                return response
            delay = rate_limit_delay(response)
            logger.warning(
                "github rate limit spent on %s %s; sleeping %.1fs until reset",
                method,
                path,
                delay,
            )
            await self._sleep(delay)

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        response = await self._send(method, path, **kwargs)
        if response.status_code >= 400:
            raise ForgeError(
                f"github {method} {path} -> HTTP {response.status_code}: {_error_message(response)}"
            )
        return response

    async def _json(self, method: str, path: str, **kwargs: Any) -> Any:
        return (await self._request(method, path, **kwargs)).json()

    async def _get_json(self, path: str, **kwargs: Any) -> Any:
        return await self._json("GET", path, **kwargs)

    async def _paged(self, path: str, **params: Any) -> list[dict[str, Any]]:
        """Every page of one GitHub list endpoint."""
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            batch = await self._get_json(
                path, params={**params, "per_page": GITHUB_PER_PAGE, "page": page}
            )
            if not isinstance(batch, list):
                raise ForgeError(f"github GET {path} did not answer a list")
            items.extend(batch)
            if len(batch) < GITHUB_PER_PAGE:
                return items
            page += 1

    # -- provenance --------------------------------------------------------

    async def _is_member(self, org: str, login: str) -> bool:
        """204 is a member, 404 is not. Any other answer is a failure, not a tier."""
        response = await self._send("GET", f"/orgs/{org}/members/{login}")
        if response.status_code == 204:
            return True
        if response.status_code == 404:
            return False
        raise ForgeError(
            f"github GET /orgs/{org}/members/{login} -> HTTP {response.status_code}: "
            f"{_error_message(response)}"
        )

    async def _role(self, org: str, login: str) -> str:
        """`admin`, `member`, or an empty string when not in the org."""
        response = await self._send("GET", f"/orgs/{org}/memberships/{login}")
        if response.status_code == 200:
            return str(response.json().get("role") or "member")
        if response.status_code == 404:
            return ""
        raise ForgeError(
            f"github GET /orgs/{org}/memberships/{login} -> HTTP {response.status_code}: "
            f"{_error_message(response)}"
        )

    async def _tier(self, org: str, login: str) -> AuthorTier:
        if not login:
            return "unknown"
        if not await self._is_member(org, login):
            return "external"
        return "owner" if await self._role(org, login) == "admin" else "member"

    async def _is_collaborator(self, repo: str, login: str) -> bool:
        """204 is a collaborator, 404 is not."""
        if not login:
            return False
        response = await self._send("GET", f"/repos/{repo}/collaborators/{login}")
        if response.status_code == 204:
            return True
        if response.status_code == 404:
            return False
        raise ForgeError(
            f"github GET /repos/{repo}/collaborators/{login} -> HTTP {response.status_code}: "
            f"{_error_message(response)}"
        )

    async def _membership(self, org: str, repo: str | None, login: str) -> AuthorMembership:
        if not login:
            return "external"
        if await self._tier(org, login) in ("owner", "member"):
            return "member"
        if repo is not None and await self._is_collaborator(repo, login):
            return "collaborator"
        return "external"

    async def _credential_user(self) -> str:
        if self._credential_login is None:
            response = await self._send("GET", "/user")
            if response.status_code == 200:
                self._credential_login = str(response.json().get("login") or "")
            elif response.status_code in (401, 403, 404):
                # A GitHub App installation token has no user behind it, so the
                # author is unknown rather than a login nothing can resolve.
                self._credential_login = ""
            else:
                raise ForgeError(
                    f"github GET /user -> HTTP {response.status_code}: {_error_message(response)}"
                )
        return self._credential_login

    def _source(self, kind: SourceKind, id: str, author: str, tier: AuthorTier) -> Source:
        return Source(system=self._system, kind=kind, id=id, author=author, author_tier=tier)

    async def _last_commit_author(self, repo: str, path: str, ref: str) -> tuple[str, AuthorTier]:
        """The GitHub login of the last commit that touched `path`, if any."""
        owner, _ = split_repo(repo)
        commits = await self._get_json(
            f"/repos/{repo}/commits",
            params={"sha": ref, "path": path, "per_page": 1},
        )
        if not commits:
            return "", "unknown"
        author = commits[0].get("author") or {}
        login = str(author.get("login") or "")
        if not login:
            # A commit whose author is a name and email with no GitHub account.
            return "", "unknown"
        return login, await self._tier(owner, login)

    # -- reads -------------------------------------------------------------

    async def list_repos(self, org: str) -> list[Repo]:
        data = await self._paged(f"/orgs/{org}/repos")
        return [await self._repo_from(item, org) for item in data]

    async def list_issues(self, repo: str, state: str = "open") -> list[Issue]:
        owner, _ = split_repo(repo)
        if state not in ("open", "closed", "all"):
            raise ForgeError(f"state must be open, closed, or all, not {state!r}")
        data = await self._paged(f"/repos/{repo}/issues", state=state)
        # GitHub returns pull requests from the issues endpoint. An issue read
        # that answered with a PR would put a pull request's body where an
        # issue's belongs, so they are filtered out.
        issues = [item for item in data if "pull_request" not in item]
        return [await self._issue_from(item, repo, owner) for item in issues]

    async def get_issue(self, repo: str, number: int) -> Issue:
        owner, _ = split_repo(repo)
        item = await self._get_json(f"/repos/{repo}/issues/{number}")
        comments = await self._paged(f"/repos/{repo}/issues/{number}/comments")
        issue = await self._issue_from(item, repo, owner)
        issue.comments = [
            await self._comment_from(comment, repo, number, owner) for comment in comments
        ]
        return issue

    async def get_file(self, repo: str, path: str, ref: str = "main") -> FileContent:
        item = await self._get_json(f"/repos/{repo}/contents/{path}", params={"ref": ref})
        if isinstance(item, list):
            raise ForgeError(f"{path!r} is a directory in {repo}, not a file")
        content = _decode_content(item)
        author, tier = await self._last_commit_author(repo, item.get("path", path), ref)
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
            params={"recursive": "1"},
        )
        entries = [entry for entry in (tree.get("tree") or []) if entry.get("type") == "blob"]
        truncated = bool(tree.get("truncated"))
        if len(entries) > self._max_blobs:
            entries = entries[: self._max_blobs]
            truncated = True

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
                    authors[path] = await self._last_commit_author(repo, path, ref)
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
        return await self._comment_from(item, repo, number, owner)

    async def create_branch(self, repo: str, name: str, from_ref: str = "main") -> Branch:
        owner, _ = split_repo(repo)
        source = await self._get_json(f"/repos/{repo}/git/ref/heads/{from_ref}")
        sha = str((source.get("object") or {}).get("sha") or "")
        item = await self._json(
            "POST",
            f"/repos/{repo}/git/refs",
            json={"ref": f"refs/heads/{name}", "sha": sha},
        )
        login = await self._credential_user()
        tier = await self._tier(owner, login)
        branch = str(item.get("ref") or f"refs/heads/{name}").removeprefix("refs/heads/")
        return Branch(
            name=branch,
            sha=str((item.get("object") or {}).get("sha") or sha),
            source=self._source("repo", f"{repo}:{name}", login, tier),
        )

    async def commit_file(
        self, repo: str, branch: str, path: str, content: str, message: str
    ) -> Commit:
        owner, _ = split_repo(repo)
        existing = await self._send("GET", f"/repos/{repo}/contents/{path}", params={"ref": branch})
        payload: dict[str, Any] = {
            "branch": branch,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "message": message,
        }
        if existing.status_code == 200 and isinstance(existing.json(), list):
            raise ForgeError(f"{path!r} is a directory in {repo}, not a file")
        if existing.status_code == 200:
            payload["sha"] = existing.json().get("sha")
        elif existing.status_code != 404:
            raise ForgeError(
                f"github GET /repos/{repo}/contents/{path}?ref={branch} -> "
                f"HTTP {existing.status_code}: {_error_message(existing)}"
            )
        item = await self._json("PUT", f"/repos/{repo}/contents/{path}", json=payload)
        login = await self._credential_user()
        tier = await self._tier(owner, login)
        commit = item.get("commit") or {}
        return Commit(
            sha=commit.get("sha", ""),
            path=(item.get("content") or {}).get("path", path),
            branch=branch,
            message=message,
            html_url=commit.get("html_url", ""),
            source=self._source("file", f"{repo}:{path}@{branch}", login, tier),
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
        tier = await self._tier(owner, login)
        number = item.get("number", 0)
        return PullRequest(
            number=number,
            title=item.get("title", title),
            body=item.get("body") or body,
            head=head,
            base=base,
            state=item.get("state", "open"),
            html_url=item.get("html_url", ""),
            source=self._source("issue", f"{repo}#{number}", login, tier),
        )

    async def set_repo_visibility(self, repo: str, visibility: Visibility) -> Repo:
        if visibility not in ("public", "private"):
            raise ForgeError(f"visibility must be public or private, not {visibility!r}")
        owner, _ = split_repo(repo)
        item = await self._json(
            "PATCH",
            f"/repos/{repo}",
            json={"private": visibility == "private"},
        )
        return await self._repo_from(item, owner)

    # -- shaping -----------------------------------------------------------

    async def _repo_from(self, item: dict[str, Any], org: str) -> Repo:
        full_name = item.get("full_name", item.get("name", ""))
        owner = str((item.get("owner") or {}).get("login") or "")
        return Repo(
            name=item.get("name", ""),
            full_name=full_name,
            description=item.get("description") or "",
            private=bool(item.get("private")),
            default_branch=item.get("default_branch") or "main",
            html_url=item.get("html_url") or "",
            # The author of a repo is its owner. An org-owned repo has the org
            # as its owner, and an org is not a member of its own owner team, so
            # the honest tier there is `external` rather than a tier nothing
            # granted.
            source=self._source("repo", full_name, owner, await self._tier(org, owner)),
        )

    async def _issue_from(self, item: dict[str, Any], repo: str, org: str) -> Issue:
        author = str((item.get("user") or {}).get("login") or "")
        number = item.get("number", 0)
        labels = [label.get("name", "") for label in item.get("labels") or []]
        return Issue(
            number=number,
            title=item.get("title", ""),
            body=item.get("body") or "",
            state=item.get("state", "open"),
            author=author,
            author_membership=await self._membership(org, repo, author),
            labels=labels,
            html_url=item.get("html_url") or "",
            source=self._source("issue", f"{repo}#{number}", author, await self._tier(org, author)),
        )

    async def _comment_from(
        self, item: dict[str, Any], repo: str, number: int, org: str
    ) -> Comment:
        author = str((item.get("user") or {}).get("login") or "")
        comment_id = item.get("id", 0)
        tier = await self._tier(org, author)
        return Comment(
            id=str(comment_id),
            body=item.get("body") or "",
            author=author,
            author_membership=await self._membership(org, repo, author),
            created_at=item.get("created_at"),
            source=self._source("comment", f"{repo}#{number}/comment/{comment_id}", author, tier),
        )


def _github_headers(token: str) -> dict[str, str]:
    """The headers every GitHub call carries, without ever logging the token."""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
