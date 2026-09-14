"""Unit tests for the forge's argument handling, with no server.

Everything here runs before a network call, so it needs no stack.
"""

from __future__ import annotations

import pytest

from servers.gitea_mcp.forge import ForgeError, GiteaForge, split_repo


def test_split_repo_requires_exactly_owner_and_name() -> None:
    assert split_repo("acme/demo") == ("acme", "demo")


@pytest.mark.parametrize("repo", ["demo", "", "/demo", "acme/", "acme/demo/extra", "acme/demo/"])
def test_split_repo_refuses_anything_else(repo: str) -> None:
    with pytest.raises(ForgeError):
        split_repo(repo)


def test_gitea_forge_refuses_to_start_without_a_token() -> None:
    with pytest.raises(ForgeError):
        GiteaForge("http://localhost:3000", "")
