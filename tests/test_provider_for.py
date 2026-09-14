"""The `WARRANT_MODEL` spec and the route table behind `provider_for`."""

from __future__ import annotations

import pytest

from agents.providers import (
    DEFAULT_SPEC,
    OpenAICompatProvider,
    ProviderSettings,
    parse_spec,
    provider_for,
)


def test_parse_spec_reads_all_three_parts() -> None:
    assert parse_spec("deepseek:deepseek-flash@high") == ("deepseek", "deepseek-flash", "high")


def test_parse_spec_defaults_the_effort_to_off() -> None:
    assert parse_spec("deepseek:deepseek-flash") == ("deepseek", "deepseek-flash", "off")


@pytest.mark.parametrize(
    "spec",
    ["deepseek-flash", "deepseek:", ":deepseek-flash@off", "deepseek:deepseek-flash@medium"],
)
def test_parse_spec_refuses_a_bad_spec(spec: str) -> None:
    with pytest.raises(ValueError):
        parse_spec(spec)


def test_provider_for_builds_the_route(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-not-a-secret")

    provider = provider_for("deepseek:deepseek-flash@high")

    assert isinstance(provider, OpenAICompatProvider)
    assert provider.name == "deepseek"
    assert provider.base_url == "https://api.deepseek.com"
    assert provider.model == "deepseek-flash"
    assert provider.effort == "high"


def test_provider_for_defaults_to_the_project_spec(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-not-a-secret")

    provider = provider_for(settings=ProviderSettings(warrant_model=DEFAULT_SPEC))

    assert provider.model == "deepseek-flash"
    assert provider.effort == "off"


def test_provider_for_refuses_an_unknown_route(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-not-a-secret")

    with pytest.raises(ValueError, match="no provider route"):
        provider_for("nobody:some-model@off")


def test_provider_for_refuses_a_missing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    settings = ProviderSettings(deepseek_api_key="", warrant_model=DEFAULT_SPEC)

    with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
        provider_for(settings=settings)
