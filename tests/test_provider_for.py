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


def test_parse_spec_reads_a_model_id_that_contains_a_colon() -> None:
    """The local model id has a colon, and the route splits on the first only."""
    assert parse_spec("qwen-local:qwen3.8:27b@off") == ("qwen-local", "qwen3.8:27b", "off")


@pytest.mark.parametrize(
    "spec",
    ["deepseek-flash", "deepseek:", ":deepseek-flash@off", "deepseek:deepseek-flash@medium"],
)
def test_parse_spec_refuses_a_bad_spec(spec: str) -> None:
    with pytest.raises(ValueError):
        parse_spec(spec)


def test_provider_for_builds_the_keyless_local_route(monkeypatch: pytest.MonkeyPatch) -> None:
    """The local route is a row in the same table and needs no key in `.env`."""
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    provider = provider_for("qwen-local:qwen3.8:27b@off")

    assert isinstance(provider, OpenAICompatProvider)
    assert provider.name == "qwen-local"
    assert provider.base_url == "http://localhost:11434/v1"
    assert provider.model == "qwen3.8:27b"
    assert provider.effort == "off"


def test_provider_for_builds_the_route(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-not-a-secret")

    provider = provider_for("deepseek:deepseek-flash@high")

    assert isinstance(provider, OpenAICompatProvider)
    assert provider.name == "deepseek"
    assert provider.base_url == "https://api.deepseek.com"
    assert provider.model == "deepseek-flash"
    assert provider.effort == "high"


def test_provider_for_carries_the_output_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-not-a-secret")

    provider = provider_for("deepseek:deepseek-flash@max", max_tokens=1234)

    assert provider._max_tokens == 1234


def test_provider_for_carries_the_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-not-a-secret")

    provider = provider_for("deepseek:deepseek-flash@max", timeout=42.0)

    assert provider._client.timeout == 42.0


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
