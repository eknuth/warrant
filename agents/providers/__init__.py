"""Model providers, one neutral interface over the chat-completions endpoints.

`provider_for` turns the `WARRANT_MODEL` spec `provider:model@effort` into a
provider. The route table below is the whole registry: a new endpoint is one
row naming its base URL and the environment variable its key is read from. Only
the OpenAI-compatible shape is implemented, so the provider class is the same
for every row; a vendor with a different shape adds a class beside
`OpenAICompatProvider`.

The key is read the way the rest of this repository reads one, through a
pydantic settings object whose `env_file` is `.env`, so a run needs no exported
shell variable. A value already in the environment still wins, which is what
`pydantic-settings` does by default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from pydantic_settings import BaseSettings, SettingsConfigDict

from .base import Provider, ToolResultBlock, ToolSchema, ToolUse, Turn, Usage
from .openai_compat import EFFORTS, OpenAICompatProvider

# The spec the project runs when nothing overrides it. `off` costs the least and
# is what day-one triage uses; the evals raise it per scenario.
DEFAULT_SPEC = "deepseek:deepseek-flash@off"


@dataclass(frozen=True)
class Route:
    """Where one provider name sends its requests and where its key lives."""

    base_url: str
    key_env: str


ROUTES: dict[str, Route] = {
    "deepseek": Route(base_url="https://api.deepseek.com", key_env="DEEPSEEK_API_KEY"),
}


class ProviderSettings(BaseSettings):
    """What the provider layer reads from the environment and `.env`."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    warrant_model: str = DEFAULT_SPEC
    deepseek_api_key: str = ""


def parse_spec(spec: str) -> tuple[str, str, str]:
    """Split `provider:model@effort` into its three parts.

    The effort suffix is optional and defaults to `off`. A spec with no colon,
    no model, or an unknown effort is refused here rather than at request time.
    """
    provider, separator, rest = spec.partition(":")
    if not separator or not provider or not rest:
        raise ValueError(f"model spec must be 'provider:model@effort', not {spec!r}")
    model, at, effort = rest.partition("@")
    if not model:
        raise ValueError(f"model spec names no model: {spec!r}")
    effort = effort if at else "off"
    if effort not in EFFORTS:
        raise ValueError(f"effort in {spec!r} must be one of {EFFORTS}, not {effort!r}")
    return provider, model, effort


def provider_for(
    spec: str | None = None,
    *,
    settings: ProviderSettings | None = None,
    max_tokens: int | None = None,
    timeout: float | None = None,
) -> OpenAICompatProvider:
    """Build the provider a spec names, or the one `WARRANT_MODEL` names.

    `max_tokens` is the per-request output cap and `timeout` the client's own
    read timeout. The adjudicator sets both; the agent loop leaves them unset
    and the endpoint's defaults apply.
    """
    settings = settings or ProviderSettings()
    provider_name, model, effort = parse_spec(spec or settings.warrant_model)
    route = ROUTES.get(provider_name)
    if route is None:
        raise ValueError(
            f"no provider route for {provider_name!r}; known routes are {sorted(ROUTES)}"
        )
    api_key = getattr(settings, route.key_env.lower(), "") or os.environ.get(route.key_env, "")
    if not api_key:
        raise ValueError(f"{route.key_env} is not set; add it to .env")
    return OpenAICompatProvider(
        route.base_url,
        api_key,
        model,
        effort,
        name=provider_name,
        max_tokens=max_tokens,
        **({"timeout": timeout} if timeout is not None else {}),
    )


__all__ = [
    "DEFAULT_SPEC",
    "EFFORTS",
    "ROUTES",
    "OpenAICompatProvider",
    "Provider",
    "ProviderSettings",
    "Route",
    "ToolResultBlock",
    "ToolSchema",
    "ToolUse",
    "Turn",
    "Usage",
    "parse_spec",
    "provider_for",
]
