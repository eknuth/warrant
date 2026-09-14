"""A provider over an OpenAI-compatible chat completions endpoint.

The endpoint is configured by `base_url` and `api_key`, so the same class
serves any vendor that speaks the chat completions shape. The vendor-specific
parts are the thinking toggle and its effort levels; both are built in
`request_fields`, which is what the mocked-transport tests read on the wire.

What the wire looks like, from the vendor's own current documentation:

- The thinking toggle travels inside `extra_body` as `{"thinking": {"type":
  "enabled"}}` or `{"thinking": {"type": "disabled"}}`. It is not a parameter
  the OpenAI SDK has a name for.
- The effort travels as the top-level `reasoning_effort` field, next to
  `thinking` in the body. `off` sends no effort at all.
- `reasoning_content` comes back beside `content` on the assistant message.
  This provider logs it and never puts it on the next request; see
  `agents/providers/base.py` for why.

Parallel tool calls arrive as several entries in `message.tool_calls` on one
reply, so they are returned as several `ToolUse` blocks on one turn. A reply
that hit the output limit carries `finish_reason == "length"`; the provider
warns and returns the partial turn rather than pretending it is complete.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from openai import AsyncOpenAI

from .base import ToolSchema, ToolUse, Turn, Usage

logger = logging.getLogger(__name__)

EFFORTS = ("off", "low", "high", "max")

# The vendor's mapping table accepts more names than the project uses, and
# collapses several of them onto two real levels. Warrant names the four levels
# it reports on and refuses anything else, so a typo in `WARRANT_MODEL` stops
# the run instead of silently landing on a default.
THINKING_DISABLED = {"type": "disabled"}
THINKING_ENABLED = {"type": "enabled"}


def request_fields(effort: str) -> dict[str, Any]:
    """The request keywords one effort level adds.

    `off` disables thinking and sends no effort. The other three enable thinking
    and name the effort. The result is merged into the SDK call as keyword
    arguments, which is what makes `extra_body` land at the body's top level.
    """
    if effort == "off":
        return {"extra_body": {"thinking": dict(THINKING_DISABLED)}}
    if effort not in EFFORTS:
        raise ValueError(f"effort must be one of {EFFORTS}, not {effort!r}")
    return {
        "reasoning_effort": effort,
        "extra_body": {"thinking": dict(THINKING_ENABLED)},
    }


def wire_tools(tools: list[ToolSchema]) -> list[dict[str, Any]]:
    """The `tools` array in the body, one function entry per tool."""
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.input_schema,
            },
        }
        for tool in tools
    ]


def wire_messages(messages: list[Turn]) -> list[dict[str, Any]]:
    """The `messages` array in the body.

    Tool results become one `tool` message each, keyed by the id the model used.
    An assistant turn is rebuilt from `text` and `tool_uses`, which is exactly
    what drops `reasoning_content`: the neutral turn keeps the reasoning for the
    log and this function cannot emit it.
    """
    wire: list[dict[str, Any]] = []
    for turn in messages:
        if turn.role == "system":
            wire.append({"role": "system", "content": turn.text or ""})
        elif turn.role == "assistant":
            message: dict[str, Any] = {"role": "assistant", "content": turn.text}
            if turn.tool_uses:
                message["tool_calls"] = [
                    {
                        "id": use.id,
                        "type": "function",
                        "function": {
                            "name": use.name,
                            "arguments": json.dumps(use.args, separators=(",", ":")),
                        },
                    }
                    for use in turn.tool_uses
                ]
            wire.append(message)
        else:
            for block in turn.tool_results:
                wire.append(
                    {
                        "role": "tool",
                        "tool_call_id": block.tool_use_id,
                        "content": block.content,
                    }
                )
            if turn.text is not None:
                wire.append({"role": "user", "content": turn.text})
    return wire


def usage_from(raw: Any) -> Usage | None:
    """The billed token counts from the reply, across the two shapes seen.

    One endpoint reports the cached prompt read at the top level and another
    under `prompt_tokens_details`, so both are read and the first present wins.
    """
    if raw is None:
        return None
    prompt_details = getattr(raw, "prompt_tokens_details", None)
    completion_details = getattr(raw, "completion_tokens_details", None)
    cache_read = getattr(raw, "prompt_cache_hit_tokens", None)
    if cache_read is None:
        cache_read = getattr(prompt_details, "cached_tokens", 0)
    return Usage(
        input_tokens=getattr(raw, "prompt_tokens", 0) or 0,
        output_tokens=getattr(raw, "completion_tokens", 0) or 0,
        cache_read_tokens=cache_read or 0,
        reasoning_tokens=getattr(completion_details, "reasoning_tokens", 0) or 0,
    )


def parse_tool_uses(message: Any) -> list[ToolUse]:
    """Every tool call on one assistant message.

    Arguments that are not a JSON object are refused here rather than at the
    tool: the call is kept with empty arguments and `malformed` set, so the loop
    still answers it and the model sees the tool's own complaint.
    """
    uses: list[ToolUse] = []
    for call in getattr(message, "tool_calls", None) or []:
        raw = call.function.arguments
        malformed = False
        try:
            args = json.loads(raw) if raw else {}
            if not isinstance(args, dict):
                raise ValueError("arguments are not a JSON object")
        except (TypeError, ValueError) as error:
            logger.warning(
                "tool call %s carried arguments that are not a JSON object: %r (%s)",
                call.function.name,
                raw,
                error,
            )
            args, malformed = {}, True
        uses.append(ToolUse(id=call.id, name=call.function.name, args=args, malformed=malformed))
    return uses


class OpenAICompatProvider:
    """`Provider` over one OpenAI-compatible chat completions endpoint."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        effort: str,
        *,
        name: str = "openai-compat",
        client: Any | None = None,
        http_client: Any | None = None,
        timeout: float = 300.0,
        max_tokens: int | None = None,
    ) -> None:
        if effort not in EFFORTS:
            raise ValueError(f"effort must be one of {EFFORTS}, not {effort!r}")
        if not api_key:
            raise ValueError("an API key is required; add it to .env")
        self.name = name
        self.model = model
        self.effort = effort
        self.base_url = base_url.rstrip("/")
        self._max_tokens = max_tokens
        self._client = client or AsyncOpenAI(
            base_url=self.base_url,
            api_key=api_key,
            http_client=http_client,
            timeout=timeout,
        )

    async def run(self, messages: list[Turn], tools: list[ToolSchema]) -> Turn:
        """One completion, translated back into a neutral assistant turn."""
        fields = request_fields(self.effort)
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": wire_messages(messages),
        }
        if tools:
            kwargs["tools"] = wire_tools(tools)
        if self._max_tokens is not None:
            kwargs["max_completion_tokens"] = self._max_tokens
        kwargs.update(fields)

        response = await self._client.chat.completions.create(**kwargs)
        choice = response.choices[0]
        message = choice.message

        reasoning = getattr(message, "reasoning_content", None)
        if reasoning:
            # Logged here and nowhere else on purpose. It is the model's own
            # account of the turn, useful to a run reader, and it is not sent
            # back on the next request.
            logger.info("assistant reasoning: %s", reasoning)

        if choice.finish_reason == "length":
            logger.warning("the reply hit the output limit and was cut off; the turn is partial")

        return Turn(
            role="assistant",
            text=message.content,
            tool_uses=parse_tool_uses(message),
            reasoning=reasoning,
            finish_reason=choice.finish_reason,
            usage=usage_from(getattr(response, "usage", None)),
        )
