"""The one model interface the agent loop speaks: messages in, tool use out.

The loop in `agents/triage.py` never imports a vendor SDK. It builds a neutral
list of `Turn` objects and hands it to a `Provider`, which translates them to
whatever its endpoint wants and translates the reply back into a `Turn`. A
provider for another chat-completions endpoint plugs in here and the loop does
not change.

The shape is the one this project's provider interface already uses, so a
provider written against that tree can be moved here unchanged: a `ToolSchema`
offered to the model, a `ToolUse` the model asks for, a `ToolResultBlock` on its
way back, and a `Turn` that carries whichever of those its role allows.

`Turn.reasoning` holds a provider's chain of thought. It is deliberately not
part of what a provider sends back. The vendor documents that a request carrying
tools must repeat `reasoning_content` or answer 400, and a live probe against
the cloud endpoint on 2026-09-13 showed the follow-up request accepted with the
field omitted, so the transcript keeps the reasoning in the run log and drops it
from the wire. `tests/test_provider_openai_compat.py` pins that omission.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

# A turn is a system instruction, something the user (or the loop) said, or
# something the model said. Tool results ride on a user turn rather than a role
# of their own, so the transcript stays provider-neutral; a provider that wants
# one message per result splits the turn when it converts.
Role = Literal["system", "user", "assistant"]


@dataclass(frozen=True)
class ToolSchema:
    """One tool offered to the model."""

    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class ToolUse:
    """The model asking for one tool call."""

    id: str
    name: str
    args: dict[str, Any]
    malformed: bool = False
    """True when the provider could not trust the arguments as a JSON object.

    `args` is `{}` whenever this is set. The loop treats the call exactly like
    any other: it goes out with empty arguments, and the tool's own schema is
    what refuses it, through the same error path a well-formed but invalid call
    takes.
    """


@dataclass(frozen=True)
class ToolResultBlock:
    """The answer to one `ToolUse`, on its way back to the model."""

    tool_use_id: str
    content: str
    is_error: bool = False


@dataclass(frozen=True)
class Usage:
    """Tokens billed for one completion.

    `cache_read_tokens` is counted apart because a cached prompt read is billed
    at a fraction of a fresh input token. `reasoning_tokens` is a subset of the
    output tokens and is kept only for the run record.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    reasoning_tokens: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_read_tokens=self.cache_read_tokens + other.cache_read_tokens,
            reasoning_tokens=self.reasoning_tokens + other.reasoning_tokens,
        )


@dataclass
class Turn:
    """One entry in the neutral transcript.

    A user turn carries either `text` or `tool_results`. A system turn carries
    the instructions. An assistant turn carries `text` and `tool_uses`, plus the
    provider's own `reasoning`, `finish_reason`, and `usage` for the log.
    """

    role: Role
    text: str | None = None
    tool_uses: list[ToolUse] = field(default_factory=list)
    tool_results: list[ToolResultBlock] = field(default_factory=list)
    reasoning: str | None = None
    finish_reason: str | None = None
    usage: Usage | None = None


@runtime_checkable
class Provider(Protocol):
    """Messages in, tool use out. Every provider is async and stateless."""

    name: str
    model: str
    effort: str

    async def run(self, messages: list[Turn], tools: list[ToolSchema]) -> Turn:
        """One turn of the conversation."""
        ...
