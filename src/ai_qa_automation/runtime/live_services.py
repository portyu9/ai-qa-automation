from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .internal_tools import RuntimeServices
from .run_control import RuntimeControl


@dataclass
class LiveRuntimeServices(RuntimeServices):
    """RuntimeServices adapter whose live tool accounting is owned by PreToolUse.

    Internal tool implementations still call ``consume`` as an execution
    checkpoint, but they do not maintain an independent live budget/repetition
    authority. Canonical RuntimeControl covers internal and external SDK tool
    requests uniformly; this adapter only mirrors that charged request count into
    AgentRunState while preserving standalone RuntimeServices behavior elsewhere.
    """

    control: RuntimeControl | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.control is None:
            raise ValueError("live runtime services require RuntimeControl")

    def consume(self, tool_name: str, tool_input: dict[str, Any]) -> None:
        del tool_name, tool_input
        if self.control is None:  # pragma: no cover - guarded by __post_init__
            raise RuntimeError("live runtime services lost RuntimeControl")
        self.state.tool_call_count = self.control.budget.snapshot().tool_calls
        self.checkpoint()
