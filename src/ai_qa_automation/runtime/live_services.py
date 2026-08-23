from __future__ import annotations

from dataclasses import dataclass

from .coherent_control import CoherentRuntimeControl
from .internal_tools import RuntimeServices


@dataclass
class LiveRuntimeServices(RuntimeServices):
    """RuntimeServices adapter whose live tool accounting is owned by PreToolUse.

    Internal tool implementations still call ``consume`` as an execution
    checkpoint, but they no longer maintain an independent budget/repetition
    authority. The hook-owned RuntimeControl covers internal and external tools
    uniformly and this adapter mirrors its charged request count into canonical
    run state.
    """

    control: CoherentRuntimeControl | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.control is None:
            raise ValueError("live runtime services require RuntimeControl")

    def consume(self, tool_name: str, tool_input: dict[str, object]) -> None:
        del tool_name, tool_input
        if self.control is None:  # pragma: no cover - guarded by __post_init__
            raise RuntimeError("live runtime services lost RuntimeControl")
        self.state.tool_call_count = self.control.budget.snapshot().tool_calls
        self.checkpoint()
