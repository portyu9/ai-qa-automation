from __future__ import annotations

from dataclasses import dataclass, field

from .run_control import RuntimeControl


class RepeatedActionError(RuntimeError):
    """Raised when one identical authorized request exceeds its bounded repetition budget."""


@dataclass
class CoherentRuntimeControl(RuntimeControl):
    """Live RuntimeControl with one repetition authority for every SDK tool request.

    ExecutionBudget remains the authoritative multidimensional request budget.
    This adapter adds content-sensitive repetition tracking at the same PreToolUse
    boundary so internal and external MCP calls obey the same control path.
    """

    max_repeated_action: int = 3
    repeated_action_counts: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__post_init__()
        if type(self.max_repeated_action) is not int or self.max_repeated_action < 1:
            raise ValueError("max_repeated_action must be a positive integer")

    def register_tool_request(self, tool_name: str, input_fingerprint: str) -> None:
        """Apply circuit and repetition policy to one already-budget-charged request."""

        with self._lock:
            self.before_tool(tool_name)
            key = f"{tool_name}:{input_fingerprint}"
            seen = self.repeated_action_counts.get(key, 0)
            if seen >= self.max_repeated_action:
                raise RepeatedActionError(
                    f"repeated identical action budget exhausted for tool: {tool_name}"
                )
            self.repeated_action_counts[key] = seen + 1
            self.persist()

    def snapshot(self, *, include_pending_details: bool = False) -> dict[str, object]:
        with self._lock:
            payload = super().snapshot(include_pending_details=include_pending_details)
            payload["max_repeated_action"] = self.max_repeated_action
            payload["repeated_action_counts"] = dict(sorted(self.repeated_action_counts.items()))
            return payload
