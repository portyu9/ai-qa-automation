from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..models import TerminalStatus, ValidationResult, ValidationStatus
from .internal_tools import RuntimeServices, _pytest_scope, _stable_gate_id
from .mutation_lineage import build_rollback_lineage_checkpoints
from .run_control import RuntimeControl
from .tool_input_bounds import validate_tool_request


@dataclass
class LiveRuntimeServices(RuntimeServices):
    """RuntimeServices adapter whose live tool accounting is owned by PreToolUse.

    Internal tool implementations still call ``consume`` as an execution
    checkpoint, but they do not maintain an independent live budget/repetition
    authority. Canonical RuntimeControl covers internal and external SDK tool
    requests uniformly; this adapter only mirrors that charged request count into
    AgentRunState while preserving standalone RuntimeServices behavior elsewhere.

    Target-controlled pytest code is additionally fail-closed unless trusted
    deployment infrastructure explicitly asserts both process/filesystem
    containment and outbound-egress enforcement. These booleans are prerequisite
    assertions only; they do not implement the isolation themselves.
    """

    control: RuntimeControl | None = None
    pytest_process_isolation_enforced: bool = False
    pytest_external_egress_enforced: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.control is None:
            raise ValueError("live runtime services require RuntimeControl")
        if self.state_store is None:
            raise ValueError("live runtime services require durable StateStore authority")
        if self.workspace_root_identity is None:
            raise ValueError("live runtime services require a lease-bound workspace_root_identity")
        for name, value in {
            "pytest_process_isolation_enforced": self.pytest_process_isolation_enforced,
            "pytest_external_egress_enforced": self.pytest_external_egress_enforced,
        }.items():
            if not isinstance(value, bool):
                raise ValueError(f"{name} must be a boolean")

        before_close, after_close = build_rollback_lineage_checkpoints(
            self.state,
            self.state_store,
        )
        self.control.rollback_lineage_before_close = before_close
        self.control.rollback_lineage_after_close = after_close

    def pytest_execution_block_reason(self) -> str | None:
        missing: list[str] = []
        if not self.pytest_process_isolation_enforced:
            missing.append("process/filesystem isolation")
        if not self.pytest_external_egress_enforced:
            missing.append("outbound-egress enforcement")
        if not missing:
            return None
        return (
            "pytest target-code execution requires trusted deployment enforcement for "
            + " and ".join(missing)
            + "; configuration flags are prerequisite assertions, not sandbox implementations"
        )

    def consume(self, tool_name: str, tool_input: dict[str, Any]) -> None:
        if self.control is None:  # pragma: no cover - guarded by __post_init__
            raise RuntimeError("live runtime services lost RuntimeControl")

        # Defense in depth for direct live-service invocation. Normal SDK execution
        # is rejected earlier by PreToolUse before request fingerprinting or budget
        # mutation, but a tool body may never receive an unbounded input even when
        # invoked outside that hook path.
        validate_tool_request(tool_name, tool_input)

        # PreToolUse already charged the canonical runtime budget. Mirror that
        # authority before any tool-specific fail-closed return so persisted
        # AgentRunState cannot undercount a blocked request.
        self.state.tool_call_count = self.control.budget.snapshot().tool_calls

        if tool_name == "run_pytest":
            reason = self.pytest_execution_block_reason()
            if reason is not None:
                pytest_args = [str(item) for item in (tool_input.get("args") or [])]
                self.state.validation_results.append(
                    ValidationResult(
                        name="pytest",
                        gate_id=_stable_gate_id("pytest", pytest_args),
                        revision=self.state.change_revision,
                        status=ValidationStatus.BLOCKED,
                        summary=reason,
                        details={
                            "scope": _pytest_scope(pytest_args),
                            "args": pytest_args,
                            "execution_started": False,
                            "process_isolation_enforced": self.pytest_process_isolation_enforced,
                            "external_egress_enforced": self.pytest_external_egress_enforced,
                        },
                    )
                )
                self.state.terminal_status = TerminalStatus.BLOCKED
                self.state.terminal_reason = reason
                self.checkpoint()
                raise PermissionError(reason)

        self.checkpoint()
