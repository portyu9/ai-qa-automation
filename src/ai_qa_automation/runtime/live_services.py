from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import TerminalStatus, ValidationResult, ValidationStatus
from .internal_tools import RuntimeServices, _pytest_scope, _stable_gate_id
from .k6_authority import k6_gate_payload, k6_persisted_subject
from .mutation_lineage import build_rollback_lineage_checkpoints
from .run_control import RuntimeControl
from .tool_input_bounds import validate_tool_request
from .workspace_freshness import WorkspaceFreshnessCode, observe_workspace_freshness

_LIVE_MUTATION_TOOL_NAMES = frozenset({"create_test_file", "apply_locator_heal"})


@dataclass
class LiveRuntimeServices(RuntimeServices):
    """Bind live internal execution to canonical runtime and workspace authority.

    Internal tool implementations still call ``consume`` as an execution
    checkpoint, but they do not maintain an independent live budget/repetition
    authority. Canonical RuntimeControl covers internal and external SDK tool
    requests uniformly; this adapter mirrors that charged request count while
    owning the target-subject checks that must occur immediately before an
    in-process internal tool body proceeds.

    Target-controlled pytest code is additionally fail-closed unless trusted
    deployment infrastructure explicitly asserts both process/filesystem
    containment and outbound-egress enforcement. These booleans are prerequisite
    assertions only; they do not implement the isolation themselves.

    Target-controlled k6 code is fail-closed at this live-service boundary until
    process/filesystem isolation, executable module-loading isolation, bounded
    runner resources, and bounded target workload authority are explicitly plumbed
    through trusted runtime configuration to the controlled runner. Egress
    configuration alone cannot authorize process spawn.
    """

    control: RuntimeControl | None = None
    pytest_process_isolation_enforced: bool = False
    pytest_external_egress_enforced: bool = False
    _active_tool_name: str | None = field(default=None, init=False, repr=False)

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

    def k6_execution_block_reason(self) -> str:
        missing = [
            "process/filesystem isolation",
            "module-loading isolation",
            "runner resource limits",
            "target workload limits",
        ]
        if not self.k6_external_egress_enforced:
            missing.append("outbound-egress enforcement")
        return (
            "k6 target-code execution requires trusted deployment enforcement for "
            + ", ".join(missing)
            + "; the current live runtime exposes only the outbound-egress assertion, "
            "not the process/filesystem, module-loading, runner-resource, or target-workload "
            "authority required by the controlled K6Runner"
        )

    def _require_workspace_freshness(self, *, stage: str, tool_name: str | None) -> None:
        if self.control is None or self.state_store is None:  # pragma: no cover - guarded above
            raise RuntimeError("live runtime services lost durable workspace authority")
        freshness = observe_workspace_freshness(
            self.workspace,
            expected_fingerprint=self.control.expected_workspace_fingerprint,
            expected_root_identity=self.workspace_root_identity,
        )
        if freshness.fresh:
            return

        if freshness.code is WorkspaceFreshnessCode.SUBJECT_UNAVAILABLE:
            status = TerminalStatus.INFRASTRUCTURE_FAILURE
            reason = (
                "Workspace freshness infrastructure could not revalidate the target subject safely."
            )
        elif freshness.code is WorkspaceFreshnessCode.FINGERPRINT_INCOMPLETE:
            status = TerminalStatus.BLOCKED
            reason = (
                "Workspace freshness is incomplete; live tool execution cannot bind the current "
                "target subject."
            )
        elif freshness.code is WorkspaceFreshnessCode.BASELINE_MISSING:
            status = TerminalStatus.BLOCKED
            reason = "Workspace freshness baseline is unavailable; live tool execution is denied."
        else:
            status = TerminalStatus.BLOCKED
            reason = "Target workspace changed outside the authorized runtime mutation lineage."

        if self.state.terminal_status in {None, TerminalStatus.SUCCESS}:
            self.state.terminal_status = status
            self.state.terminal_reason = reason
        self.control.journal.try_append(
            "workspace_freshness_denied",
            stage=stage,
            tool_name=tool_name,
            reason_code=freshness.code.value,
        )
        self.state_store.save(self.state)
        self.control.persist()
        raise PermissionError(reason)

    def checkpoint(self) -> None:
        """Persist tool state only while observations remain on the authorized subject."""

        if self._active_tool_name not in _LIVE_MUTATION_TOOL_NAMES:
            self._require_workspace_freshness(
                stage="tool_checkpoint",
                tool_name=self._active_tool_name,
            )
        super().checkpoint()

    def consume(self, tool_name: str, tool_input: dict[str, Any]) -> None:
        if self.control is None:  # pragma: no cover - guarded by __post_init__
            raise RuntimeError("live runtime services lost RuntimeControl")

        # Defense in depth for direct live-service invocation. A tool body may never
        # receive an unbounded input even if the SDK hook path is unavailable.
        validate_tool_request(tool_name, tool_input)

        # PreToolUse normally charged the canonical runtime budget. Mirror that
        # authority before any tool-specific fail-closed return so persisted
        # AgentRunState cannot undercount an already-accounted request.
        self.state.tool_call_count = self.control.budget.snapshot().tool_calls

        # Re-prove target freshness at the application-owned internal execution
        # boundary. This deliberately avoids RepositoryInspector work inside the
        # shorter SDK PreToolUse timeout.
        self._require_workspace_freshness(stage="pre_tool", tool_name=tool_name)

        if tool_name in _LIVE_MUTATION_TOOL_NAMES:
            # A skipped/broken SDK hook must not widen rollback authority. Re-run
            # deterministic mutation policy before reading target bytes for backup.
            policy_decision = self.policy.authorize_tool(
                f"mcp__qa__{tool_name}",
                tool_input,
            )
            self.state.policy_decisions.append(policy_decision)
            if policy_decision.decision.value != "ALLOW":
                reason = f"{policy_decision.rule_id}: {policy_decision.reason}"
                if self.state.terminal_status in {None, TerminalStatus.SUCCESS}:
                    self.state.terminal_status = TerminalStatus.POLICY_DENIED
                    self.state.terminal_reason = reason
                self.control.journal.try_append(
                    "mutation_policy_denied",
                    tool_name=f"mcp__qa__{tool_name}",
                    rule_id=policy_decision.rule_id,
                )
                if self.state_store is not None:  # pragma: no branch - required in __post_init__
                    self.state_store.save(self.state)
                self.control.persist()
                raise PermissionError(reason)

            if self.state.target_git_sha is None:
                reason = "Autonomous mutation requires a Git-backed target workspace"
                self.state.terminal_status = TerminalStatus.BLOCKED
                self.state.terminal_reason = reason
                self.control.journal.try_append(
                    "mutation_blocked_non_git_workspace",
                    tool_name=f"mcp__qa__{tool_name}",
                )
                if self.state_store is not None:  # pragma: no branch - required in __post_init__
                    self.state_store.save(self.state)
                self.control.persist()
                raise PermissionError(reason)

            # Capture rollback authority only after the exact workspace baseline and
            # mutation policy have both been re-proved.
            self.control.prepare_mutation(
                str(tool_input.get("path") or ""),
                change_revision_before=self.state.change_revision,
            )

        self._active_tool_name = tool_name
        super().checkpoint()

        if tool_name == "run_pytest":
            pytest_block_reason = self.pytest_execution_block_reason()
            if pytest_block_reason is not None:
                pytest_args = [str(item) for item in (tool_input.get("args") or [])]
                self.state.validation_results.append(
                    ValidationResult(
                        name="pytest",
                        gate_id=_stable_gate_id("pytest", pytest_args),
                        revision=self.state.change_revision,
                        status=ValidationStatus.BLOCKED,
                        summary=pytest_block_reason,
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
                self.state.terminal_reason = pytest_block_reason
                super().checkpoint()
                raise PermissionError(pytest_block_reason)

        if tool_name == "run_k6":
            try:
                gate_payload = k6_gate_payload(tool_input)
            except ValueError:
                # The canonical attempt was already charged. Persist that accounting,
                # but do not manufacture a validation gate for an invalid subject.
                super().checkpoint()
                raise
            reason = self.k6_execution_block_reason()
            self.state.validation_results.append(
                ValidationResult(
                    name="k6",
                    gate_id=_stable_gate_id("k6", gate_payload),
                    revision=self.state.change_revision,
                    status=ValidationStatus.BLOCKED,
                    summary=reason,
                    details={
                        **k6_persisted_subject(gate_payload),
                        "execution_started": False,
                        "process_isolation_enforced": False,
                        "module_isolation_enforced": False,
                        "resource_limits_enforced": False,
                        "workload_limits_enforced": False,
                        "external_egress_enforced": self.k6_external_egress_enforced,
                    },
                )
            )
            self.state.terminal_status = TerminalStatus.BLOCKED
            self.state.terminal_reason = reason
            super().checkpoint()
            raise PermissionError(reason)
