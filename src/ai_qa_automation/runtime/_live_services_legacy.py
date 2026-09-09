from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import (
    EvidenceKind,
    EvidenceNature,
    TerminalStatus,
    ToolDecision,
    ValidationResult,
    ValidationStatus,
)
from ..network_authority import NetworkAuthorityCode, NetworkAuthorityError
from .internal_tools import RuntimeServices, _pytest_scope, _stable_gate_id
from .k6_authority import k6_gate_payload, k6_persisted_subject
from .locator_repair import LocatorRepairAuthorityError, resolve_locator_repair_authority
from .mutation_lineage import build_rollback_lineage_checkpoints
from .run_control import RuntimeControl
from .tool_input_bounds import validate_tool_request
from .workspace_freshness import WorkspaceFreshnessCode, observe_workspace_freshness

# Proposal-only create_test_file never owns repository mutation/rollback authority.
_LIVE_MUTATION_TOOL_NAMES = frozenset({"apply_locator_heal"})


@dataclass
class LiveRuntimeServices(RuntimeServices):
    """Bind live internal execution to canonical runtime and workspace authority.

    Internal tool implementations still call ``consume`` as an execution
    checkpoint, but they do not maintain an independent live budget/repetition
    authority. Canonical RuntimeControl covers internal and external SDK tool
    requests uniformly; this adapter mirrors that charged request count while
    owning the target-subject checks that must occur immediately before an
    in-process internal tool body proceeds.

    Target-controlled pytest code is fail-closed unless trusted deployment
    infrastructure explicitly asserts the intended containment policy *and* the
    concrete TestRunner proves a usable OS sandbox immediately before the tool
    body proceeds. The assertions alone can never authorize direct host pytest.

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

    def network_hosts(self, url: str) -> set[str]:
        try:
            return super().network_hosts(url)
        except NetworkAuthorityError as exc:
            if exc.code is NetworkAuthorityCode.EXTERNAL_EGRESS_UNVERIFIED:
                reason = str(exc)
                if self.state.terminal_status in {None, TerminalStatus.SUCCESS}:
                    self.state.terminal_status = TerminalStatus.BLOCKED
                    self.state.terminal_reason = reason
                if self.control is None or self.state_store is None:  # pragma: no cover
                    raise RuntimeError(
                        "live runtime services lost durable network authority"
                    ) from exc
                self.control.journal.try_append(
                    "external_network_authority_blocked",
                    reason_code=exc.code.value,
                )
                self.state_store.save(self.state)
                self.control.persist()
            raise

    def _pytest_execution_authority(self) -> tuple[str | None, dict[str, object]]:
        missing: list[str] = []
        if not self.pytest_process_isolation_enforced:
            missing.append("process/filesystem isolation")
        if not self.pytest_external_egress_enforced:
            missing.append("outbound-egress enforcement")
        if missing:
            return (
                "pytest target-code execution requires trusted deployment enforcement for "
                + " and ".join(missing)
                + "; configuration assertions alone never authorize target execution",
                {
                    "preflight_attempted": False,
                    "backend": "bubblewrap",
                    "ready": False,
                    "reason": "deployment intent prerequisite is missing",
                },
            )

        try:
            sandbox = self.test_runner.sandbox_preflight()
        except (OSError, RuntimeError, ValueError) as exc:
            return (
                "pytest target-code execution requires a verified OS sandbox; "
                f"sandbox preflight failed with {type(exc).__name__}",
                {
                    "preflight_attempted": True,
                    "backend": "bubblewrap",
                    "ready": False,
                    "reason": f"sandbox preflight failed with {type(exc).__name__}",
                },
            )
        details = sandbox.details()
        details["preflight_attempted"] = True
        if not sandbox.ready:
            return (
                "pytest target-code execution requires a verified OS sandbox; "
                + (sandbox.reason or "sandbox capability proof was incomplete"),
                details,
            )
        return None, details

    def pytest_execution_block_reason(self) -> str | None:
        reason, _details = self._pytest_execution_authority()
        return reason

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

    def _deny_live_mutation(self, *, tool_name: str, rule_id: str, reason: str) -> None:
        if self.control is None or self.state_store is None:  # pragma: no cover - guarded above
            raise RuntimeError("live runtime services lost durable mutation authority")
        if self.state.terminal_status in {None, TerminalStatus.SUCCESS}:
            self.state.terminal_status = TerminalStatus.POLICY_DENIED
            self.state.terminal_reason = f"{rule_id}: {reason}"
        self.control.journal.try_append(
            "mutation_policy_denied",
            tool_name=f"mcp__qa__{tool_name}",
            rule_id=rule_id,
        )
        self.state_store.save(self.state)
        self.control.persist()
        raise PermissionError(f"{rule_id}: {reason}")

    def _resolved_live_mutation_path(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
    ) -> str:
        """Resolve mutation subject from trusted same-run evidence, never model-supplied path data."""

        if tool_name != "apply_locator_heal":
            raise PermissionError("unsupported live mutation tool")
        proposal_id = tool_input.get("proposal_evidence_id")
        if not isinstance(proposal_id, str) or not proposal_id:
            raise PermissionError("live locator mutation requires proposal evidence identity")
        try:
            proposal = self.evidence.get(proposal_id)
        except KeyError as exc:
            raise PermissionError("live locator mutation proposal evidence is unavailable") from exc
        data = proposal.structured_data
        if (
            proposal.kind is not EvidenceKind.HEALING_PROPOSAL
            or proposal.nature is not EvidenceNature.MODEL_INTERPRETATION
            or proposal.source != "self_healing_engine"
            or proposal.id not in self.state.evidence_ids
        ):
            raise PermissionError(
                "live locator mutation proposal lacks trusted same-run provenance"
            )
        repair_subject_id = data.get("repair_subject_id")
        if not isinstance(repair_subject_id, str) or not repair_subject_id:
            raise PermissionError("live locator mutation proposal lost repair subject identity")
        try:
            authority = resolve_locator_repair_authority(
                subject_id=repair_subject_id,
                workspace=self.workspace,
                expected_root_identity=self.workspace_root_identity,
                state=self.state,
                evidence=self.evidence,
            )
        except LocatorRepairAuthorityError as exc:
            raise PermissionError("live locator mutation subject authority is invalid") from exc
        if proposal.source_identifier != repair_subject_id or data.get("path") != authority.path:
            raise PermissionError(
                "live locator mutation proposal does not match repair subject path"
            )
        return authority.path

    def _bind_active_mutation_candidate(self) -> None:
        if self.control is None:  # pragma: no cover - guarded by __post_init__
            raise RuntimeError("live runtime services lost RuntimeControl")
        pending = self.control.pending_mutation
        if (
            pending is None
            or not pending.candidate_required
            or pending.candidate_sha256 is not None
        ):
            return

        for evidence_id in reversed(self.state.evidence_ids):
            try:
                item = self.evidence.get(evidence_id)
            except KeyError:
                continue
            if item.kind is not EvidenceKind.GIT_DIFF or item.source != "safe_test_patcher":
                continue
            path = item.structured_data.get("path")
            candidate_sha256 = item.structured_data.get("new_sha256")
            if path != pending.relative_path or not isinstance(candidate_sha256, str):
                continue
            self.control.bind_pending_mutation_candidate(path, candidate_sha256)
            return
        raise RuntimeError(
            "live mutation produced no exact candidate evidence; pending rollback authority remains open"
        )

    def checkpoint(self) -> None:
        """Persist tool state only while observations remain on the authorized subject."""

        if self._active_tool_name in _LIVE_MUTATION_TOOL_NAMES:
            # The mutation tool records its exact post-write digest before checkpoint.
            # Bind that digest to the durable transaction before canonical state can
            # persist the revision as an owned live mutation.
            self._bind_active_mutation_candidate()
        else:
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
            if policy_decision.decision is not ToolDecision.ALLOW:
                self._deny_live_mutation(
                    tool_name=tool_name,
                    rule_id=policy_decision.rule_id,
                    reason=policy_decision.reason,
                )

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

            subject_path = self._resolved_live_mutation_path(tool_name, tool_input)
            path_decision = self.policy.authorize_path(Path(subject_path), write=True)
            self.state.policy_decisions.append(path_decision)
            if path_decision.decision is not ToolDecision.ALLOW:
                self._deny_live_mutation(
                    tool_name=tool_name,
                    rule_id=path_decision.rule_id,
                    reason=path_decision.reason,
                )
            if Path(subject_path).suffix != ".py":
                self._deny_live_mutation(
                    tool_name=tool_name,
                    rule_id="WRITE-RUNTIME-001",
                    reason="live autonomous mutation is restricted to pytest-backed Python test paths",
                )

            # Capture rollback authority only after the exact workspace baseline,
            # mutation policy, and evidence-resolved subject have all been re-proved.
            self.control.prepare_mutation(
                subject_path,
                change_revision_before=self.state.change_revision,
                candidate_required=True,
            )

        self._active_tool_name = tool_name
        super().checkpoint()

        if tool_name == "run_pytest":
            pytest_block_reason, sandbox_details = self._pytest_execution_authority()
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
                            "sandbox": sandbox_details,
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
