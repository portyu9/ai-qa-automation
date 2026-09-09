from __future__ import annotations

from pathlib import Path
from typing import Any, NoReturn, TypeGuard

from ..models import EvidenceKind, EvidenceNature, TerminalStatus, ToolDecision
from ..tools.repository import RepositoryInspector
from ..tools.safe_patch import SafeTestPatcher
from ._live_services_legacy import LiveRuntimeServices as _LegacyLiveRuntimeServices
from .internal_tools import RuntimeServices
from .locator_repair import LocatorRepairAuthorityError, resolve_locator_repair_authority
from .run_control import MutationPendingError
from .strict_mutation_publish import publish_pending_candidate
from .tool_input_bounds import validate_tool_request

_LIVE_MUTATION_TOOL_NAMES = frozenset({"apply_locator_heal"})


def _is_sha256_hex(value: object) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


class LiveRuntimeServices(_LegacyLiveRuntimeServices):
    """Add strict evidence-bound mutation authority to the stable live services."""

    def __post_init__(self) -> None:
        super().__post_init__()
        self._active_mutation_proposal_id: str | None = None

    def _resolved_live_mutation_path(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
    ) -> str:
        """Resolve mutation subject from trusted same-run evidence, never model path data."""

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
            or proposal.run_id != self.state.run_id
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
        if (
            proposal.source_identifier != repair_subject_id
            or data.get("path") != authority.path
            or data.get("expected_sha256") != authority.expected_sha256
        ):
            raise PermissionError(
                "live locator mutation proposal does not match repair subject path and bytes"
            )
        return authority.path

    def _live_mutation_original_sha256(self, proposal_id: str) -> str:
        try:
            proposal = self.evidence.get(proposal_id)
        except KeyError as exc:  # pragma: no cover - path resolution already proved availability
            raise RuntimeError(
                "live mutation proposal disappeared after subject resolution"
            ) from exc
        expected = proposal.structured_data.get("expected_sha256")
        if not _is_sha256_hex(expected):
            raise PermissionError(
                "live locator mutation proposal has invalid original-byte authority"
            )
        return expected

    def _observe_live_mutation_context(self, relative_path: str) -> tuple[str, str]:
        inspector = RepositoryInspector(
            self.workspace,
            expected_root_identity=self.workspace_root_identity,
        )
        workspace_fingerprint, context_fingerprint, complete, reasons = (
            inspector.mutation_context_fingerprint(relative_path)
        )
        if not complete:
            rendered = ", ".join(reasons) or "unspecified"
            raise RuntimeError(
                f"live mutation workspace context could not be bound completely ({rendered})"
            )
        return workspace_fingerprint, context_fingerprint

    def _block_live_mutation_integrity(self, reason: str) -> NoReturn:
        if self.control is None or self.state_store is None:  # pragma: no cover - constructor guard
            raise RuntimeError("live runtime services lost durable mutation authority")
        self.state.terminal_status = TerminalStatus.BLOCKED
        self.state.terminal_reason = reason
        self.control.open_circuits.update(_LIVE_MUTATION_TOOL_NAMES)
        self.control.journal.try_append("live_mutation_integrity_blocked", reason=reason)
        self.state_store.save(self.state)
        self.control.persist()
        raise RuntimeError(reason)

    def _abort_prepared_live_mutation(self, reason: str) -> NoReturn:
        if self.control is None:  # pragma: no cover - constructor guard
            raise RuntimeError("live runtime services lost RuntimeControl")
        rollback_note = ""
        if self.control.pending_mutation is not None:
            try:
                self.control.rollback_pending_mutation(reason=reason)
            except (MutationPendingError, OSError, RuntimeError, ValueError) as exc:
                rollback_note = (
                    "; rollback could not be proven safe and pending authority was retained: "
                    f"{type(exc).__name__}"
                )
        self._block_live_mutation_integrity(reason + rollback_note)

    def _publish_live_mutation_candidate(
        self,
        relative_path: str,
        expected_original_sha256: str,
        candidate_bytes: bytes,
    ) -> str:
        if self.control is None:  # pragma: no cover - constructor guard
            raise RuntimeError("live runtime services lost RuntimeControl")
        return publish_pending_candidate(
            self.control,
            relative_path=relative_path,
            expected_original_sha256=expected_original_sha256,
            candidate_bytes=candidate_bytes,
        )

    def build_safe_test_patcher(self) -> SafeTestPatcher:
        """Bind strict live patch publication to the current pending transaction."""

        return SafeTestPatcher(
            self.workspace,
            self.policy,
            candidate_publisher=self._publish_live_mutation_candidate,
        )

    def _bind_active_mutation_candidate(self) -> None:
        if self.control is None:  # pragma: no cover - constructor guard
            raise RuntimeError("live runtime services lost RuntimeControl")
        pending = self.control.pending_mutation
        if pending is None or not pending.candidate_required:
            return

        matching_candidates: list[str] = []
        for evidence_id in reversed(self.state.evidence_ids):
            try:
                item = self.evidence.get(evidence_id)
            except KeyError:
                continue
            if (
                item.kind is not EvidenceKind.GIT_DIFF
                or item.nature is not EvidenceNature.OBSERVED_FACT
                or item.source != "safe_test_patcher"
                or item.run_id != self.state.run_id
            ):
                continue
            path = item.structured_data.get("path")
            observed_sha256 = item.structured_data.get("new_sha256")
            proposal_evidence_id = item.structured_data.get("proposal_evidence_id")
            if (
                path != pending.relative_path
                or not _is_sha256_hex(observed_sha256)
                or not isinstance(proposal_evidence_id, str)
                or proposal_evidence_id != self._active_mutation_proposal_id
                or item.source_identifier != proposal_evidence_id
            ):
                continue
            matching_candidates.append(observed_sha256)

        if len(matching_candidates) != 1:
            reason = (
                "live mutation produced no exact candidate evidence; pending rollback authority "
                "remains open"
                if not matching_candidates
                else "live mutation produced ambiguous exact candidate evidence; pending rollback "
                "authority remains open"
            )
            self._block_live_mutation_integrity(reason)
        candidate_sha256 = matching_candidates[0]

        if pending.candidate_sha256 is None:
            self.control.bind_pending_mutation_candidate(
                pending.relative_path,
                candidate_sha256,
            )
        elif pending.candidate_sha256 != candidate_sha256:
            self._block_live_mutation_integrity(
                "runtime-bound candidate bytes do not match exact same-run patch evidence"
            )

        try:
            workspace_fingerprint, context_fingerprint = self._observe_live_mutation_context(
                pending.relative_path
            )
        except (OSError, RuntimeError, ValueError) as exc:
            self._block_live_mutation_integrity(
                "live mutation candidate workspace could not be observed completely: "
                f"{type(exc).__name__}"
            )

        pending = self.control.pending_mutation
        if pending is None:  # pragma: no cover - binding cannot close transaction
            raise RuntimeError("live mutation candidate binding lost pending authority")
        self.control.bind_pending_mutation_candidate(
            pending.relative_path,
            candidate_sha256,
            candidate_workspace_fingerprint=workspace_fingerprint,
        )
        if pending.pre_mutation_context_fingerprint != context_fingerprint:
            self._block_live_mutation_integrity(
                "workspace changed outside the authorized live mutation subject"
            )
        self.control.set_workspace_fingerprint(workspace_fingerprint)

    def consume(self, tool_name: str, tool_input: dict[str, Any]) -> None:
        if tool_name not in _LIVE_MUTATION_TOOL_NAMES:
            self._active_mutation_proposal_id = None
            return super().consume(tool_name, tool_input)
        if self.control is None:  # pragma: no cover - constructor guard
            raise RuntimeError("live runtime services lost RuntimeControl")

        validate_tool_request(tool_name, tool_input)
        self.state.tool_call_count = self.control.budget.snapshot().tool_calls
        self._require_workspace_freshness(stage="pre_tool", tool_name=tool_name)

        policy_decision = self.policy.authorize_tool(f"mcp__qa__{tool_name}", tool_input)
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
            if self.state_store is not None:
                self.state_store.save(self.state)
            self.control.persist()
            raise PermissionError(reason)

        subject_path = self._resolved_live_mutation_path(tool_name, tool_input)
        proposal_id = tool_input.get("proposal_evidence_id")
        if not isinstance(proposal_id, str):  # pragma: no cover - resolved above
            raise RuntimeError("live mutation proposal identity was lost after resolution")
        expected_original_sha256 = self._live_mutation_original_sha256(proposal_id)
        self._active_mutation_proposal_id = proposal_id
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

        try:
            pre_workspace_fingerprint, pre_context_fingerprint = (
                self._observe_live_mutation_context(subject_path)
            )
        except (OSError, RuntimeError, ValueError) as exc:
            self._block_live_mutation_integrity(
                f"live mutation pre-state could not be observed completely: {type(exc).__name__}"
            )
        if pre_workspace_fingerprint != self.control.expected_workspace_fingerprint:
            self._block_live_mutation_integrity(
                "workspace changed before strict mutation rollback authority was prepared"
            )
        self.control.prepare_mutation(
            subject_path,
            change_revision_before=self.state.change_revision,
            candidate_required=True,
            pre_mutation_context_fingerprint=pre_context_fingerprint,
        )

        pending = self.control.pending_mutation
        if (
            pending is None
            or not pending.candidate_required
            or pending.relative_path != subject_path
            or pending.original_sha256 != expected_original_sha256
        ):
            self._abort_prepared_live_mutation(
                "strict mutation rollback authority does not match the evidence-bound original bytes"
            )
        try:
            prepared_workspace_fingerprint, prepared_context_fingerprint = (
                self._observe_live_mutation_context(subject_path)
            )
        except (OSError, RuntimeError, ValueError) as exc:
            self._abort_prepared_live_mutation(
                "strict mutation prepared state could not be re-observed completely: "
                f"{type(exc).__name__}"
            )
        if (
            prepared_workspace_fingerprint != pre_workspace_fingerprint
            or prepared_context_fingerprint != pre_context_fingerprint
        ):
            self._abort_prepared_live_mutation(
                "workspace changed while strict mutation rollback authority was being prepared"
            )

        self._active_tool_name = tool_name
        RuntimeServices.checkpoint(self)
