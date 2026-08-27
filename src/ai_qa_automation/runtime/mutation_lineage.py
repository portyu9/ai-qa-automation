from __future__ import annotations

from collections.abc import Callable

from ..models import AgentRunState, TerminalStatus, ValidationResult, ValidationStatus
from ..state import StateStore
from .run_control import PendingMutation


def _downgrade_success_after_rollback(state: AgentRunState) -> None:
    if state.terminal_status == TerminalStatus.SUCCESS:
        state.terminal_status = TerminalStatus.NOT_VERIFIED
        state.terminal_reason = (
            "Persisted mutation bytes were rolled back or entered rollback; the current revision "
            "no longer certifies the target workspace."
        )


def _rollback_gate_index(
    state: AgentRunState,
    *,
    gate_id: str,
    relative_path: str,
    change_revision_before: int,
    scope: str,
) -> int | None:
    for index, item in enumerate(state.validation_results):
        if (
            item.name == "mutation_transaction"
            and item.gate_id == gate_id
            and item.revision == state.change_revision
            and item.status == ValidationStatus.NOT_VERIFIED
            and item.details.get("scope") == scope
            and item.details.get("path") == relative_path
            and item.details.get("change_revision_before") == change_revision_before
        ):
            return index
    return None


def _assert_pending_revision_coherent(
    state: AgentRunState,
    *,
    change_revision_before: int,
) -> None:
    if state.change_revision != change_revision_before + 1:
        raise RuntimeError(
            "pending mutation revision lineage is incoherent with canonical change revision"
        )


def invalidate_pending_mutation_lineage(
    state: AgentRunState,
    *,
    relative_path: str,
    change_revision_before: int | None,
) -> bool:
    """Poison an advanced revision before rollback may clear runtime authority."""

    if not relative_path or change_revision_before is None:
        return False
    if state.change_revision <= change_revision_before:
        return False
    _assert_pending_revision_coherent(
        state,
        change_revision_before=change_revision_before,
    )

    gate_id = f"mutation_transaction:{relative_path}"
    if _rollback_gate_index(
        state,
        gate_id=gate_id,
        relative_path=relative_path,
        change_revision_before=change_revision_before,
        scope="rolled_back_mutation",
    ) is not None:
        _downgrade_success_after_rollback(state)
        return True
    if _rollback_gate_index(
        state,
        gate_id=gate_id,
        relative_path=relative_path,
        change_revision_before=change_revision_before,
        scope="rollback_pending",
    ) is None:
        state.validation_results.append(
            ValidationResult(
                name="mutation_transaction",
                gate_id=gate_id,
                revision=state.change_revision,
                status=ValidationStatus.NOT_VERIFIED,
                summary=(
                    "Mutation rollback is pending durable closure; this revision cannot certify "
                    "persisted target bytes."
                ),
                details={
                    "path": relative_path,
                    "scope": "rollback_pending",
                    "change_revision_before": change_revision_before,
                },
            )
        )
    _downgrade_success_after_rollback(state)
    return True


def reconcile_rolled_back_mutation(
    state: AgentRunState,
    *,
    relative_path: str,
    change_revision_before: int | None,
) -> bool:
    """Invalidate lineage for rollback of a mutation that advanced canonical revision state.

    The transition is idempotent so crash recovery may safely retry after canonical
    state was persisted but before runtime pending authority was durably cleared.
    Revision numbers remain monotonic; reverted bytes receive a current-revision
    NOT_VERIFIED transaction gate instead of rewriting history.
    """
    if not relative_path or change_revision_before is None:
        return False
    if state.change_revision <= change_revision_before:
        return False
    _assert_pending_revision_coherent(
        state,
        change_revision_before=change_revision_before,
    )

    gate_id = f"mutation_transaction:{relative_path}"
    already_reconciled = _rollback_gate_index(
        state,
        gate_id=gate_id,
        relative_path=relative_path,
        change_revision_before=change_revision_before,
        scope="rolled_back_mutation",
    )
    if already_reconciled is not None:
        _downgrade_success_after_rollback(state)
        return True

    pending_index = _rollback_gate_index(
        state,
        gate_id=gate_id,
        relative_path=relative_path,
        change_revision_before=change_revision_before,
        scope="rollback_pending",
    )
    for index in range(len(state.files_modified) - 1, -1, -1):
        if state.files_modified[index] == relative_path:
            state.files_modified.pop(index)
            break
    state.observations.append(
        f"Rolled back mutation revision {state.change_revision} for {relative_path}; "
        "modified-file accounting was reconciled while revision history remained monotonic."
    )
    rolled_back = ValidationResult(
        name="mutation_transaction",
        gate_id=gate_id,
        revision=state.change_revision,
        status=ValidationStatus.NOT_VERIFIED,
        summary=(
            "Mutation bytes were rolled back; this attempted revision cannot certify persisted "
            "target bytes."
        ),
        details={
            "path": relative_path,
            "scope": "rolled_back_mutation",
            "change_revision_before": change_revision_before,
        },
    )
    if pending_index is None:
        state.validation_results.append(rolled_back)
    else:
        state.validation_results[pending_index] = rolled_back
    _downgrade_success_after_rollback(state)
    return True


def build_rollback_lineage_checkpoints(
    state: AgentRunState,
    state_store: StateStore,
) -> tuple[Callable[[PendingMutation], None], Callable[[PendingMutation], None]]:
    """Bind live rollback to durable canonical validation lineage.

    The pre-close callback runs before target bytes are restored or runtime pending
    authority is cleared. The post-close callback reconciles file accounting after
    runtime closure. If the second save fails, the first persisted NOT_VERIFIED gate
    still prevents stale PASS lineage from certifying the reverted bytes.
    """

    def before_close(pending: PendingMutation) -> None:
        advanced = invalidate_pending_mutation_lineage(
            state,
            relative_path=pending.relative_path,
            change_revision_before=pending.change_revision_before,
        )
        if advanced:
            state_store.save(state)

    def after_close(pending: PendingMutation) -> None:
        reconciled = reconcile_rolled_back_mutation(
            state,
            relative_path=pending.relative_path,
            change_revision_before=pending.change_revision_before,
        )
        if reconciled:
            state_store.save(state)

    return before_close, after_close
