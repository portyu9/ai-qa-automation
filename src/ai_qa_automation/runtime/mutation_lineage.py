from __future__ import annotations

from ..models import AgentRunState, TerminalStatus, ValidationResult, ValidationStatus


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

    gate_id = f"mutation_transaction:{relative_path}"
    already_reconciled = any(
        item.name == "mutation_transaction"
        and item.gate_id == gate_id
        and item.revision == state.change_revision
        and item.status == ValidationStatus.NOT_VERIFIED
        and item.details.get("scope") == "rolled_back_mutation"
        and item.details.get("path") == relative_path
        and item.details.get("change_revision_before") == change_revision_before
        for item in state.validation_results
    )
    if already_reconciled:
        if state.terminal_status == TerminalStatus.SUCCESS:
            state.terminal_status = TerminalStatus.NOT_VERIFIED
            state.terminal_reason = (
                "Persisted mutation bytes were rolled back; the current revision no longer "
                "certifies the target workspace."
            )
        return True

    for index in range(len(state.files_modified) - 1, -1, -1):
        if state.files_modified[index] == relative_path:
            state.files_modified.pop(index)
            break
    state.observations.append(
        f"Rolled back mutation revision {state.change_revision} for {relative_path}; "
        "modified-file accounting was reconciled while revision history remained monotonic."
    )
    state.validation_results.append(
        ValidationResult(
            name="mutation_transaction",
            gate_id=gate_id,
            revision=state.change_revision,
            status=ValidationStatus.NOT_VERIFIED,
            summary=(
                "Mutation bytes were rolled back; this attempted revision cannot certify "
                "persisted target bytes."
            ),
            details={
                "path": relative_path,
                "scope": "rolled_back_mutation",
                "change_revision_before": change_revision_before,
            },
        )
    )
    if state.terminal_status == TerminalStatus.SUCCESS:
        state.terminal_status = TerminalStatus.NOT_VERIFIED
        state.terminal_reason = (
            "Persisted mutation bytes were rolled back; the current revision no longer "
            "certifies the target workspace."
        )
    return True
