from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from ..models import TerminalStatus, ValidationResult, ValidationStatus


@dataclass(frozen=True, slots=True)
class ActiveValidationSet:
    """Latest-revision observations for each deterministic gate identity."""

    results: tuple[ValidationResult, ...]
    conflicting_gate_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RevisionClosure:
    """Deterministic closure result for one mutated revision."""

    closed: bool
    code: str
    reason: str
    mutation_path: str | None = None


def active_validation_set(validations: list[ValidationResult]) -> ActiveValidationSet:
    """Select only the newest revision for every gate while retaining same-revision conflict truth."""

    grouped: dict[str, list[ValidationResult]] = defaultdict(list)
    for item in validations:
        grouped[item.gate_id or item.name].append(item)

    active: list[ValidationResult] = []
    conflicts: list[str] = []
    for gate_id in sorted(grouped):
        items = grouped[gate_id]
        latest_revision = max(item.revision for item in items)
        current = [item for item in items if item.revision == latest_revision]
        statuses = {item.status for item in current}
        if ValidationStatus.PASS in statuses and ValidationStatus.FAIL in statuses:
            conflicts.append(gate_id)
        active.extend(current)

    return ActiveValidationSet(tuple(active), tuple(conflicts))


def _future_validation_revisions(
    validations: list[ValidationResult] | tuple[ValidationResult, ...],
    *,
    current_revision: int,
) -> tuple[int, ...]:
    return tuple(sorted({item.revision for item in validations if item.revision > current_revision}))


def evaluate_revision_closure(
    validations: list[ValidationResult] | tuple[ValidationResult, ...],
    *,
    current_revision: int,
    expected_path: str | None = None,
) -> RevisionClosure:
    """Apply the one authoritative changed-test closure rule.

    Revision zero has no autonomous mutation to close. A positive revision closes
    only when every result at that revision is PASS, exactly one patch-safety
    subject exists, targeted pytest is explicitly bound to that subject, and a
    full regression pytest PASS exists at the same revision. Negative or
    future-ahead revision state is invalid and fails closed.
    """

    if current_revision < 0:
        return RevisionClosure(
            False,
            "invalid_revision",
            "Change revision must be a non-negative integer before deterministic closure.",
        )
    future_revisions = _future_validation_revisions(
        validations,
        current_revision=current_revision,
    )
    if future_revisions:
        return RevisionClosure(
            False,
            "future_validation_revision",
            "Validation lineage is ahead of canonical change revision: "
            + ", ".join(str(item) for item in future_revisions)
            + ".",
        )
    if current_revision == 0:
        return RevisionClosure(True, "unchanged", "No changed revision requires closure.")

    current = [item for item in validations if item.revision == current_revision]
    if not current:
        return RevisionClosure(
            False,
            "missing_revision_validation",
            "Files changed, but no deterministic validation was executed at the current change revision.",
        )

    failed = sorted(
        {item.gate_id or item.name for item in current if item.status == ValidationStatus.FAIL}
    )
    if failed:
        return RevisionClosure(
            False,
            "failed_revision_validation",
            "Current deterministic validation failed: " + ", ".join(failed) + ".",
        )

    incomplete = sorted(
        {item.status.value for item in current if item.status != ValidationStatus.PASS}
    )
    if incomplete:
        return RevisionClosure(
            False,
            "incomplete_revision_validation",
            "Current changed revision contains non-PASS validation: " + ", ".join(incomplete) + ".",
        )

    patch_paths = {
        str(item.details.get("path") or "")
        for item in current
        if item.name == "test_patch_safety"
        and item.status == ValidationStatus.PASS
        and str(item.details.get("path") or "")
    }
    if not patch_paths:
        return RevisionClosure(
            False,
            "missing_patch_safety",
            "Files changed, but deterministic patch-safety validation is missing for the current revision.",
        )
    if len(patch_paths) != 1:
        return RevisionClosure(
            False,
            "ambiguous_patch_subject",
            "A changed revision must resolve to exactly one patch-safety target path before commit.",
        )

    mutation_path = next(iter(patch_paths))
    if expected_path is not None and mutation_path != expected_path:
        return RevisionClosure(
            False,
            "unexpected_patch_subject",
            "The current validation closure is bound to a different mutation subject.",
            mutation_path,
        )

    current_pytest = [
        item for item in current if item.name == "pytest" and item.status == ValidationStatus.PASS
    ]
    if not current_pytest:
        return RevisionClosure(
            False,
            "missing_pytest",
            "Files changed, but no passing pytest gate validated the current change revision.",
            mutation_path,
        )

    targeted = any(
        item.details.get("scope") == "targeted"
        and item.details.get("mutation_target_bound") is True
        and item.details.get("mutation_target") == mutation_path
        for item in current_pytest
    )
    regression = any(item.details.get("scope") == "regression" for item in current_pytest)
    if not targeted or not regression:
        return RevisionClosure(
            False,
            "incomplete_pytest_closure",
            "A changed test requires an exact-path-bound targeted pytest PASS and a full-regression pytest PASS at the current revision.",
            mutation_path,
        )

    return RevisionClosure(
        True,
        "closed",
        "Current changed revision is deterministically closed.",
        mutation_path,
    )


def determine_terminal_outcome(
    result_subtype: str | None,
    validations: list[ValidationResult],
    *,
    current_revision: int = 0,
    objective_gate_id: str | None = None,
) -> tuple[TerminalStatus, str]:
    """Derive terminal truth without model authority or unrelated-green promotion."""

    if result_subtype != "success":
        return TerminalStatus.FAILURE, f"Agent result subtype: {result_subtype or 'unknown'}"
    if current_revision < 0:
        return (
            TerminalStatus.NOT_VERIFIED,
            "Agent completed, but change revision is invalid and deterministic closure cannot be established.",
        )
    future_revisions = _future_validation_revisions(
        validations,
        current_revision=current_revision,
    )
    if future_revisions:
        return (
            TerminalStatus.NOT_VERIFIED,
            "Agent completed, but validation lineage is ahead of canonical change revision: "
            + ", ".join(str(item) for item in future_revisions)
            + ".",
        )
    if not validations:
        return (
            TerminalStatus.NOT_VERIFIED,
            "Agent completed, but no deterministic validation gate proved success.",
        )

    active_set = active_validation_set(validations)
    active = list(active_set.results)
    if active_set.conflicting_gate_ids:
        return (
            TerminalStatus.NOT_VERIFIED,
            "Conflicting PASS/FAIL results at the same change revision; possible flakiness: "
            + ", ".join(active_set.conflicting_gate_ids)
            + ".",
        )

    failed = [item for item in active if item.status == ValidationStatus.FAIL]
    if failed:
        names = ", ".join(sorted({item.gate_id or item.name for item in failed}))
        return TerminalStatus.FAILURE, f"Current deterministic validation failed: {names}."

    incomplete = sorted(
        {item.status.value for item in active if item.status != ValidationStatus.PASS}
    )
    if incomplete:
        return (
            TerminalStatus.NOT_VERIFIED,
            "Agent completed, but current validation remained incomplete: "
            + ", ".join(incomplete)
            + ".",
        )

    if current_revision == 0:
        if not objective_gate_id:
            return (
                TerminalStatus.NOT_VERIFIED,
                "Agent completed with passing deterministic checks, but the operator did not supply an exact objective-validation gate contract.",
            )
        objective_bound = [
            item
            for item in active
            if item.status == ValidationStatus.PASS
            and (item.gate_id or item.name) == objective_gate_id
        ]
        if not objective_bound:
            return (
                TerminalStatus.NOT_VERIFIED,
                "Agent completed with passing deterministic checks, but no active PASS matched the operator-supplied objective-validation gate contract.",
            )
    else:
        closure = evaluate_revision_closure(active, current_revision=current_revision)
        if not closure.closed:
            return TerminalStatus.NOT_VERIFIED, closure.reason

    return (
        TerminalStatus.SUCCESS,
        "Agent completed and all current deterministic validation gates passed; historical failures remain recorded.",
    )
