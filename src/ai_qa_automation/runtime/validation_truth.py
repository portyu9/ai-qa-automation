from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath

from ..models import TerminalStatus, ValidationResult, ValidationStatus

_UNBOUND_OBJECTIVE_GATE_IDS = {"browser_runtime"}


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


def _is_sha256_identity(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        return False
    try:
        int(value[7:], 16)
    except ValueError:
        return False
    return True


def _verified_regression_suite_id(item: ValidationResult) -> str | None:
    """Return one self-consistent controller-bound regression suite identity."""

    if item.details.get("scope") != "regression":
        return None
    if item.details.get("regression_suite_verified") is not True:
        return None
    suite_id = item.details.get("regression_suite_id")
    suite = item.details.get("regression_suite")
    if not _is_sha256_identity(suite_id):
        return None
    if not isinstance(suite, dict):
        return None
    if suite.get("suite_id") != suite_id:
        return None
    if suite.get("pre_post_collection_match") is not True:
        return None
    if suite.get("execution_nodes_match") is not True:
        return None
    if not isinstance(suite.get("node_count"), int) or int(suite["node_count"]) < 1:
        return None
    subject_digest = suite.get("execution_subject_digest")
    if not _is_sha256_identity(subject_digest):
        return None
    return suite_id


def _normalized_target_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.rstrip("/")
    if not normalized:
        return None
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    if path.as_posix() != normalized:
        return None
    return normalized


def _verified_targeted_execution_covers_path(
    item: ValidationResult,
    mutation_path: str,
) -> bool:
    """Require self-consistent call-phase PASS evidence for the exact mutation path."""

    expected = _normalized_target_path(mutation_path)
    if expected is None:
        return False
    if item.details.get("scope") != "targeted":
        return False
    if item.details.get("mutation_target_bound") is not True:
        return False
    if _normalized_target_path(item.details.get("mutation_target")) != expected:
        return False
    if item.details.get("targeted_outcome_report_verified") is not True:
        return False

    execution_id = item.details.get("targeted_execution_id")
    execution = item.details.get("targeted_execution")
    if not _is_sha256_identity(execution_id) or not isinstance(execution, dict):
        return False
    if execution.get("execution_id") != execution_id:
        return False
    if execution.get("report_complete") is not True:
        return False
    if execution.get("child_exit_code") != 0 or execution.get("pytest_returncode") != 0:
        return False
    if not _is_sha256_identity(execution.get("execution_subject_digest")):
        return False
    git_sha = execution.get("git_sha")
    source_fingerprint = execution.get("source_fingerprint")
    if not isinstance(git_sha, str) or not git_sha or len(git_sha) > 128:
        return False
    if (
        not isinstance(source_fingerprint, str)
        or not source_fingerprint
        or len(source_fingerprint) > 256
    ):
        return False

    passed_count = execution.get("passed_call_count")
    top_count = item.details.get("targeted_executed_pass_count")
    if type(passed_count) is not int or passed_count < 1 or top_count != passed_count:
        return False
    passed_paths = execution.get("passed_paths")
    top_paths = item.details.get("targeted_executed_pass_paths")
    if (
        not isinstance(passed_paths, list)
        or not isinstance(top_paths, list)
        or passed_paths != top_paths
        or not 1 <= len(passed_paths) <= 4
    ):
        return False
    normalized_paths = [_normalized_target_path(value) for value in passed_paths]
    if any(value is None for value in normalized_paths):
        return False
    if len(set(normalized_paths)) != len(normalized_paths):
        return False
    return expected in normalized_paths


def evaluate_revision_closure(
    validations: list[ValidationResult] | tuple[ValidationResult, ...],
    *,
    current_revision: int,
    expected_path: str | None = None,
) -> RevisionClosure:
    """Apply the one authoritative changed-test closure rule.

    Revision zero has no autonomous mutation to close. A positive revision closes
    only when every result at that revision is PASS, exactly one patch-safety
    subject exists, targeted pytest is explicitly bound to and has an executed
    call-phase PASS for that subject, and a controller-bound full-regression suite
    PASS exists at the same revision. Negative or future-ahead revision state is
    invalid and fails closed.
    """

    if current_revision < 0:
        return RevisionClosure(
            False,
            "invalid_revision",
            "Change revision must be a non-negative integer before deterministic closure.",
        )
    future_revisions = _future_validation_revisions(validations, current_revision=current_revision)
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

    incomplete = sorted({item.status.value for item in current if item.status != ValidationStatus.PASS})
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
        _verified_targeted_execution_covers_path(item, mutation_path) for item in current_pytest
    )
    regression_candidates = [
        item for item in current_pytest if item.details.get("scope") == "regression"
    ]
    regression_suite_ids = {
        suite_id
        for item in regression_candidates
        if (suite_id := _verified_regression_suite_id(item)) is not None
    }
    if not targeted:
        return RevisionClosure(
            False,
            "incomplete_pytest_closure",
            "A changed test requires an exact-path-bound targeted pytest PASS with a controller-verified executed call-phase PASS for that path, plus a controller-bound full-regression pytest PASS at the current revision.",
            mutation_path,
        )
    if not regression_suite_ids:
        return RevisionClosure(
            False,
            "unbound_regression_suite",
            "A changed test requires a full-regression PASS bound to an exact controller-verified suite identity.",
            mutation_path,
        )
    if len(regression_suite_ids) != 1:
        return RevisionClosure(
            False,
            "ambiguous_regression_suite",
            "Current revision contains multiple controller-verified regression suite identities.",
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
    future_revisions = _future_validation_revisions(validations, current_revision=current_revision)
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

    incomplete = sorted({item.status.value for item in active if item.status != ValidationStatus.PASS})
    if incomplete:
        return (
            TerminalStatus.NOT_VERIFIED,
            "Agent completed, but current validation remained incomplete: "
            + ", ".join(incomplete)
            + ".",
        )

    if not objective_gate_id:
        return (
            TerminalStatus.NOT_VERIFIED,
            "Agent completed with passing deterministic checks, but the operator did not supply an exact objective-validation gate contract.",
        )
    if objective_gate_id in _UNBOUND_OBJECTIVE_GATE_IDS:
        return (
            TerminalStatus.NOT_VERIFIED,
            "Agent completed, but the operator supplied a legacy validation gate that is not bound to an exact deterministic subject.",
        )
    objective_bound = [
        item
        for item in active
        if item.status == ValidationStatus.PASS
        and item.revision == current_revision
        and (item.gate_id or item.name) == objective_gate_id
    ]
    if not objective_bound:
        return (
            TerminalStatus.NOT_VERIFIED,
            "Agent completed with passing deterministic checks, but no active PASS matched the operator-supplied objective-validation gate contract at the current change revision.",
        )

    if current_revision > 0:
        closure = evaluate_revision_closure(active, current_revision=current_revision)
        if not closure.closed:
            return TerminalStatus.NOT_VERIFIED, closure.reason

    return (
        TerminalStatus.SUCCESS,
        "Agent completed and all current deterministic validation gates passed; historical failures remain recorded.",
    )
