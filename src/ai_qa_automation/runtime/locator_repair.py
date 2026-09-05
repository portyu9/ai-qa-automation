from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..evidence import EvidenceStore
from ..intelligence.failure_analysis import FailureAnalyzer
from ..models import (
    AgentRunState,
    EvidenceItem,
    EvidenceKind,
    EvidenceNature,
    FailureClass,
    ToolDecision,
    ValidationResult,
    ValidationStatus,
)
from ..policy import PolicyEngine
from ..tools.locators import parse_locator_expression
from ..tools.repository import RepositoryInspector
from .model_source_observation import read_model_source_confined

_LOCATOR_REPAIR_AUTHORITY_VERSION = "locator_repair_subject_v1"
_ALLOWED_REPAIR_CLASSES = {
    FailureClass.LOCATOR_UI_CONTRACT_CHANGE,
    FailureClass.TEST_AUTOMATION_DEFECT,
}
_MIN_REPAIR_CONFIDENCE = 0.75
_MAX_FAILURE_EVIDENCE_ITEMS = 16
_MAX_CANDIDATES = 20


class LocatorRepairAuthorityError(ValueError):
    """Raised when locator-repair lineage cannot be proven deterministically."""


@dataclass(frozen=True, slots=True)
class LocatorRepairBinding:
    revision: int
    failure_validation_id: str
    failure_gate_id: str
    path: str
    pytest_selector: str
    failing_node_id: str
    failure_evidence_ids: tuple[str, ...]
    failure_items: tuple[EvidenceItem, ...]
    git_sha: str
    workspace_fingerprint: str
    expected_sha256: str
    original_locator: str
    original_locator_hash: str
    original_locator_offset: int


@dataclass(frozen=True, slots=True)
class LocatorRepairAuthority:
    validation: ValidationResult
    path: str
    expected_sha256: str
    original_locator: str
    verification: EvidenceItem
    classification: FailureClass
    classification_confidence: float


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_hex_digest(value: object, *, length: int = 64) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _is_prefixed_sha256(value: object, *, prefix: str = "sha256:") -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and _is_hex_digest(value.removeprefix(prefix))
    )


def _is_gate_sha256(value: object, prefix: str) -> bool:
    if not isinstance(value, str) or not value.startswith(prefix):
        return False
    return _is_hex_digest(value.removeprefix(prefix))


def _subject_gate_id(payload: dict[str, object]) -> str:
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "locator_repair:" + hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _normalized_pytest_selector(args: object) -> tuple[str, str, str]:
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise LocatorRepairAuthorityError("targeted pytest validation has malformed arguments")

    selectors: list[str] = []
    skip_next = False
    for item in args:
        if skip_next:
            skip_next = False
            continue
        if item in {"-k", "-m"} or item.startswith(("-k=", "-m=")):
            raise LocatorRepairAuthorityError(
                "locator repair requires one explicit pytest node selector without -k/-m filtering"
            )
        if item in {"--maxfail", "--tb"}:
            skip_next = True
            continue
        if item.startswith(("--maxfail=", "--tb=")) or item.startswith("-"):
            continue
        selectors.append(item)

    if len(selectors) != 1:
        raise LocatorRepairAuthorityError(
            "locator repair requires exactly one targeted pytest node selector"
        )

    selector = selectors[0].replace("\\", "/")
    while selector.startswith("./"):
        selector = selector[2:]
    if not selector or "\x00" in selector or "::" not in selector:
        raise LocatorRepairAuthorityError(
            "locator repair requires an explicit pytest test-node selector"
        )

    path_text, node_text = selector.split("::", 1)
    pure = PurePosixPath(path_text)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.as_posix() != path_text
        or pure.suffix.casefold() != ".py"
    ):
        raise LocatorRepairAuthorityError(
            "locator repair requires a safe relative Python pytest path"
        )
    node_parts = node_text.split("::")
    base_parts = [
        part.split("[", 1)[0] if index == len(node_parts) - 1 else part
        for index, part in enumerate(node_parts)
    ]
    if not node_parts or any(not part or not part.isidentifier() for part in base_parts):
        raise LocatorRepairAuthorityError(
            "locator repair pytest node identity is unsupported or ambiguous"
        )
    return selector, path_text, selector


def _selected_python_test_node(source: str, selector: str) -> ast.AST:
    node_parts = selector.split("::")[1:]
    names = [
        part.split("[", 1)[0] if index == len(node_parts) - 1 else part
        for index, part in enumerate(node_parts)
    ]
    try:
        body: list[ast.stmt] = ast.parse(source).body
    except SyntaxError as exc:
        raise LocatorRepairAuthorityError(
            "failing Python test subject is not syntactically valid"
        ) from exc

    selected: ast.AST | None = None
    for index, name in enumerate(names):
        matches = [
            item
            for item in body
            if isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == name
        ]
        if len(matches) != 1:
            raise LocatorRepairAuthorityError(
                "pytest node selector does not resolve to exactly one source test node"
            )
        selected = matches[0]
        if index < len(names) - 1:
            if not isinstance(selected, ast.ClassDef):
                raise LocatorRepairAuthorityError(
                    "pytest node hierarchy cannot be mapped to the Python test source"
                )
            body = selected.body
    if not isinstance(selected, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise LocatorRepairAuthorityError(
            "pytest selector must resolve to one concrete Python test function"
        )
    return selected


def _assert_locator_in_selected_node(source: str, selector: str, original_locator: str) -> None:
    node = _selected_python_test_node(source, selector)
    end_lineno = getattr(node, "end_lineno", None)
    if type(node.lineno) is not int or type(end_lineno) is not int:
        raise LocatorRepairAuthorityError(
            "Python test node does not expose complete source boundaries"
        )
    lines = source.splitlines(keepends=True)
    node_source = "".join(lines[node.lineno - 1 : end_lineno])
    if node_source.count(original_locator) != 1:
        raise LocatorRepairAuthorityError(
            "original locator is not uniquely contained in the selected failing pytest node"
        )


def _find_failure_validation(state: AgentRunState, validation_id: str) -> ValidationResult:
    matches = [item for item in state.validation_results if item.id == validation_id]
    if len(matches) != 1:
        raise LocatorRepairAuthorityError(
            "locator repair requires exactly one referenced failing pytest validation"
        )
    validation = matches[0]
    if (
        validation.name != "pytest"
        or validation.status is not ValidationStatus.FAIL
        or validation.revision != state.change_revision
        or validation.details.get("scope") != "targeted"
        or validation.details.get("execution_started") is not True
    ):
        raise LocatorRepairAuthorityError(
            "referenced validation is not an executed failing targeted pytest result at the current revision"
        )
    return validation


def _failure_evidence(
    state: AgentRunState,
    evidence: EvidenceStore,
    validation: ValidationResult,
) -> tuple[EvidenceItem, ...]:
    evidence_ids = tuple(validation.evidence_ids)
    if (
        not evidence_ids
        or len(evidence_ids) > _MAX_FAILURE_EVIDENCE_ITEMS
        or len(set(evidence_ids)) != len(evidence_ids)
    ):
        raise LocatorRepairAuthorityError("failing pytest evidence lineage is empty or ambiguous")

    items: list[EvidenceItem] = []
    for evidence_id in evidence_ids:
        if evidence_id not in state.evidence_ids:
            raise LocatorRepairAuthorityError(
                "failing pytest evidence is not registered in canonical run state"
            )
        try:
            item = evidence.get(evidence_id)
        except KeyError as exc:
            raise LocatorRepairAuthorityError(
                "failing pytest evidence is unavailable in the current run"
            ) from exc
        if item.run_id != state.run_id or item.nature is not EvidenceNature.OBSERVED_FACT:
            raise LocatorRepairAuthorityError(
                "failing pytest lineage contains non-observed or wrong-run evidence"
            )
        items.append(item)

    exit_items = [
        item
        for item in items
        if item.kind is EvidenceKind.EXIT_CODE
        and item.source == "pytest"
        and item.structured_data.get("exit_code") == 1
    ]
    if len(exit_items) != 1:
        raise LocatorRepairAuthorityError(
            "failing targeted pytest validation requires exactly one observed pytest exit-code failure"
        )
    if not any(item.kind is EvidenceKind.EXCEPTION and item.source == "pytest" for item in items):
        raise LocatorRepairAuthorityError(
            "failing targeted pytest validation is missing observed pytest failure evidence"
        )
    return tuple(items)


def _pytest_exit_item(items: tuple[EvidenceItem, ...]) -> EvidenceItem:
    matches = [
        item
        for item in items
        if item.kind is EvidenceKind.EXIT_CODE
        and item.source == "pytest"
        and item.structured_data.get("exit_code") == 1
    ]
    if len(matches) != 1:
        raise LocatorRepairAuthorityError("failing pytest workspace lineage is ambiguous")
    return matches[0]


def _assert_failure_workspace_binding(
    items: tuple[EvidenceItem, ...],
    *,
    git_sha: str,
    workspace_fingerprint: str,
) -> None:
    """Require the failure observation itself to cover the workspace now being repaired."""

    exit_item = _pytest_exit_item(items)
    data = exit_item.structured_data
    execution_subject = data.get("execution_subject")
    if (
        data.get("workspace_integrity_verified") is not True
        or data.get("workspace_fingerprint_before") != workspace_fingerprint
        or data.get("workspace_fingerprint_after") != workspace_fingerprint
        or not isinstance(execution_subject, dict)
        or execution_subject.get("git_sha") != git_sha
        or execution_subject.get("source_fingerprint") != workspace_fingerprint
    ):
        raise LocatorRepairAuthorityError(
            "failing pytest evidence is not bound to the current workspace revision and fingerprint"
        )


def _workspace_identity(
    workspace: Path,
    *,
    expected_root_identity: tuple[int, int] | None,
) -> tuple[str, str]:
    snapshot = RepositoryInspector(
        workspace,
        expected_root_identity=expected_root_identity,
    ).snapshot()
    if not snapshot.git_sha:
        raise LocatorRepairAuthorityError("locator repair requires a Git-backed workspace")
    if not snapshot.fingerprint_complete:
        raise LocatorRepairAuthorityError(
            "locator repair requires a complete workspace fingerprint"
        )
    if not snapshot.fingerprint:
        raise LocatorRepairAuthorityError("locator repair workspace fingerprint is unavailable")
    return snapshot.git_sha, snapshot.fingerprint


def prepare_locator_repair_binding(
    *,
    workspace: Path,
    expected_root_identity: tuple[int, int] | None,
    state: AgentRunState,
    evidence: EvidenceStore,
    policy: PolicyEngine,
    failure_validation_id: str,
    original_locator: str,
) -> LocatorRepairBinding:
    """Bind one locator investigation to the exact failing test node before browser work."""

    validation = _find_failure_validation(state, failure_validation_id)
    selector, path, failing_node_id = _normalized_pytest_selector(validation.details.get("args"))
    decision = policy.authorize_path(Path(path), write=False)
    state.policy_decisions.append(decision)
    if decision.decision is not ToolDecision.ALLOW:
        raise LocatorRepairAuthorityError(
            f"{decision.rule_id}: failing test path is not authorized for locator repair"
        )

    if parse_locator_expression(original_locator) is None:
        raise LocatorRepairAuthorityError(
            "original locator is not a supported literal Playwright locator expression"
        )
    failure_items = _failure_evidence(state, evidence, validation)
    git_sha, workspace_fingerprint = _workspace_identity(
        workspace,
        expected_root_identity=expected_root_identity,
    )
    if state.target_git_sha is not None and state.target_git_sha != git_sha:
        raise LocatorRepairAuthorityError(
            "current workspace Git revision does not match canonical target revision"
        )
    _assert_failure_workspace_binding(
        failure_items,
        git_sha=git_sha,
        workspace_fingerprint=workspace_fingerprint,
    )

    source = read_model_source_confined(
        workspace,
        path,
        expected_root_identity=expected_root_identity,
        label="locator repair test subject",
    )
    if source.text.count(original_locator) != 1:
        raise LocatorRepairAuthorityError(
            "original locator must occur exactly once in the failing test file"
        )
    _assert_locator_in_selected_node(source.text, selector, original_locator)

    return LocatorRepairBinding(
        revision=state.change_revision,
        failure_validation_id=validation.id,
        failure_gate_id=str(validation.gate_id or validation.name),
        path=path,
        pytest_selector=selector,
        failing_node_id=failing_node_id,
        failure_evidence_ids=tuple(validation.evidence_ids),
        failure_items=failure_items,
        git_sha=git_sha,
        workspace_fingerprint=workspace_fingerprint,
        expected_sha256=source.sha256,
        original_locator=original_locator,
        original_locator_hash=_sha256_text(original_locator),
        original_locator_offset=source.text.index(original_locator),
    )


def ensure_locator_repair_binding_fresh(
    binding: LocatorRepairBinding,
    *,
    workspace: Path,
    expected_root_identity: tuple[int, int] | None,
    state: AgentRunState,
) -> None:
    if state.change_revision != binding.revision:
        raise LocatorRepairAuthorityError(
            "locator repair subject revision changed before authority could be established"
        )
    git_sha, workspace_fingerprint = _workspace_identity(
        workspace,
        expected_root_identity=expected_root_identity,
    )
    if git_sha != binding.git_sha or workspace_fingerprint != binding.workspace_fingerprint:
        raise LocatorRepairAuthorityError(
            "workspace revision or fingerprint changed during locator repair evidence collection"
        )
    source = read_model_source_confined(
        workspace,
        binding.path,
        expected_root_identity=expected_root_identity,
        label="locator repair test subject",
    )
    if source.sha256 != binding.expected_sha256:
        raise LocatorRepairAuthorityError(
            "failing test bytes changed during locator repair evidence collection"
        )
    if (
        source.text.count(binding.original_locator) != 1
        or source.text.index(binding.original_locator) != binding.original_locator_offset
    ):
        raise LocatorRepairAuthorityError(
            "original locator occurrence changed during locator repair evidence collection"
        )
    _assert_locator_in_selected_node(
        source.text,
        binding.pytest_selector,
        binding.original_locator,
    )


def locator_verification_context(
    *,
    state: AgentRunState,
    evidence: EvidenceStore,
    verification: EvidenceItem,
) -> tuple[EvidenceItem, EvidenceItem]:
    if (
        verification.kind is not EvidenceKind.SOURCE_OBSERVATION
        or verification.nature is not EvidenceNature.OBSERVED_FACT
        or verification.source != "playwright_locator_verification"
        or verification.run_id != state.run_id
        or verification.id not in state.evidence_ids
    ):
        raise LocatorRepairAuthorityError(
            "locator repair requires authoritative Playwright locator verification from this run"
        )

    context_ids = verification.structured_data.get("context_evidence_ids")
    if (
        not isinstance(context_ids, list)
        or len(context_ids) != 2
        or not all(isinstance(item, str) and item for item in context_ids)
        or len(set(context_ids)) != 2
    ):
        raise LocatorRepairAuthorityError(
            "locator verification is missing exact same-DOM context evidence"
        )

    context: list[EvidenceItem] = []
    for evidence_id in context_ids:
        if evidence_id not in state.evidence_ids:
            raise LocatorRepairAuthorityError(
                "locator verification context is not registered in canonical run state"
            )
        try:
            item = evidence.get(evidence_id)
        except KeyError as exc:
            raise LocatorRepairAuthorityError(
                "locator verification context evidence is unavailable in this run"
            ) from exc
        context.append(item)

    if {item.kind for item in context} != {
        EvidenceKind.SCREENSHOT,
        EvidenceKind.ACCESSIBILITY_SNAPSHOT,
    }:
        raise LocatorRepairAuthorityError(
            "locator repair requires same-DOM screenshot and accessibility evidence"
        )
    if any(
        item.run_id != state.run_id
        or item.nature is not EvidenceNature.OBSERVED_FACT
        or item.source != "playwright_locator_verification"
        or item.source_identifier != verification.source_identifier
        for item in context
    ):
        raise LocatorRepairAuthorityError(
            "locator verification context does not share the authoritative Playwright page subject"
        )
    return context[0], context[1]


def _validate_browser_subject_details(details: dict[str, object], browser_gate_id: str) -> int:
    candidate_count = details.get("candidate_count")
    if (
        not _is_gate_sha256(browser_gate_id, "browser_locator_verification:")
        or not _is_prefixed_sha256(details.get("requested_url_hash"))
        or not _is_prefixed_sha256(details.get("candidate_request_hash"))
        or type(candidate_count) is not int
        or not 0 <= candidate_count <= _MAX_CANDIDATES
    ):
        raise LocatorRepairAuthorityError(
            "browser locator verification subject identity is malformed"
        )
    return candidate_count


def _validate_observed_candidates(verification: EvidenceItem, candidate_count: int) -> None:
    original_count = verification.structured_data.get("original_count")
    observed = verification.structured_data.get("candidates")
    if (
        type(original_count) is not int
        or original_count < 0
        or not isinstance(observed, list)
        or len(observed) != candidate_count
        or len(observed) > _MAX_CANDIDATES
        or not all(isinstance(row, dict) for row in observed)
    ):
        raise LocatorRepairAuthorityError(
            "Playwright locator observation does not match the bound browser request cardinality"
        )


def build_locator_repair_subject(
    binding: LocatorRepairBinding,
    *,
    workspace: Path,
    expected_root_identity: tuple[int, int] | None,
    state: AgentRunState,
    evidence: EvidenceStore,
    verification: EvidenceItem,
    browser_gate_id: str,
    browser_subject_details: dict[str, object],
) -> ValidationResult:
    """Create one deterministic repair authority subject from only bound evidence."""

    ensure_locator_repair_binding_fresh(
        binding,
        workspace=workspace,
        expected_root_identity=expected_root_identity,
        state=state,
    )
    candidate_count = _validate_browser_subject_details(
        browser_subject_details,
        browser_gate_id,
    )
    if browser_subject_details.get("original_locator_hash") != binding.original_locator_hash:
        raise LocatorRepairAuthorityError(
            "browser locator subject original identity does not match the failing test node"
        )
    if str(verification.structured_data.get("original_locator") or "") != binding.original_locator:
        raise LocatorRepairAuthorityError(
            "Playwright verification original locator does not match the failing test subject"
        )
    _validate_observed_candidates(verification, candidate_count)
    context = locator_verification_context(
        state=state,
        evidence=evidence,
        verification=verification,
    )
    bound_items = [*binding.failure_items, verification, *context]
    classification = FailureAnalyzer().classify(bound_items)
    expected_classification_ids = [item.id for item in bound_items]
    if classification.evidence_ids != expected_classification_ids:
        raise LocatorRepairAuthorityError(
            "deterministic locator classification did not preserve exact bound evidence lineage"
        )

    eligible = (
        classification.classification in _ALLOWED_REPAIR_CLASSES
        and classification.confidence >= _MIN_REPAIR_CONFIDENCE
    )
    payload: dict[str, object] = {
        "authority_version": _LOCATOR_REPAIR_AUTHORITY_VERSION,
        "run_id": state.run_id,
        "workspace_revision": binding.revision,
        "workspace_git_sha": binding.git_sha,
        "workspace_fingerprint": binding.workspace_fingerprint,
        "path": binding.path,
        "expected_sha256": binding.expected_sha256,
        "pytest_selector": binding.pytest_selector,
        "failing_node_id": binding.failing_node_id,
        "failure_validation_id": binding.failure_validation_id,
        "failure_gate_id": binding.failure_gate_id,
        "failure_evidence_ids": list(binding.failure_evidence_ids),
        "original_locator": binding.original_locator,
        "original_locator_hash": binding.original_locator_hash,
        "original_locator_offset": binding.original_locator_offset,
        "browser_gate_id": browser_gate_id,
        "requested_url_hash": browser_subject_details.get("requested_url_hash"),
        "candidate_request_hash": browser_subject_details.get("candidate_request_hash"),
        "candidate_count": candidate_count,
        "verification_evidence_id": verification.id,
        "context_evidence_ids": [item.id for item in context],
        "classification": classification.classification.value,
        "classification_confidence": classification.confidence,
        "classification_evidence_ids": list(classification.evidence_ids),
    }
    gate_id = _subject_gate_id(payload)
    details = {**payload, "repair_subject_id": gate_id}
    return ValidationResult(
        name="locator_repair_subject",
        gate_id=gate_id,
        revision=binding.revision,
        status=ValidationStatus.PASS if eligible else ValidationStatus.NOT_VERIFIED,
        summary=(
            "Locator repair evidence is bound to one failing test node and is eligible for deterministic proposal evaluation."
            if eligible
            else "Locator repair evidence is subject-bound, but the bound deterministic classification does not authorize autonomous repair."
        ),
        evidence_ids=list(classification.evidence_ids),
        details=details,
    )


def _subject_validation(state: AgentRunState, subject_id: str) -> ValidationResult:
    matches = [
        item
        for item in state.validation_results
        if item.name == "locator_repair_subject" and item.gate_id == subject_id
    ]
    if len(matches) != 1:
        raise LocatorRepairAuthorityError(
            "locator repair proposal must reference exactly one canonical repair subject"
        )
    subject = matches[0]
    if (
        not _is_gate_sha256(subject_id, "locator_repair:")
        or subject.status is not ValidationStatus.PASS
        or subject.revision != state.change_revision
        or subject.details.get("authority_version") != _LOCATOR_REPAIR_AUTHORITY_VERSION
        or subject.details.get("repair_subject_id") != subject_id
        or subject.details.get("run_id") != state.run_id
        or subject.details.get("workspace_revision") != state.change_revision
    ):
        raise LocatorRepairAuthorityError(
            "locator repair subject is not an active verified authority at the current revision"
        )
    return subject


def resolve_locator_repair_authority(
    *,
    subject_id: str,
    workspace: Path,
    expected_root_identity: tuple[int, int] | None,
    state: AgentRunState,
    evidence: EvidenceStore,
) -> LocatorRepairAuthority:
    """Revalidate a persisted repair subject against current revision, bytes, and evidence."""

    subject = _subject_validation(state, subject_id)
    details = subject.details
    unsigned_details = {key: value for key, value in details.items() if key != "repair_subject_id"}
    if _subject_gate_id(unsigned_details) != subject_id:
        raise LocatorRepairAuthorityError(
            "locator repair subject identity does not match its payload"
        )

    path = details.get("path")
    expected_sha256 = details.get("expected_sha256")
    original_locator = details.get("original_locator")
    original_locator_hash = details.get("original_locator_hash")
    original_locator_offset = details.get("original_locator_offset")
    failing_node_id = details.get("failing_node_id")
    if (
        not isinstance(path, str)
        or not path
        or not _is_hex_digest(expected_sha256)
        or not isinstance(original_locator, str)
        or not original_locator
        or not _is_prefixed_sha256(original_locator_hash)
        or original_locator_hash != _sha256_text(original_locator)
        or type(original_locator_offset) is not int
        or original_locator_offset < 0
        or not isinstance(failing_node_id, str)
        or not failing_node_id
    ):
        raise LocatorRepairAuthorityError(
            "locator repair subject contains malformed test-file authority"
        )

    failure_validation_id = details.get("failure_validation_id")
    if not isinstance(failure_validation_id, str) or not failure_validation_id:
        raise LocatorRepairAuthorityError("locator repair subject lost failing pytest identity")
    failure_validation = _find_failure_validation(state, failure_validation_id)
    selector, failure_path, current_node_id = _normalized_pytest_selector(
        failure_validation.details.get("args")
    )
    failure_gate_id = str(failure_validation.gate_id or failure_validation.name)
    if (
        failure_path != path
        or selector != details.get("pytest_selector")
        or current_node_id != failing_node_id
        or failure_gate_id != details.get("failure_gate_id")
        or list(failure_validation.evidence_ids) != details.get("failure_evidence_ids")
    ):
        raise LocatorRepairAuthorityError(
            "locator repair subject no longer matches the referenced failing pytest validation"
        )
    failure_items = _failure_evidence(state, evidence, failure_validation)

    verification_evidence_id = details.get("verification_evidence_id")
    if not isinstance(verification_evidence_id, str) or not verification_evidence_id:
        raise LocatorRepairAuthorityError(
            "locator repair subject lost Playwright verification identity"
        )
    try:
        verification = evidence.get(verification_evidence_id)
    except KeyError as exc:
        raise LocatorRepairAuthorityError(
            "locator repair Playwright verification is unavailable in this run"
        ) from exc
    context = locator_verification_context(
        state=state,
        evidence=evidence,
        verification=verification,
    )
    if str(verification.structured_data.get("original_locator") or "") != original_locator:
        raise LocatorRepairAuthorityError(
            "locator repair subject original locator no longer matches Playwright verification"
        )
    if [item.id for item in context] != details.get("context_evidence_ids"):
        raise LocatorRepairAuthorityError(
            "locator repair subject same-DOM context identity no longer matches verification"
        )

    browser_gate_id = details.get("browser_gate_id")
    if not isinstance(browser_gate_id, str):
        raise LocatorRepairAuthorityError("locator repair subject browser gate identity is malformed")
    candidate_count = _validate_browser_subject_details(details, browser_gate_id)
    if details.get("original_locator_hash") != original_locator_hash:
        raise LocatorRepairAuthorityError(
            "locator repair subject original locator digest is inconsistent"
        )
    _validate_observed_candidates(verification, candidate_count)
    browser_matches = [
        item
        for item in state.validation_results
        if item.name == "browser_locator_verification"
        and item.gate_id == browser_gate_id
        and item.revision == state.change_revision
        and item.status is ValidationStatus.PASS
    ]
    if len(browser_matches) != 1:
        raise LocatorRepairAuthorityError(
            "locator repair subject is not backed by exactly one active browser verification gate"
        )
    browser_validation = browser_matches[0]
    required_browser_evidence = [verification.id, *[item.id for item in context]]
    if browser_validation.evidence_ids != required_browser_evidence:
        raise LocatorRepairAuthorityError(
            "browser verification gate evidence does not match locator repair subject"
        )
    expected_browser_details = {
        "operation": "verify_locator_candidates",
        "requested_url_hash": details.get("requested_url_hash"),
        "original_locator_hash": original_locator_hash,
        "candidate_count": candidate_count,
        "candidate_request_hash": details.get("candidate_request_hash"),
        "repair_subject_id": subject_id,
        "failure_validation_id": failure_validation_id,
        "failing_node_id": failing_node_id,
        "path": path,
        "workspace_revision": state.change_revision,
        "workspace_git_sha": details.get("workspace_git_sha"),
        "workspace_fingerprint": details.get("workspace_fingerprint"),
        "expected_sha256": expected_sha256,
    }
    if any(
        browser_validation.details.get(key) != value
        for key, value in expected_browser_details.items()
    ):
        raise LocatorRepairAuthorityError(
            "browser verification gate metadata does not match locator repair subject"
        )

    expected_bound_ids = [
        *list(failure_validation.evidence_ids),
        verification.id,
        *[item.id for item in context],
    ]
    if (
        details.get("classification_evidence_ids") != expected_bound_ids
        or subject.evidence_ids != expected_bound_ids
    ):
        raise LocatorRepairAuthorityError(
            "locator repair classification is not bound to the exact failure/browser evidence subset"
        )
    replayed = FailureAnalyzer().classify([*failure_items, verification, *context])
    if replayed.evidence_ids != expected_bound_ids:
        raise LocatorRepairAuthorityError(
            "replayed locator classification did not preserve exact evidence lineage"
        )
    stored_classification = details.get("classification")
    stored_confidence = details.get("classification_confidence")
    if (
        stored_classification != replayed.classification.value
        or not isinstance(stored_confidence, (int, float))
        or isinstance(stored_confidence, bool)
        or float(stored_confidence) != replayed.confidence
    ):
        raise LocatorRepairAuthorityError(
            "persisted locator classification does not reproduce from bound evidence"
        )
    if (
        replayed.classification not in _ALLOWED_REPAIR_CLASSES
        or replayed.confidence < _MIN_REPAIR_CONFIDENCE
    ):
        raise LocatorRepairAuthorityError(
            "replayed locator classification does not authorize autonomous repair"
        )

    git_sha, workspace_fingerprint = _workspace_identity(
        workspace,
        expected_root_identity=expected_root_identity,
    )
    if state.target_git_sha is not None and state.target_git_sha != git_sha:
        raise LocatorRepairAuthorityError(
            "current workspace Git revision does not match canonical target revision"
        )
    if git_sha != details.get("workspace_git_sha") or workspace_fingerprint != details.get(
        "workspace_fingerprint"
    ):
        raise LocatorRepairAuthorityError(
            "workspace revision or fingerprint changed since locator repair evidence was bound"
        )
    _assert_failure_workspace_binding(
        failure_items,
        git_sha=git_sha,
        workspace_fingerprint=workspace_fingerprint,
    )
    source = read_model_source_confined(
        workspace,
        path,
        expected_root_identity=expected_root_identity,
        label="locator repair test subject",
    )
    if source.sha256 != expected_sha256:
        raise LocatorRepairAuthorityError(
            "test file changed since locator repair evidence was bound"
        )
    if (
        source.text.count(original_locator) != 1
        or source.text.index(original_locator) != original_locator_offset
    ):
        raise LocatorRepairAuthorityError(
            "original locator occurrence changed since locator repair evidence was bound"
        )
    _assert_locator_in_selected_node(source.text, selector, original_locator)

    return LocatorRepairAuthority(
        validation=subject,
        path=path,
        expected_sha256=expected_sha256,
        original_locator=original_locator,
        verification=verification,
        classification=replayed.classification,
        classification_confidence=replayed.confidence,
    )
