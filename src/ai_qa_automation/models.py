from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class TerminalStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    BLOCKED = "BLOCKED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    POLICY_DENIED = "POLICY_DENIED"
    INFRASTRUCTURE_FAILURE = "INFRASTRUCTURE_FAILURE"
    CANCELLED = "CANCELLED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    NOT_VERIFIED = "NOT_VERIFIED"


class ValidationStatus(StrEnum):
    PASS = "PASS"  # nosec B105 - deterministic validation state, not a credential
    FAIL = "FAIL"
    NOT_EXECUTED = "NOT_EXECUTED"
    NOT_OBSERVED = "NOT_OBSERVED"
    NOT_VERIFIED = "NOT_VERIFIED"
    BLOCKED = "BLOCKED"


class EvidenceKind(StrEnum):
    ASSERTION = "assertion"
    EXCEPTION = "exception"
    STACK_TRACE = "stack_trace"
    EXIT_CODE = "exit_code"
    HTTP_RESPONSE = "http_response"
    SCHEMA_MISMATCH = "schema_mismatch"
    DOM_SNAPSHOT = "dom_snapshot"
    ACCESSIBILITY_SNAPSHOT = "accessibility_snapshot"
    SCREENSHOT = "screenshot"
    PLAYWRIGHT_TRACE = "playwright_trace"
    CONSOLE_ERROR = "console_error"
    NETWORK_ERROR = "network_error"
    GIT_DIFF = "git_diff"
    CI_RESULT = "ci_result"
    MCP_RESULT = "mcp_result"
    REQUIREMENT = "requirement"
    SOURCE_OBSERVATION = "source_observation"
    PERFORMANCE_METRIC = "performance_metric"
    POLICY_EVENT = "policy_event"
    HEALING_PROPOSAL = "healing_proposal"
    TEST_PLAN = "test_plan"
    TEST_GENERATION_PROPOSAL = "test_generation_proposal"


class EvidenceNature(StrEnum):
    OBSERVED_FACT = "OBSERVED_FACT"
    MODEL_INTERPRETATION = "MODEL_INTERPRETATION"


class EvidenceReliability(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class SanitizationStatus(StrEnum):
    RAW = "RAW"
    SANITIZED = "SANITIZED"
    REDACTED = "REDACTED"


class FailureClass(StrEnum):
    APPLICATION_DEFECT = "APPLICATION_DEFECT"
    TEST_AUTOMATION_DEFECT = "TEST_AUTOMATION_DEFECT"
    LOCATOR_UI_CONTRACT_CHANGE = "LOCATOR_UI_CONTRACT_CHANGE"
    TEST_DATA_FAILURE = "TEST_DATA_FAILURE"
    FLAKINESS_TIMING = "FLAKINESS_TIMING"
    ENVIRONMENT_FAILURE = "ENVIRONMENT_FAILURE"
    EXTERNAL_DEPENDENCY_FAILURE = "EXTERNAL_DEPENDENCY_FAILURE"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    CONFIGURATION_FAILURE = "CONFIGURATION_FAILURE"
    PERFORMANCE_REGRESSION = "PERFORMANCE_REGRESSION"
    UNKNOWN = "UNKNOWN"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class MCPStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNAUTHORIZED = "UNAUTHORIZED"
    RATE_LIMITED = "RATE_LIMITED"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    FAILED = "FAILED"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ToolDecision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class EvidenceItem(FrozenModel):
    id: str = Field(default_factory=lambda: f"ev-{uuid4().hex[:12]}")
    run_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    kind: EvidenceKind
    nature: EvidenceNature = EvidenceNature.OBSERVED_FACT
    source: str
    source_identifier: str | None = None
    summary: str
    structured_data: dict[str, Any] = Field(default_factory=dict)
    artifact_reference: str | None = None
    content_hash: str | None = None
    reliability: EvidenceReliability = EvidenceReliability.HIGH
    sanitization_status: SanitizationStatus = SanitizationStatus.SANITIZED
    related_hypothesis: str | None = None


class PolicyDecision(FrozenModel):
    decision: ToolDecision
    reason: str
    rule_id: str
    risk: RiskLevel


class ValidationResult(FrozenModel):
    id: str = Field(default_factory=lambda: f"val-{uuid4().hex[:12]}")
    name: str
    gate_id: str | None = None
    revision: int = Field(default=0, ge=0)
    status: ValidationStatus
    summary: str
    evidence_ids: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class Hypothesis(FrozenModel):
    id: str
    statement: str
    confidence: float = Field(ge=0, le=1)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    next_discriminating_action: str | None = None


class FailureClassificationResult(FrozenModel):
    classification: FailureClass
    confidence: float = Field(ge=0, le=1)
    rationale: str
    evidence_ids: list[str]
    competing_hypotheses: list[Hypothesis] = Field(default_factory=list)


class LocatorCandidate(FrozenModel):
    locator: str
    strategy: str
    uniqueness_count: int = Field(ge=0)
    semantic_match: float = Field(ge=0, le=1)
    stability_score: float = Field(ge=0, le=1)
    rejected_reason: str | None = None

    @property
    def score(self) -> float:
        if self.rejected_reason or self.uniqueness_count != 1:
            return 0.0
        return round((self.semantic_match * 0.6) + (self.stability_score * 0.4), 4)


class HealingProposal(FrozenModel):
    allowed: bool
    risk: RiskLevel
    original_locator: str
    proposed_locator: str | None = None
    rationale: str
    evidence_ids: list[str]
    required_validations: list[str] = Field(default_factory=list)


class TestLayer(StrEnum):
    UNIT = "unit"
    COMPONENT = "component"
    API = "api"
    INTEGRATION = "integration"
    UI = "ui"


class TestScenario(FrozenModel):
    scenario_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    assertion_contract_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    name: str
    layer: TestLayer
    risk: RiskLevel
    purpose: str
    assertions: list[str]
    tags: list[str] = Field(default_factory=list)


class TestGenerationPlan(FrozenModel):
    requirement_summary: str
    requirement_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    coverage_gaps: list[str]
    scenarios: list[TestScenario]
    selected_scenario_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    duplicate_risk: str
    validation_plan: list[str]


class RegressionCandidate(FrozenModel):
    test_id: str
    changed_component_overlap: float = Field(default=0, ge=0, le=1)
    dependency_overlap: float = Field(default=0, ge=0, le=1)
    historical_failure_rate: float = Field(default=0, ge=0, le=1)
    business_criticality: float = Field(default=0, ge=0, le=1)
    security_criticality: float = Field(default=0, ge=0, le=1)
    safety_criticality: float = Field(default=0, ge=0, le=1)
    regulatory_criticality: float = Field(default=0, ge=0, le=1)
    runtime_seconds: float = Field(default=0, ge=0)
    mandatory: bool = False
    smoke: bool = False
    security_critical: bool = False
    safety_critical: bool = False
    regulatory_critical: bool = False
    rationale: list[str] = Field(default_factory=list)


class RegressionSelection(FrozenModel):
    selected: list[str]
    omitted: list[str]
    rationale_by_test: dict[str, str]
    estimated_reduction_ratio: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    broadened_due_to_uncertainty: bool = False


class PerformanceMetrics(FrozenModel):
    p50_ms: float = Field(ge=0)
    p90_ms: float = Field(ge=0)
    p95_ms: float = Field(ge=0)
    p99_ms: float = Field(ge=0)
    request_rate: float = Field(ge=0)
    error_rate: float = Field(ge=0, le=1)


class PerformanceAssessment(FrozenModel):
    status: ValidationStatus
    metrics: PerformanceMetrics | None = None
    breached_thresholds: list[str] = Field(default_factory=list)
    summary: str


class AgentDecision(FrozenModel):
    action: str
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)
    tool_name: str | None = None
    tool_input: dict[str, Any] = Field(default_factory=dict)
    terminal_status: TerminalStatus | None = None


class ArtifactRecord(FrozenModel):
    artifact_id: str = Field(default_factory=lambda: f"artifact-{uuid4().hex[:12]}")
    type: str
    path: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    originating_tool: str
    content_hash: str
    sanitization_status: SanitizationStatus
    retention_classification: str = "standard"


class ControlPlaneRevalidationStatus(StrEnum):
    NOT_CAPTURED = "NOT_CAPTURED"
    BOUND = "BOUND"
    VERIFIED = "VERIFIED"
    DRIFTED = "DRIFTED"
    UNAVAILABLE = "UNAVAILABLE"


_MAX_CONTROL_PLANE_PATH_BYTES = 4096
_MAX_CONTROL_PLANE_MANIFEST_ENTRIES = 8192
_MAX_CONTROL_PLANE_MANIFEST_METADATA_BYTES = 4_000_000


def _control_plane_canonical_bytes(payload: object) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _control_plane_canonical_digest(payload: object) -> str:
    canonical = _control_plane_canonical_bytes(payload)
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _validate_control_plane_relative_path(value: str, *, label: str) -> str:
    if "\\" in value:
        raise ValueError(f"{label} must use canonical POSIX separators")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value in {"", "."}
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{label} must be a canonical relative path")
    if path.as_posix() != value:
        raise ValueError(f"{label} must be a canonical relative path")
    if len(value.encode("utf-8")) > _MAX_CONTROL_PLANE_PATH_BYTES:
        raise ValueError(f"{label} exceeds the UTF-8 path-length bound")
    return value


class ControlPlaneFileSubject(FrozenModel):
    path: str = Field(min_length=1, max_length=4096)
    size: int = Field(ge=0)
    content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("path")
    @classmethod
    def canonical_path(cls, value: str) -> str:
        return _validate_control_plane_relative_path(value, label="control-plane file path")


class ControlPlaneManifest(FrozenModel):
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    files: tuple[ControlPlaneFileSubject, ...] = Field(
        max_length=_MAX_CONTROL_PLANE_MANIFEST_ENTRIES
    )
    directories: tuple[str, ...] = Field(
        default=(), max_length=_MAX_CONTROL_PLANE_MANIFEST_ENTRIES
    )
    absent_paths: tuple[str, ...] = Field(
        default=(), max_length=_MAX_CONTROL_PLANE_MANIFEST_ENTRIES
    )
    total_bytes: int = Field(ge=0)

    @field_validator("directories", "absent_paths")
    @classmethod
    def canonical_paths(cls, values: tuple[str, ...], info: ValidationInfo) -> tuple[str, ...]:
        # Directory root marker is represented as '.' only inside the controller tree
        # manifest; all persisted authority paths otherwise remain canonical relatives.
        field_name = info.field_name or "paths"
        normalized: list[str] = []
        for value in values:
            if field_name == "directories" and value == ".":
                normalized.append(value)
            else:
                normalized.append(
                    _validate_control_plane_relative_path(
                        value, label=f"control-plane {field_name[:-1]} path"
                    )
                )
        return tuple(normalized)

    @model_validator(mode="after")
    def validate_manifest_identity(self) -> ControlPlaneManifest:
        file_paths = tuple(item.path for item in self.files)
        if file_paths != tuple(sorted(file_paths)) or len(set(file_paths)) != len(file_paths):
            raise ValueError("control-plane manifest files must be uniquely path-sorted")
        if self.directories != tuple(sorted(self.directories)) or len(set(self.directories)) != len(
            self.directories
        ):
            raise ValueError("control-plane manifest directories must be uniquely path-sorted")
        if self.absent_paths != tuple(sorted(self.absent_paths)) or len(
            set(self.absent_paths)
        ) != len(self.absent_paths):
            raise ValueError("control-plane manifest absent paths must be uniquely path-sorted")
        if set(file_paths) & set(self.absent_paths):
            raise ValueError("control-plane manifest path cannot be both present and absent")
        if self.total_bytes != sum(item.size for item in self.files):
            raise ValueError("control-plane manifest total_bytes does not match file subjects")
        payload = {
            "files": [item.model_dump(mode="json") for item in self.files],
            "directories": list(self.directories),
            "absent_paths": list(self.absent_paths),
        }
        canonical = _control_plane_canonical_bytes(payload)
        if len(canonical) > _MAX_CONTROL_PLANE_MANIFEST_METADATA_BYTES:
            raise ValueError("control-plane manifest exceeds metadata serialization bound")
        expected_digest = f"sha256:{hashlib.sha256(canonical).hexdigest()}"
        if self.digest != expected_digest:
            raise ValueError("control-plane manifest digest does not match its file subjects")
        return self


class ControlPlaneSubject(FrozenModel):
    format_version: str = "ai-qa-control-plane-subject/v1"
    subject_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    project_manifest: ControlPlaneManifest
    controller_manifest: ControlPlaneManifest
    control_git_sha: str | None = Field(
        default=None, pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
    )
    control_git_clean: bool | None = None

    @model_validator(mode="after")
    def validate_subject_identity(self) -> ControlPlaneSubject:
        if self.format_version != "ai-qa-control-plane-subject/v1":
            raise ValueError("unsupported control-plane subject format")
        if self.control_git_clean is not None and self.control_git_sha is None:
            raise ValueError("control Git cleanliness requires an exact commit SHA")
        payload = {
            "schema": self.format_version,
            "project_manifest_digest": self.project_manifest.digest,
            "controller_manifest_digest": self.controller_manifest.digest,
        }
        if self.subject_digest != _control_plane_canonical_digest(payload):
            raise ValueError("control-plane subject digest does not match its manifests")
        return self


class AgentRunState(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    run_id: str = Field(default_factory=lambda: f"run-{uuid4().hex[:12]}")
    session_id: str = Field(default_factory=lambda: f"session-{uuid4().hex[:10]}")
    objective: str
    objective_gate_id: str | None = Field(default=None, max_length=256)
    agent_version: str = "0.1.0"
    model_id: str = "not-invoked"
    sdk_version: str = "NOT_VERIFIED"
    policy_version: str = "2"
    tool_schema_version: str = "2"
    configuration_version: str = "NOT_CAPTURED"
    control_plane_subject: ControlPlaneSubject | None = None
    control_plane_revalidation_status: ControlPlaneRevalidationStatus = (
        ControlPlaneRevalidationStatus.NOT_CAPTURED
    )
    control_plane_terminal_subject_digest: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    target_repository: str | None = None
    target_git_sha: str | None = None
    workspace: str
    phase: str = "INITIALIZE"
    iteration: int = Field(default=0, ge=0)
    change_revision: int = Field(default=0, ge=0)
    tool_call_count: int = Field(default=0, ge=0)
    retry_count: int = Field(default=0, ge=0)
    observations: list[str] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    classification: FailureClass | None = None
    classification_confidence: float | None = Field(default=None, ge=0, le=1)
    files_read: list[str] = Field(default_factory=list)
    files_modified: list[str] = Field(default_factory=list)
    tests_executed: list[str] = Field(default_factory=list)
    validation_results: list[ValidationResult] = Field(default_factory=list)
    mcp_status: dict[str, MCPStatus] = Field(default_factory=dict)
    external_evidence: list[str] = Field(default_factory=list)
    policy_decisions: list[PolicyDecision] = Field(default_factory=list)
    token_usage: int = Field(default=0, ge=0)
    cost: float = Field(default=0.0, ge=0)
    duration: float = Field(default=0.0, ge=0)
    terminal_status: TerminalStatus | None = None
    terminal_reason: str | None = None

    @field_validator("workspace")
    @classmethod
    def normalize_workspace(cls, value: str) -> str:
        return str(Path(value).expanduser())

    @field_validator("objective_gate_id")
    @classmethod
    def normalize_objective_gate_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("objective_gate_id must not be empty when supplied")
        return normalized


class FinalAgentReport(FrozenModel):
    run_id: str
    objective: str
    terminal_status: TerminalStatus
    summary: str
    classification: FailureClass | None = None
    classification_confidence: float | None = Field(default=None, ge=0, le=1)
    evidence_ids: list[str] = Field(default_factory=list)
    validation_results: list[ValidationResult] = Field(default_factory=list)
    files_modified: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
