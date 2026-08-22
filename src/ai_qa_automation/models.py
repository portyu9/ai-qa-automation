from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


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
    PASS = "PASS"
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
    name: str
    layer: TestLayer
    risk: RiskLevel
    purpose: str
    assertions: list[str]
    tags: list[str] = Field(default_factory=list)


class TestGenerationPlan(FrozenModel):
    requirement_summary: str
    coverage_gaps: list[str]
    scenarios: list[TestScenario]
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


class AgentRunState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(default_factory=lambda: f"run-{uuid4().hex[:12]}")
    session_id: str = Field(default_factory=lambda: f"session-{uuid4().hex[:10]}")
    objective: str
    agent_version: str = "0.1.0"
    model_id: str = "not-invoked"
    sdk_version: str = "NOT_VERIFIED"
    policy_version: str = "2"
    tool_schema_version: str = "2"
    configuration_version: str = "NOT_CAPTURED"
    target_repository: str | None = None
    target_git_sha: str | None = None
    workspace: str
    phase: str = "INITIALIZE"
    iteration: int = 0
    change_revision: int = 0
    tool_call_count: int = 0
    retry_count: int = 0
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
    token_usage: int = 0
    cost: float = 0.0
    duration: float = 0.0
    terminal_status: TerminalStatus | None = None
    terminal_reason: str | None = None

    @field_validator("workspace")
    @classmethod
    def normalize_workspace(cls, value: str) -> str:
        return str(Path(value).expanduser())


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
    provenance: dict[str, str] = Field(default_factory=dict)
