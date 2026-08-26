from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..evidence import EvidenceStore
from ..intelligence.ci_analysis import analyze_ci_failure
from ..intelligence.failure_analysis import FailureAnalyzer
from ..intelligence.performance import PerformanceAssessor
from ..intelligence.prioritization import RegressionPrioritizer
from ..intelligence.quality_review import review_python_test_source
from ..intelligence.self_healing import SelfHealingEngine
from ..intelligence.test_generation import TestGenerationPlanner
from ..models import (
    AgentRunState,
    EvidenceItem,
    EvidenceKind,
    EvidenceNature,
    FailureClass,
    LocatorCandidate,
    RegressionCandidate,
    RiskLevel,
    ValidationResult,
    ValidationStatus,
)
from ..policy import PolicyEngine
from ..redaction import redact_text
from ..state import StateStore
from ..tools.api_testing import ApiProbe, ApiProbeTransportError
from ..tools.browser_evidence import BrowserProbe, BrowserProbeExecutionError
from ..tools.contracts import validate_json_schema
from ..tools.mobile import MobileRuntimeInspector
from ..tools.performance import K6Runner
from ..tools.repository import RepositoryInspector
from ..tools.safe_patch import SafeTestPatcher
from ..tools.test_execution import TestRunner
from .browser_validation import (
    browser_inspection_subject,
    browser_locator_verification_subject,
    browser_validation_result,
)
from .model_source_observation import (
    CoverageSearchObservation,
    read_model_source_confined,
    search_test_coverage_confined,
)

_MAX_MODEL_SOURCE_CHARS = 12_000


def _stable_gate_id(prefix: str, payload: Any) -> str:
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _pytest_scope(args: list[str]) -> str:
    """Classify pytest as full regression or filtered/targeted execution."""
    selectors: list[str] = []
    filtered = False
    skip_next = False
    for raw in args:
        item = str(raw)
        if skip_next:
            skip_next = False
            continue
        if item in {"-k", "-m"}:
            filtered = True
            skip_next = True
            continue
        if item in {"--maxfail", "--tb"}:
            skip_next = True
            continue
        if item.startswith(("-k=", "-m=")):
            filtered = True
            continue
        if item.startswith(("--maxfail=", "--tb=")) or item.startswith("-"):
            continue
        selectors.append(item)
    return "targeted" if filtered or selectors else "regression"


def _change_revision_closed(state: AgentRunState) -> bool:
    """Require exact mutation-subject closure before another mutation begins."""
    if state.change_revision == 0:
        return True
    current = [item for item in state.validation_results if item.revision == state.change_revision]
    if not current or any(item.status != ValidationStatus.PASS for item in current):
        return False
    patch_paths = {
        str(item.details.get("path") or "")
        for item in current
        if item.name == "test_patch_safety"
        and item.status == ValidationStatus.PASS
        and str(item.details.get("path") or "")
    }
    if len(patch_paths) != 1:
        return False
    mutation_path = next(iter(patch_paths))
    targeted = any(
        item.name == "pytest"
        and item.status == ValidationStatus.PASS
        and item.details.get("scope") == "targeted"
        and item.details.get("mutation_target_bound") is True
        and item.details.get("mutation_target") == mutation_path
        for item in current
    )
    regression = any(
        item.name == "pytest"
        and item.status == ValidationStatus.PASS
        and item.details.get("scope") == "regression"
        for item in current
    )
    return targeted and regression


def _require_closed_revision_before_mutation(services: RuntimeServices) -> str | None:
    if _change_revision_closed(services.state):
        return None
    return (
        f"change revision {services.state.change_revision} is not closed; "
        "run an exact-path-bound targeted pytest gate and a passing full regression before another mutation"
    )


def _pytest_validation_status(exit_code: int) -> ValidationStatus:
    if exit_code == 0:
        return ValidationStatus.PASS
    if exit_code == 1:
        return ValidationStatus.FAIL
    return ValidationStatus.NOT_VERIFIED


def _coverage_search(
    workspace: Path,
    *,
    query: str,
    max_results: int = 100,
    max_scan_files: int = 5_000,
    expected_root_identity: tuple[int, int] | None = None,
) -> CoverageSearchObservation:
    return search_test_coverage_confined(
        workspace,
        query=query,
        max_results=max_results,
        max_scan_entries=max_scan_files,
        expected_root_identity=expected_root_identity,
    )


def _record_patch_safety_validation(
    services: RuntimeServices,
    *,
    path: str,
    evidence_id: str,
    summary: str,
) -> None:
    services.state.validation_results.append(
        ValidationResult(
            name="test_patch_safety",
            gate_id=f"test_patch_safety:{path}",
            revision=services.state.change_revision,
            status=ValidationStatus.PASS,
            summary=summary,
            evidence_ids=[evidence_id],
            details={"path": path, "scope": "static_patch_safety"},
        )
    )


@dataclass
class RuntimeServices:
    workspace: Path
    state: AgentRunState
    evidence: EvidenceStore
    policy: PolicyEngine
    test_runner: TestRunner
    max_tool_calls: int
    max_repeated_action: int
    allowed_network_hosts: set[str] = field(default_factory=set)
    allow_external_network: bool = False
    allow_mutating_api_methods: bool = False
    k6_external_egress_enforced: bool = False
    state_store: StateStore | None = None
    workspace_root_identity: tuple[int, int] | None = None
    _fingerprints: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name, value in {
            "max_tool_calls": self.max_tool_calls,
            "max_repeated_action": self.max_repeated_action,
        }.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name, value in {
            "allow_external_network": self.allow_external_network,
            "allow_mutating_api_methods": self.allow_mutating_api_methods,
            "k6_external_egress_enforced": self.k6_external_egress_enforced,
        }.items():
            if not isinstance(value, bool):
                raise ValueError(f"{name} must be a boolean")
        if self.workspace_root_identity is not None and (
            not isinstance(self.workspace_root_identity, tuple)
            or len(self.workspace_root_identity) != 2
            or any(type(part) is not int or part < 0 for part in self.workspace_root_identity)
        ):
            raise ValueError("workspace_root_identity must be a (device, inode) integer tuple")

    def consume(self, tool_name: str, tool_input: dict[str, Any]) -> None:
        if self.state.tool_call_count >= self.max_tool_calls:
            raise RuntimeError("tool-call budget exhausted")
        payload = json.dumps(tool_input, sort_keys=True, default=str)
        fingerprint = hashlib.sha256(f"{tool_name}:{payload}".encode()).hexdigest()
        seen = self._fingerprints.get(fingerprint, 0) + 1
        self._fingerprints[fingerprint] = seen
        if seen > self.max_repeated_action:
            raise RuntimeError("repeated identical action budget exhausted")
        self.state.tool_call_count += 1
        self.checkpoint()

    def checkpoint(self) -> None:
        if self.state_store is not None:
            self.state_store.save(self.state)

    def network_hosts(self, url: str) -> set[str]:
        host = (urlparse(url).hostname or "").lower()
        if not host or host not in self.allowed_network_hosts:
            raise PermissionError(
                f"network host is not explicitly allowlisted: {host or '<missing>'}"
            )
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if not self.allow_external_network and host not in local_hosts:
            raise PermissionError("external network access is disabled")
        if not self.allow_external_network:
            return self.allowed_network_hosts & local_hosts
        return set(self.allowed_network_hosts)


def build_internal_mcp_server(services: RuntimeServices) -> tuple[Any, list[str]]:
    """Create trusted in-process MCP tools owned by this application."""
    try:
        from claude_agent_sdk import create_sdk_mcp_server, tool
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("claude-agent-sdk is required for live agent mode") from exc

    @tool("inspect_repository", "Inspect target Git metadata without modifying it.", {})
    async def inspect_repository(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("inspect_repository", args)
        snapshot = RepositoryInspector(services.workspace).snapshot()
        item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.SOURCE_OBSERVATION,
                nature=EvidenceNature.OBSERVED_FACT,
                source="repository",
                summary="Observed target repository state",
                structured_data={
                    "git_sha": snapshot.git_sha,
                    "branch": snapshot.branch,
                    "dirty": bool(snapshot.status),
                    "changed_files": list(snapshot.changed_files),
                    "fingerprint_complete": snapshot.fingerprint_complete,
                    "fingerprint_incomplete_reasons": list(snapshot.fingerprint_incomplete_reasons),
                },
            )
        )
        services.state.evidence_ids.append(item.id)
        services.state.target_git_sha = snapshot.git_sha
        services.checkpoint()
        return {"content": [{"type": "text", "text": item.model_dump_json()}]}

    @tool(
        "run_pytest",
        "Execute pytest in the isolated target workspace and capture deterministic evidence.",
        {"args": list[str]},
    )
    async def run_pytest(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("run_pytest", args)
        pytest_args = [str(item) for item in (args.get("args") or [])]
        result = services.test_runner.run_pytest(pytest_args)
        services.state.tests_executed.append(" ".join(result.command))
        services.state.evidence_ids.extend(
            eid for eid in result.evidence_ids if eid not in services.state.evidence_ids
        )
        status = _pytest_validation_status(result.exit_code)
        services.state.validation_results.append(
            ValidationResult(
                name="pytest",
                gate_id=_stable_gate_id("pytest", pytest_args),
                revision=services.state.change_revision,
                status=status,
                summary=f"pytest exited with {result.exit_code}",
                evidence_ids=list(result.evidence_ids),
                details={
                    "duration_seconds": result.duration_seconds,
                    "scope": _pytest_scope(pytest_args),
                    "args": pytest_args,
                },
            )
        )
        services.checkpoint()
        text = {
            "exit_code": result.exit_code,
            "validation_status": status.value,
            "duration_seconds": result.duration_seconds,
            "evidence_ids": result.evidence_ids,
            "stdout_tail": result.stdout[-3000:],
            "stderr_tail": result.stderr[-3000:],
        }
        return {
            "content": [{"type": "text", "text": str(text)}],
            "is_error": result.exit_code != 0,
        }

    @tool(
        "probe_api",
        "Make one policy-approved HTTP request and register sanitized response evidence.",
        {"method": str, "url": str},
    )
    async def probe_api(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("probe_api", args)
        method_decision = services.policy.authorize_api_method(
            args["method"], allow_mutating=services.allow_mutating_api_methods
        )
        services.state.policy_decisions.append(method_decision)
        if method_decision.decision.value != "ALLOW":
            services.checkpoint()
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"DENIED {method_decision.rule_id}: {method_decision.reason}",
                    }
                ],
                "is_error": True,
            }
        allow_hosts = services.network_hosts(args["url"])
        try:
            result = await ApiProbe(
                services.evidence,
                allow_hosts=allow_hosts,
                allowed_methods={args["method"]},
            ).request(args["method"], args["url"])
        except ApiProbeTransportError as exc:
            if exc.evidence_id not in services.state.evidence_ids:
                services.state.evidence_ids.append(exc.evidence_id)
            services.checkpoint()
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": "NETWORK_ERROR",
                                "error": str(exc),
                                "evidence_id": exc.evidence_id,
                            }
                        ),
                    }
                ],
                "is_error": True,
            }
        services.state.evidence_ids.append(result.evidence_id)
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "status_code": result.status_code,
                            "elapsed_ms": result.elapsed_ms,
                            "evidence_id": result.evidence_id,
                            "body": result.body,
                            "truncated": result.truncated,
                        },
                        default=str,
                    )[:12000],
                }
            ]
        }

    @tool(
        "inspect_browser",
        "Collect allowlisted browser accessibility, screenshot, console, and network evidence.",
        {"url": str},
    )
    async def inspect_browser(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("inspect_browser", args)
        subject = browser_inspection_subject(args["url"])
        allow_hosts = services.network_hosts(args["url"])
        try:
            result = await BrowserProbe(services.evidence, allow_hosts=allow_hosts).inspect(
                args["url"]
            )
        except BrowserProbeExecutionError as exc:
            if exc.evidence_id not in services.state.evidence_ids:
                services.state.evidence_ids.append(exc.evidence_id)
            services.state.validation_results.append(
                browser_validation_result(
                    subject,
                    revision=services.state.change_revision,
                    status=ValidationStatus.NOT_VERIFIED,
                    summary="Browser evidence collection did not complete deterministically.",
                    evidence_ids=[exc.evidence_id],
                    details={"failure_kind": "browser_execution"},
                )
            )
            services.checkpoint()
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": "BROWSER_ERROR",
                                "error": str(exc),
                                "evidence_id": exc.evidence_id,
                                "gate_id": subject.gate_id,
                            }
                        ),
                    }
                ],
                "is_error": True,
            }
        except RuntimeError as exc:
            services.state.validation_results.append(
                browser_validation_result(
                    subject,
                    revision=services.state.change_revision,
                    status=ValidationStatus.NOT_VERIFIED,
                    summary=redact_text(str(exc)),
                    details={"failure_kind": "browser_runtime"},
                )
            )
            services.checkpoint()
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"NOT_VERIFIED gate_id={subject.gate_id}: {redact_text(str(exc))}",
                    }
                ],
                "is_error": True,
            }
        ids = [
            evidence_id
            for evidence_id in [
                result.screenshot_evidence_id,
                result.dom_evidence_id,
                result.network_evidence_id,
            ]
            if evidence_id
        ]
        services.state.evidence_ids.extend(
            eid for eid in ids if eid not in services.state.evidence_ids
        )
        services.state.validation_results.append(
            browser_validation_result(
                subject,
                revision=services.state.change_revision,
                status=ValidationStatus.PASS,
                summary="Playwright Chromium collected browser evidence for the exact request subject.",
                evidence_ids=ids,
            )
        )
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "url": result.url,
                            "title": result.title,
                            "accessibility_snapshot": result.accessibility_snapshot,
                            "console_errors": result.console_errors,
                            "failed_requests": result.failed_requests,
                            "http_errors": result.http_errors,
                            "evidence_ids": ids,
                            "gate_id": subject.gate_id,
                        }
                    )[:16000],
                }
            ]
        }

    @tool(
        "classify_failure",
        "Classify currently collected evidence with a deterministic first-pass classifier.",
        {},
    )
    async def classify_failure(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("classify_failure", args)
        result = FailureAnalyzer().classify(services.evidence.all())
        services.state.classification = result.classification
        services.state.classification_confidence = result.confidence
        services.checkpoint()
        return {"content": [{"type": "text", "text": result.model_dump_json()}]}

    @tool(
        "read_test_file",
        "Read a UTF-8 test file after deterministic path authorization.",
        {"path": str},
    )
    async def read_test_file(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("read_test_file", args)
        relative = Path(args["path"])
        decision = services.policy.authorize_path(relative, write=False)
        services.state.policy_decisions.append(decision)
        if decision.decision.value != "ALLOW":
            return {
                "content": [
                    {"type": "text", "text": f"DENIED {decision.rule_id}: {decision.reason}"}
                ],
                "is_error": True,
            }
        if relative.suffix.lower() not in {".py", ".ts", ".js", ".java", ".cs"}:
            return {
                "content": [
                    {"type": "text", "text": "DENIED: file is not an approved test-code type"}
                ],
                "is_error": True,
            }
        try:
            observed = read_model_source_confined(
                services.workspace,
                relative,
                expected_root_identity=services.workspace_root_identity,
            )
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        text = redact_text(observed.text[:_MAX_MODEL_SOURCE_CHARS])
        services.state.files_read.append(relative.as_posix())
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "path": relative.as_posix(),
                            "sha256": observed.sha256,
                            "content": text,
                            "truncated": len(observed.text) > _MAX_MODEL_SOURCE_CHARS,
                            "size_bytes": observed.size_bytes,
                        }
                    )[:16000],
                }
            ]
        }

    @tool(
        "search_test_coverage",
        "Search bounded test-code paths/content and record observed repository coverage evidence.",
        {"query": str, "max_results": int},
    )
    async def search_test_coverage(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("search_test_coverage", args)
        raw_query = str(args.get("query", ""))
        try:
            observed = _coverage_search(
                services.workspace,
                query=raw_query,
                max_results=int(args.get("max_results", 100)),
                expected_root_identity=services.workspace_root_identity,
            )
        except (ValueError, OSError, RuntimeError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        redacted_query = redact_text(raw_query)
        structured = observed.as_structured_data(query=redacted_query)
        item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.SOURCE_OBSERVATION,
                nature=EvidenceNature.OBSERVED_FACT,
                source="repository_test_coverage_search",
                source_identifier=redacted_query,
                summary=(
                    f"Observed {len(observed.results)} bounded test coverage search result(s); "
                    f"complete={observed.complete}"
                ),
                structured_data=structured,
            )
        )
        services.state.evidence_ids.append(item.id)
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "coverage_evidence_id": item.id,
                            "results": structured["results"],
                            "complete": observed.complete,
                            "incomplete_reasons": list(observed.incomplete_reasons),
                        }
                    )[:16000],
                }
            ]
        }

    @tool(
        "plan_tests",
        "Create a deterministic coverage-aware test-generation plan.",
        {"requirement": str, "existing_coverage_json": str, "coverage_evidence_id": str},
    )
    async def plan_tests(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("plan_tests", args)
        try:
            coverage_evidence = services.evidence.get(args["coverage_evidence_id"])
        except KeyError:
            return {
                "content": [
                    {"type": "text", "text": "DENIED: coverage evidence does not exist in this run"}
                ],
                "is_error": True,
            }
        if (
            coverage_evidence.kind != EvidenceKind.SOURCE_OBSERVATION
            or coverage_evidence.nature != EvidenceNature.OBSERVED_FACT
            or coverage_evidence.source != "repository_test_coverage_search"
            or coverage_evidence.id not in services.state.evidence_ids
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: test planning requires observed repository coverage-search evidence",
                    }
                ],
                "is_error": True,
            }
        try:
            existing_coverage = json.loads(args["existing_coverage_json"])
        except json.JSONDecodeError as exc:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"DENIED: malformed coverage JSON: {redact_text(str(exc))}",
                    }
                ],
                "is_error": True,
            }
        if (
            not isinstance(existing_coverage, list)
            or not all(isinstance(item, str) and len(item) <= 500 for item in existing_coverage)
            or len(existing_coverage) > 500
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: existing coverage must be a JSON string list with at most 500 bounded entries",
                    }
                ],
                "is_error": True,
            }
        requirement = str(args["requirement"])
        if not requirement.strip() or len(requirement) > 8000:
            return {
                "content": [
                    {"type": "text", "text": "DENIED: requirement must be 1-8000 characters"}
                ],
                "is_error": True,
            }
        result = TestGenerationPlanner().plan(requirement, existing_coverage=existing_coverage)
        item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.TEST_PLAN,
                nature=EvidenceNature.MODEL_INTERPRETATION,
                source="test_generation_planner",
                source_identifier=coverage_evidence.id,
                summary="Coverage-aware test-generation plan created",
                structured_data={
                    "coverage_evidence_id": coverage_evidence.id,
                    "coverage_complete": coverage_evidence.structured_data.get("complete") is True,
                    "coverage_incomplete_reasons": coverage_evidence.structured_data.get(
                        "incomplete_reasons", []
                    ),
                    "plan": result.model_dump(mode="json"),
                },
            )
        )
        services.state.evidence_ids.append(item.id)
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {"plan_evidence_id": item.id, "plan": result.model_dump(mode="json")}
                    )[:16000],
                }
            ]
        }

    @tool(
        "prioritize_regression",
        "Risk-rank regression candidates; low confidence broadens selection.",
        {"candidates_json": str, "dependency_confidence": float},
    )
    async def prioritize_regression(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("prioritize_regression", args)
        try:
            raw = json.loads(args["candidates_json"])
            if not isinstance(raw, list) or len(raw) > 1000:
                raise ValueError("candidates_json must contain at most 1000 candidates")
            candidates = [RegressionCandidate.model_validate(item) for item in raw]
            result = RegressionPrioritizer().select(
                candidates, dependency_confidence=float(args["dependency_confidence"])
            )
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        return {"content": [{"type": "text", "text": result.model_dump_json()}]}

    @tool(
        "review_python_test",
        "Run deterministic test-quality checks against a Python test file.",
        {"path": str},
    )
    async def review_python_test(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("review_python_test", args)
        relative = Path(args["path"])
        decision = services.policy.authorize_path(relative, write=False)
        services.state.policy_decisions.append(decision)
        if decision.decision.value != "ALLOW":
            return {
                "content": [
                    {"type": "text", "text": f"DENIED {decision.rule_id}: {decision.reason}"}
                ],
                "is_error": True,
            }
        if relative.suffix.lower() != ".py":
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: only existing Python test files are supported",
                    }
                ],
                "is_error": True,
            }
        try:
            observed = read_model_source_confined(
                services.workspace,
                relative,
                expected_root_identity=services.workspace_root_identity,
            )
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        findings = [item.__dict__ for item in review_python_test_source(observed.text)]
        return {"content": [{"type": "text", "text": json.dumps({"findings": findings})}]}

    @tool(
        "create_test_file",
        "Create a new policy-approved test file from a coverage-aware plan after deterministic syntax/quality checks.",
        {"path": str, "content": str, "plan_evidence_id": str},
    )
    async def create_test_file(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("create_test_file", args)
        if reason := _require_closed_revision_before_mutation(services):
            return {"content": [{"type": "text", "text": f"DENIED: {reason}"}], "is_error": True}
        try:
            plan_item = services.evidence.get(args["plan_evidence_id"])
        except KeyError:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: test-generation plan evidence does not exist in this run",
                    }
                ],
                "is_error": True,
            }
        if (
            plan_item.kind != EvidenceKind.TEST_PLAN
            or plan_item.nature != EvidenceNature.MODEL_INTERPRETATION
            or plan_item.source != "test_generation_planner"
            or plan_item.id not in services.state.evidence_ids
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: test creation requires a coverage-aware plan from this run",
                    }
                ],
                "is_error": True,
            }
        patcher = SafeTestPatcher(services.workspace, services.policy)
        try:
            result = patcher.create_test(relative_path=args["path"], content=args["content"])
        except (PermissionError, ValueError, SyntaxError, FileExistsError) as exc:
            return {"content": [{"type": "text", "text": f"DENIED: {exc}"}], "is_error": True}
        services.state.files_modified.append(result.path)
        services.state.change_revision += 1
        item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.GIT_DIFF,
                source="safe_test_patcher",
                summary="Generated test file created; execution validation still required",
                structured_data={
                    "path": result.path,
                    "new_sha256": result.new_sha256,
                    "diff": result.diff[:12000],
                    "plan_evidence_id": plan_item.id,
                },
            )
        )
        services.state.evidence_ids.append(item.id)
        _record_patch_safety_validation(
            services,
            path=result.path,
            evidence_id=item.id,
            summary="Generated test passed deterministic syntax, path, assertion, and unsafe-diff checks.",
        )
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"TEST_CREATED evidence_id={item.id}; run deterministic validation next",
                }
            ]
        }

    @tool(
        "verify_locator_candidates",
        "Use Playwright to deterministically measure locator candidate uniqueness in the current DOM.",
        {"url": str, "original_locator": str, "candidates_json": str},
    )
    async def verify_locator_candidates(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("verify_locator_candidates", args)
        subject = None
        try:
            payload = json.loads(args["candidates_json"])
            if not isinstance(payload, list):
                raise ValueError("candidates_json must contain a JSON list")
            candidates = [LocatorCandidate.model_validate(item) for item in payload]
            subject = browser_locator_verification_subject(
                args["url"], args["original_locator"], candidates
            )
            allow_hosts = services.network_hosts(args["url"])
            verified, evidence_id = await BrowserProbe(
                services.evidence, allow_hosts=allow_hosts
            ).verify_locator_candidates(args["url"], args["original_locator"], candidates)
        except BrowserProbeExecutionError as exc:
            if exc.evidence_id not in services.state.evidence_ids:
                services.state.evidence_ids.append(exc.evidence_id)
            if subject is not None:
                services.state.validation_results.append(
                    browser_validation_result(
                        subject,
                        revision=services.state.change_revision,
                        status=ValidationStatus.NOT_VERIFIED,
                        summary="Browser locator verification did not complete deterministically.",
                        evidence_ids=[exc.evidence_id],
                        details={"failure_kind": "browser_execution"},
                    )
                )
            services.checkpoint()
            gate_text = f" gate_id={subject.gate_id}" if subject is not None else ""
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"NOT_VERIFIED{gate_text}: {redact_text(str(exc))}",
                    }
                ],
                "is_error": True,
            }
        except (ValueError, PermissionError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        except RuntimeError as exc:
            if subject is not None:
                services.state.validation_results.append(
                    browser_validation_result(
                        subject,
                        revision=services.state.change_revision,
                        status=ValidationStatus.NOT_VERIFIED,
                        summary=redact_text(str(exc)),
                        details={"failure_kind": "browser_runtime"},
                    )
                )
                services.checkpoint()
            gate_text = f" gate_id={subject.gate_id}" if subject is not None else ""
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"NOT_VERIFIED{gate_text}: {redact_text(str(exc))}",
                    }
                ],
                "is_error": True,
            }
        verification_item = services.evidence.get(evidence_id)
        context_ids = verification_item.structured_data.get("context_evidence_ids", [])
        registered_context_ids: list[str] = []
        if isinstance(context_ids, list):
            for context_id in context_ids:
                context_id = str(context_id)
                registered_context_ids.append(context_id)
                if context_id not in services.state.evidence_ids:
                    services.state.evidence_ids.append(context_id)
        if evidence_id not in services.state.evidence_ids:
            services.state.evidence_ids.append(evidence_id)
        if subject is None:  # pragma: no cover - assigned before browser execution
            raise RuntimeError("browser locator verification lost deterministic subject identity")
        services.state.validation_results.append(
            browser_validation_result(
                subject,
                revision=services.state.change_revision,
                status=ValidationStatus.PASS,
                summary="Playwright verified locator candidates for the exact request subject.",
                evidence_ids=[evidence_id, *registered_context_ids],
            )
        )
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "verification_evidence_id": evidence_id,
                            "candidates": [item.model_dump(mode="json") for item in verified],
                            "gate_id": subject.gate_id,
                        }
                    )[:16000],
                }
            ]
        }

    @tool(
        "propose_locator_heal",
        "Evaluate only browser-verified semantic locator candidates; does not change test code.",
        {
            "path": str,
            "expected_sha256": str,
            "original_locator": str,
            "candidates_json": str,
            "verification_evidence_id": str,
        },
    )
    async def propose_locator_heal(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("propose_locator_heal", args)
        classification = services.state.classification
        confidence = services.state.classification_confidence or 0.0
        if (
            classification
            not in {
                FailureClass.LOCATOR_UI_CONTRACT_CHANGE,
                FailureClass.TEST_AUTOMATION_DEFECT,
            }
            or confidence < 0.75
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: current deterministic failure classification does not support a sufficiently confident locator repair",
                    }
                ],
                "is_error": True,
            }
        try:
            verification = services.evidence.get(args["verification_evidence_id"])
        except KeyError:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: locator verification evidence does not exist in this run",
                    }
                ],
                "is_error": True,
            }
        if (
            verification.kind != EvidenceKind.SOURCE_OBSERVATION
            or verification.nature != EvidenceNature.OBSERVED_FACT
            or verification.source != "playwright_locator_verification"
            or verification.id not in services.state.evidence_ids
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: supplied evidence is not authoritative Playwright locator verification from this run",
                    }
                ],
                "is_error": True,
            }

        all_items = {item.id: item for item in services.evidence.all()}
        context_ids = verification.structured_data.get("context_evidence_ids", [])
        if not isinstance(context_ids, list) or len(context_ids) != 2:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: locator verification is missing same-DOM context evidence",
                    }
                ],
                "is_error": True,
            }
        try:
            context_items = [all_items[str(eid)] for eid in context_ids]
        except KeyError:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: locator verification context evidence is unavailable in this run",
                    }
                ],
                "is_error": True,
            }
        if any(item.id not in services.state.evidence_ids for item in context_items):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: locator verification context is not registered in canonical run state",
                    }
                ],
                "is_error": True,
            }
        context_kinds = {item.kind for item in context_items}
        if context_kinds != {EvidenceKind.SCREENSHOT, EvidenceKind.ACCESSIBILITY_SNAPSHOT} or any(
            item.source != "playwright_locator_verification"
            or item.source_identifier != verification.source_identifier
            for item in context_items
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: locator repair requires screenshot and accessibility evidence captured by the same Playwright verification",
                    }
                ],
                "is_error": True,
            }

        if (
            str(verification.structured_data.get("original_locator") or "")
            != args["original_locator"]
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: original locator does not match the browser verification evidence",
                    }
                ],
                "is_error": True,
            }
        observed_rows = verification.structured_data.get("candidates", [])
        observed_map = {
            (str(row.get("locator")), str(row.get("strategy"))): row
            for row in observed_rows
            if isinstance(row, dict)
        }
        try:
            requested = json.loads(args["candidates_json"])
            if not isinstance(requested, list):
                raise ValueError("candidates_json must contain a JSON list")
            bound: list[LocatorCandidate] = []
            for raw in requested:
                candidate = LocatorCandidate.model_validate(raw)
                observed = observed_map.get((candidate.locator, candidate.strategy))
                if observed is None:
                    raise ValueError(
                        "candidate was not measured by the supplied Playwright verification evidence"
                    )
                bound.append(
                    candidate.model_copy(
                        update={
                            "uniqueness_count": int(observed.get("uniqueness_count", 0)),
                            "rejected_reason": observed.get("rejected_reason"),
                        }
                    )
                )
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }

        proposal = SelfHealingEngine().propose(
            classification=classification,
            original_locator=args["original_locator"],
            candidates=bound,
            evidence_ids=[verification.id],
            policy=services.policy,
        )
        proposal_item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.HEALING_PROPOSAL,
                nature=EvidenceNature.MODEL_INTERPRETATION,
                source="self_healing_engine",
                source_identifier=verification.id,
                summary="Locator healing proposal evaluated against browser-verified candidates",
                structured_data={
                    **proposal.model_dump(mode="json"),
                    "path": args["path"],
                    "expected_sha256": args["expected_sha256"],
                    "classification": classification.value,
                    "classification_confidence": confidence,
                    "verification_evidence_id": verification.id,
                },
            )
        )
        services.state.evidence_ids.append(proposal_item.id)
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "proposal_evidence_id": proposal_item.id,
                            "proposal": proposal.model_dump(mode="json"),
                        }
                    ),
                }
            ],
            "is_error": not proposal.allowed,
        }

    @tool(
        "apply_locator_heal",
        "Apply one previously approved, browser-verified locator proposal to its bound test file.",
        {"proposal_evidence_id": str, "path": str},
    )
    async def apply_locator_heal(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("apply_locator_heal", args)
        if reason := _require_closed_revision_before_mutation(services):
            return {"content": [{"type": "text", "text": f"DENIED: {reason}"}], "is_error": True}
        try:
            proposal_item = services.evidence.get(args["proposal_evidence_id"])
        except KeyError:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: healing proposal evidence does not exist in this run",
                    }
                ],
                "is_error": True,
            }
        data = proposal_item.structured_data
        if (
            proposal_item.kind != EvidenceKind.HEALING_PROPOSAL
            or proposal_item.nature != EvidenceNature.MODEL_INTERPRETATION
            or proposal_item.id not in services.state.evidence_ids
            or data.get("allowed") is not True
            or data.get("risk") not in {RiskLevel.LOW.value, RiskLevel.MEDIUM.value}
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: proposal is not an approved low/medium-risk healing decision from this run",
                    }
                ],
                "is_error": True,
            }
        path = str(data.get("path") or "")
        if str(args.get("path") or "") != path:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: requested path does not match the path bound into the healing proposal",
                    }
                ],
                "is_error": True,
            }
        expected_sha256 = str(data.get("expected_sha256") or "")
        original_locator = str(data.get("original_locator") or "")
        proposed_locator = str(data.get("proposed_locator") or "")
        if not all((path, expected_sha256, original_locator, proposed_locator)):
            return {
                "content": [{"type": "text", "text": "DENIED: healing proposal is incomplete"}],
                "is_error": True,
            }
        patcher = SafeTestPatcher(services.workspace, services.policy)
        try:
            result = patcher.replace_locator_once(
                relative_path=path,
                expected_sha256=expected_sha256,
                old_locator=original_locator,
                new_locator=proposed_locator,
            )
        except (PermissionError, RuntimeError, ValueError, FileNotFoundError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        services.state.change_revision += 1
        services.state.files_modified.append(result.path)
        item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.GIT_DIFF,
                source="safe_test_patcher",
                source_identifier=proposal_item.id,
                summary="Browser-verified locator replacement applied; execution validation still required",
                structured_data={
                    "path": result.path,
                    "old_sha256": result.old_sha256,
                    "new_sha256": result.new_sha256,
                    "diff": result.diff[:12000],
                    "proposal_evidence_id": proposal_item.id,
                },
            )
        )
        services.state.evidence_ids.append(item.id)
        _record_patch_safety_validation(
            services,
            path=result.path,
            evidence_id=item.id,
            summary="Locator-only patch passed deterministic path, syntax, quality, and unsafe-diff checks.",
        )
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"LOCATOR_PATCH_APPLIED evidence_id={item.id} revision={services.state.change_revision}; run targeted test and relevant regression next",
                }
            ]
        }

    @tool(
        "validate_json_contract",
        "Validate a JSON instance against a JSON Schema deterministically.",
        {"instance_json": str, "schema_json": str},
    )
    async def validate_json_contract(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("validate_json_contract", args)
        try:
            if len(args["instance_json"]) > 1_000_000 or len(args["schema_json"]) > 1_000_000:
                raise ValueError("JSON contract inputs exceed 1 MB limit")
            instance = json.loads(args["instance_json"])
            schema = json.loads(args["schema_json"])
            result = validate_json_schema(instance, schema)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        result = result.model_copy(
            update={
                "gate_id": _stable_gate_id(
                    "json_schema",
                    {"instance": instance, "schema": schema},
                ),
                "revision": services.state.change_revision,
            }
        )
        services.state.validation_results.append(result)
        services.checkpoint()
        return {"content": [{"type": "text", "text": result.model_dump_json()}]}

    @tool(
        "analyze_ci_failure",
        "Classify a CI command failure from an exit code and sanitized log tail.",
        {"exit_code": int, "log_tail": str},
    )
    async def analyze_ci_failure_tool(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("analyze_ci_failure", args)
        signal = analyze_ci_failure(
            exit_code=int(args["exit_code"]), log_tail=redact_text(args["log_tail"][-12000:])
        )
        return {"content": [{"type": "text", "text": json.dumps(signal.__dict__)}]}

    @tool(
        "inspect_mobile_runtime",
        "Report whether an Appium mobile runtime is actually configured.",
        {},
    )
    async def inspect_mobile_runtime(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("inspect_mobile_runtime", args)
        result = MobileRuntimeInspector().inspect()
        result = result.model_copy(
            update={"gate_id": "mobile_runtime", "revision": services.state.change_revision}
        )
        services.state.validation_results.append(result)
        services.checkpoint()
        return {"content": [{"type": "text", "text": result.model_dump_json()}]}

    @tool(
        "run_k6",
        "Run a target-bound k6 script against an explicitly non-production environment and assess thresholds.",
        {
            "script": str,
            "target_url": str,
            "environment": str,
            "max_p95_ms": float,
            "max_error_rate": float,
            "min_request_rate": float,
        },
    )
    async def run_k6(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("run_k6", args)
        services.network_hosts(args["target_url"])
        if not services.k6_external_egress_enforced:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: k6 execution requires trusted infrastructure-level egress enforcement for every target, including localhost",
                    }
                ],
                "is_error": True,
            }
        runner = K6Runner(
            services.workspace,
            services.policy,
            external_egress_enforced=services.k6_external_egress_enforced,
        )
        try:
            metrics = runner.run(
                Path(args["script"]),
                target_url=args["target_url"],
                environment=args["environment"],
            )
            assessment = PerformanceAssessor().assess(
                metrics,
                max_p95_ms=float(args["max_p95_ms"]),
                max_error_rate=float(args["max_error_rate"]),
                min_request_rate=float(args["min_request_rate"]),
            )
        except PermissionError as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        except (RuntimeError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            status = ValidationStatus.NOT_VERIFIED
            services.state.validation_results.append(
                ValidationResult(
                    name="k6",
                    gate_id=_stable_gate_id(
                        "k6",
                        {
                            "script": args["script"],
                            "target_url": args["target_url"],
                            "environment": args["environment"],
                        },
                    ),
                    revision=services.state.change_revision,
                    status=status,
                    summary=redact_text(str(exc)),
                )
            )
            services.checkpoint()
            return {
                "content": [{"type": "text", "text": f"{status.value}: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.PERFORMANCE_METRIC,
                source="k6",
                summary=assessment.summary,
                structured_data={
                    "metrics": metrics.model_dump(mode="json"),
                    "threshold_breached": assessment.status == ValidationStatus.FAIL,
                },
            )
        )
        services.state.evidence_ids.append(item.id)
        services.state.validation_results.append(
            ValidationResult(
                name="k6",
                gate_id=_stable_gate_id(
                    "k6",
                    {
                        "script": args["script"],
                        "target_url": args["target_url"],
                        "environment": args["environment"],
                        "max_p95_ms": float(args["max_p95_ms"]),
                        "max_error_rate": float(args["max_error_rate"]),
                        "min_request_rate": float(args["min_request_rate"]),
                    },
                ),
                revision=services.state.change_revision,
                status=assessment.status,
                summary=assessment.summary,
                evidence_ids=[item.id],
                details={
                    "metrics": metrics.model_dump(mode="json"),
                    "breached_thresholds": assessment.breached_thresholds,
                },
            )
        )
        services.checkpoint()
        return {"content": [{"type": "text", "text": assessment.model_dump_json()}]}

    tools = [
        inspect_repository,
        run_pytest,
        probe_api,
        inspect_browser,
        classify_failure,
        read_test_file,
        search_test_coverage,
        plan_tests,
        prioritize_regression,
        review_python_test,
        create_test_file,
        verify_locator_candidates,
        propose_locator_heal,
        apply_locator_heal,
        validate_json_contract,
        analyze_ci_failure_tool,
        inspect_mobile_runtime,
        run_k6,
    ]
    server = create_sdk_mcp_server(name="qa", version="1.0.0", tools=tools)
    names = [
        f"mcp__qa__{name}"
        for name in [
            "inspect_repository",
            "run_pytest",
            "probe_api",
            "inspect_browser",
            "classify_failure",
            "read_test_file",
            "search_test_coverage",
            "plan_tests",
            "prioritize_regression",
            "review_python_test",
            "create_test_file",
            "verify_locator_candidates",
            "propose_locator_heal",
            "apply_locator_heal",
            "validate_json_contract",
            "analyze_ci_failure",
            "inspect_mobile_runtime",
            "run_k6",
        ]
    ]
    return server, names
