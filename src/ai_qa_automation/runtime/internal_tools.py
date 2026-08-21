from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..evidence import EvidenceStore
from ..intelligence.failure_analysis import FailureAnalyzer
from ..intelligence.prioritization import RegressionPrioritizer
from ..intelligence.quality_review import review_python_test_source
from ..intelligence.test_generation import TestGenerationPlanner
from ..models import (
    AgentRunState,
    EvidenceItem,
    EvidenceKind,
    EvidenceNature,
    ValidationResult,
    ValidationStatus,
    RegressionCandidate,
)
from ..policy import PolicyEngine
from ..tools.api_testing import ApiProbe
from ..tools.browser_evidence import BrowserProbe
from ..tools.repository import RepositoryInspector
from ..tools.safe_patch import SafeTestPatcher
from ..tools.test_execution import TestRunner


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
    _fingerprints: dict[str, int] = field(default_factory=dict)

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

    def network_hosts(self, url: str) -> set[str]:
        host = (urlparse(url).hostname or "").lower()
        if not host or host not in self.allowed_network_hosts:
            raise PermissionError(f"network host is not explicitly allowlisted: {host or '<missing>'}")
        if not self.allow_external_network and host not in {"localhost", "127.0.0.1", "::1"}:
            raise PermissionError("external network access is disabled")
        return self.allowed_network_hosts


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
                structured_data={"git_sha": snapshot.git_sha, "branch": snapshot.branch, "dirty": bool(snapshot.status), "changed_files": list(snapshot.changed_files)},
            )
        )
        services.state.evidence_ids.append(item.id)
        services.state.target_git_sha = snapshot.git_sha
        return {"content": [{"type": "text", "text": item.model_dump_json()}]}

    @tool("run_pytest", "Execute pytest in the isolated target workspace and capture deterministic evidence.", {"args": list[str]})
    async def run_pytest(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("run_pytest", args)
        result = services.test_runner.run_pytest(args.get("args") or [])
        services.state.tests_executed.append(" ".join(result.command))
        services.state.evidence_ids.extend(eid for eid in result.evidence_ids if eid not in services.state.evidence_ids)
        services.state.validation_results.append(
            ValidationResult(
                name="pytest",
                status=ValidationStatus.PASS if result.exit_code == 0 else ValidationStatus.FAIL,
                summary=f"pytest exited with {result.exit_code}",
                evidence_ids=list(result.evidence_ids),
                details={"duration_seconds": result.duration_seconds},
            )
        )
        text = {"exit_code": result.exit_code, "duration_seconds": result.duration_seconds, "evidence_ids": result.evidence_ids, "stdout_tail": result.stdout[-3000:], "stderr_tail": result.stderr[-3000:]}
        return {"content": [{"type": "text", "text": str(text)}], "is_error": result.exit_code != 0}

    @tool("probe_api", "Make one allowlisted HTTP request and register response evidence.", {"method": str, "url": str})
    async def probe_api(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("probe_api", args)
        allow_hosts = services.network_hosts(args["url"])
        result = await ApiProbe(services.evidence, allow_hosts=allow_hosts).request(args["method"], args["url"])
        services.state.evidence_ids.append(result.evidence_id)
        return {"content": [{"type": "text", "text": json.dumps({"status_code": result.status_code, "elapsed_ms": result.elapsed_ms, "evidence_id": result.evidence_id, "body": result.body}, default=str)[:12000]}]}

    @tool("inspect_browser", "Collect allowlisted browser accessibility, screenshot, console, and network evidence.", {"url": str})
    async def inspect_browser(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("inspect_browser", args)
        allow_hosts = services.network_hosts(args["url"])
        result = await BrowserProbe(services.evidence, allow_hosts=allow_hosts).inspect(args["url"])
        ids = [eid for eid in [result.screenshot_evidence_id, result.dom_evidence_id] if eid]
        services.state.evidence_ids.extend(eid for eid in ids if eid not in services.state.evidence_ids)
        return {"content": [{"type": "text", "text": json.dumps({"url": result.url, "title": result.title, "console_errors": result.console_errors, "failed_requests": result.failed_requests, "evidence_ids": ids})}]}

    @tool("classify_failure", "Classify currently collected evidence with a deterministic first-pass classifier.", {})
    async def classify_failure(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("classify_failure", args)
        result = FailureAnalyzer().classify(services.evidence.all())
        services.state.classification = result.classification
        services.state.classification_confidence = result.confidence
        return {"content": [{"type": "text", "text": result.model_dump_json()}]}

    @tool("read_test_file", "Read a UTF-8 test file after deterministic path authorization.", {"path": str})
    async def read_test_file(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("read_test_file", args)
        relative = Path(args["path"])
        decision = services.policy.authorize_path(relative, write=False)
        services.state.policy_decisions.append(decision)
        if decision.decision.value != "ALLOW":
            return {"content": [{"type": "text", "text": f"DENIED {decision.rule_id}: {decision.reason}"}], "is_error": True}
        target = (services.workspace / relative).resolve()
        if not target.is_file() or target.suffix not in {".py", ".ts", ".js", ".java", ".cs"}:
            return {"content": [{"type": "text", "text": "DENIED: file is not an approved test-code type"}], "is_error": True}
        text = target.read_text(encoding="utf-8")[:12000]
        services.state.files_read.append(relative.as_posix())
        return {"content": [{"type": "text", "text": text}]}

    @tool("plan_tests", "Create a deterministic coverage-aware test-generation plan.", {"requirement": str})
    async def plan_tests(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("plan_tests", args)
        result = TestGenerationPlanner().plan(args["requirement"])
        return {"content": [{"type": "text", "text": result.model_dump_json()}]}

    @tool("prioritize_regression", "Risk-rank regression candidates; low confidence broadens selection.", {"candidates_json": str, "dependency_confidence": float})
    async def prioritize_regression(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("prioritize_regression", args)
        raw = json.loads(args["candidates_json"])
        candidates = [RegressionCandidate.model_validate(item) for item in raw]
        result = RegressionPrioritizer().select(candidates, dependency_confidence=float(args["dependency_confidence"]))
        return {"content": [{"type": "text", "text": result.model_dump_json()}]}

    @tool("review_python_test", "Run deterministic test-quality checks against a Python test file.", {"path": str})
    async def review_python_test(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("review_python_test", args)
        relative = Path(args["path"])
        decision = services.policy.authorize_path(relative, write=False)
        if decision.decision.value != "ALLOW":
            return {"content": [{"type": "text", "text": f"DENIED {decision.rule_id}: {decision.reason}"}], "is_error": True}
        target = (services.workspace / relative).resolve()
        if target.suffix != ".py" or not target.is_file():
            return {"content": [{"type": "text", "text": "DENIED: only existing Python test files are supported"}], "is_error": True}
        findings = [item.__dict__ for item in review_python_test_source(target.read_text(encoding="utf-8"))]
        return {"content": [{"type": "text", "text": json.dumps({"findings": findings})}]}

    @tool("create_test_file", "Create a new policy-approved test file after deterministic syntax/quality checks.", {"path": str, "content": str})
    async def create_test_file(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("create_test_file", args)
        patcher = SafeTestPatcher(services.workspace, services.policy)
        try:
            result = patcher.create_test(relative_path=args["path"], content=args["content"])
        except (PermissionError, ValueError, SyntaxError, FileExistsError) as exc:
            return {"content": [{"type": "text", "text": f"DENIED: {exc}"}], "is_error": True}
        services.state.files_modified.append(result.path)
        item = services.evidence.add(EvidenceItem(run_id=services.state.run_id, kind=EvidenceKind.GIT_DIFF, source="safe_test_patcher", summary="Generated test file created; execution validation still required", structured_data={"path": result.path, "new_sha256": result.new_sha256, "diff": result.diff[:12000]}))
        services.state.evidence_ids.append(item.id)
        return {"content": [{"type": "text", "text": f"TEST_CREATED evidence_id={item.id}; run deterministic validation next"}]}

    @tool("safe_replace_test_text", "Atomically replace one exact test-code fragment with optimistic concurrency and unsafe-diff guards.", {"path": str, "expected_sha256": str, "old_text": str, "new_text": str})
    async def safe_replace_test_text(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("safe_replace_test_text", args)
        patcher = SafeTestPatcher(services.workspace, services.policy)
        try:
            result = patcher.replace_once(relative_path=args["path"], expected_sha256=args["expected_sha256"], old_text=args["old_text"], new_text=args["new_text"])
        except (PermissionError, RuntimeError, ValueError, FileNotFoundError) as exc:
            return {"content": [{"type": "text", "text": f"DENIED: {exc}"}], "is_error": True}
        services.state.files_modified.append(result.path)
        item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.GIT_DIFF,
                source="safe_test_patcher",
                summary="Guarded test-code replacement applied; validation still required",
                structured_data={"path": result.path, "old_sha256": result.old_sha256, "new_sha256": result.new_sha256, "diff": result.diff[:12000]},
            )
        )
        services.state.evidence_ids.append(item.id)
        return {"content": [{"type": "text", "text": f"PATCH_APPLIED evidence_id={item.id}; deterministic test validation is still required"}]}

    tools = [inspect_repository, run_pytest, probe_api, inspect_browser, classify_failure, read_test_file, plan_tests, prioritize_regression, review_python_test, create_test_file, safe_replace_test_text]
    server = create_sdk_mcp_server(name="qa", version="1.0.0", tools=tools)
    names = [f"mcp__qa__{name}" for name in ["inspect_repository", "run_pytest", "probe_api", "inspect_browser", "classify_failure", "read_test_file", "plan_tests", "prioritize_regression", "review_python_test", "create_test_file", "safe_replace_test_text"]]
    return server, names
