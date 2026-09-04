from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...intelligence.prioritization import RegressionPrioritizer
from ...intelligence.quality_review import review_python_test_source
from ...intelligence.test_generation import TestGenerationPlanner
from ...models import (
    EvidenceItem,
    EvidenceKind,
    EvidenceNature,
    RegressionCandidate,
    TerminalStatus,
    ValidationResult,
    ValidationStatus,
)
from ...redaction import redact_text
from ...tools.pytest_regression import run_regression_pytest
from ...tools.safe_patch import SafeTestPatcher
from ...tools.test_execution import TestRunner
from ..model_source_observation import read_model_source_confined
from .common import (
    RuntimeServices,
    ToolDecorator,
    pytest_scope,
    pytest_validation_status,
    record_patch_safety_validation,
    require_closed_revision_before_mutation,
    stable_gate_id,
)


def register_testing_tools(services: RuntimeServices, tool: ToolDecorator) -> dict[str, Any]:
    @tool(
        "run_pytest",
        "Execute pytest in the isolated target workspace and capture deterministic evidence.",
        {"args": list[str]},
    )
    async def run_pytest(args: dict[str, Any]) -> dict[str, Any]:
        services.consume("run_pytest", args)
        pytest_args = [str(item) for item in (args.get("args") or [])]
        scope = pytest_scope(pytest_args)
        regression_suite = None
        if scope == "regression" and isinstance(services.test_runner, TestRunner):
            result, regression_suite = run_regression_pytest(services.test_runner, pytest_args)
        else:
            result = services.test_runner.run_pytest(pytest_args)
        services.state.tests_executed.append(" ".join(result.command))
        services.state.evidence_ids.extend(
            eid for eid in result.evidence_ids if eid not in services.state.evidence_ids
        )
        status = (
            ValidationStatus.BLOCKED
            if not result.execution_started
            else pytest_validation_status(result.exit_code)
        )
        suite_verified = (
            scope == "regression"
            and regression_suite is not None
            and result.execution_started
            and result.exit_code == 0
            and regression_suite.pre_post_collection_match
            and regression_suite.execution_nodes_match
        )
        if scope == "regression" and status is ValidationStatus.PASS and not suite_verified:
            status = ValidationStatus.NOT_VERIFIED
        summary = (
            (result.block_reason or "pytest sandbox blocked target-code execution")
            if not result.execution_started
            else (
                "pytest regression exit was zero but no controller-bound suite identity was proven"
                if scope == "regression" and status is ValidationStatus.NOT_VERIFIED
                else f"pytest exited with {result.exit_code}"
            )
        )
        suite_details = regression_suite.details() if regression_suite is not None else None
        services.state.validation_results.append(
            ValidationResult(
                name="pytest",
                gate_id=stable_gate_id("pytest", pytest_args),
                revision=services.state.change_revision,
                status=status,
                summary=summary,
                evidence_ids=list(result.evidence_ids),
                details={
                    "duration_seconds": result.duration_seconds,
                    "scope": scope,
                    "args": pytest_args,
                    "execution_started": result.execution_started,
                    "regression_suite_verified": suite_verified,
                    "regression_suite_id": (
                        regression_suite.suite_id
                        if suite_verified and regression_suite is not None
                        else None
                    ),
                    "regression_suite": suite_details,
                },
            )
        )
        if not result.execution_started:
            services.state.terminal_status = TerminalStatus.BLOCKED
            services.state.terminal_reason = summary
        services.checkpoint()
        text = {
            "exit_code": result.exit_code,
            "validation_status": status.value,
            "duration_seconds": result.duration_seconds,
            "evidence_ids": result.evidence_ids,
            "regression_suite_id": (
                regression_suite.suite_id
                if suite_verified and regression_suite is not None
                else None
            ),
            "stdout_tail": result.stdout[-3000:],
            "stderr_tail": result.stderr[-3000:],
        }
        return {
            "content": [{"type": "text", "text": str(text)}],
            "is_error": status is not ValidationStatus.PASS,
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
        if reason := require_closed_revision_before_mutation(services):
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
        record_patch_safety_validation(
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

    return {
        "run_pytest": run_pytest,
        "plan_tests": plan_tests,
        "prioritize_regression": prioritize_regression,
        "review_python_test": review_python_test,
        "create_test_file": create_test_file,
    }
