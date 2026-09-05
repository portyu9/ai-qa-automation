from __future__ import annotations

import ast
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
    TestGenerationPlan,
    TestScenario,
    ToolDecision,
    ValidationResult,
    ValidationStatus,
)
from ...redaction import redact_text
from ...tools.pytest_regression import run_regression_pytest
from ...tools.safe_patch import SafeTestPatcher
from ...tools.test_execution import TestRunner
from ..generated_test_authority import (
    GeneratedTestAuthorityError,
    canonical_sha256,
    capture_generated_test_repository_subject,
    generated_test_plan_subject,
    generated_test_proposal_subject,
    require_same_generated_test_repository_subject,
    text_sha256,
)
from ..model_source_observation import read_model_source_confined
from .common import (
    RuntimeServices,
    ToolDecorator,
    pytest_scope,
    pytest_validation_status,
    require_closed_revision_before_mutation,
    stable_gate_id,
)

_TARGETED_EXECUTION_AUTHORITY = "unavailable"
_REQUIREMENT_PROVENANCE = "plan_tests.requirement"


def _evidence_digest(item: EvidenceItem) -> str:
    return canonical_sha256(item.model_dump(mode="json"))


def _validate_generated_test_proposal(
    services: RuntimeServices,
    *,
    relative_path: str,
    content: str,
) -> tuple[str, str, str]:
    """Run the same deterministic static guards as SafeTestPatcher without writing bytes."""

    patcher = SafeTestPatcher(services.workspace, services.policy)
    content_bytes = content.encode("utf-8")
    if len(content_bytes) > patcher._MAX_TEST_FILE_BYTES:
        raise ValueError(f"generated test exceeds {patcher._MAX_TEST_FILE_BYTES} byte limit")
    path, destination = patcher._resolve_owned_path(relative_path)
    decision = services.policy.authorize_path(path, write=True)
    services.state.policy_decisions.append(decision)
    if decision.decision != ToolDecision.ALLOW:
        raise PermissionError(f"{decision.rule_id}: {decision.reason}")
    if destination.suffix not in patcher._SUPPORTED_SUFFIXES:
        raise PermissionError("generated tests support Python/JavaScript/TypeScript files only")
    if destination.exists():
        raise FileExistsError(destination)
    if destination.suffix == ".py":
        ast.parse(content)
        blockers = [
            finding
            for finding in review_python_test_source(content)
            if finding.severity in {"HIGH", "CRITICAL"}
        ]
        if blockers:
            raise PermissionError(
                "generated test failed deterministic quality review: "
                + ", ".join(f"{item.code}@{item.line}" for item in blockers)
            )
    elif not patcher._has_non_python_assertion(content):
        raise PermissionError("generated JavaScript/TypeScript test has no observable assertion")
    synthetic_diff = "".join(f"+{line}" for line in content.splitlines(keepends=True))
    violations = services.policy.validate_patch(synthetic_diff)
    if violations:
        raise PermissionError(f"unsafe generated test rejected: {', '.join(violations)}")
    return path.as_posix(), text_sha256(content), synthetic_diff


def _plan_selected_scenario(plan: TestGenerationPlan) -> TestScenario:
    matches = [item for item in plan.scenarios if item.scenario_id == plan.selected_scenario_id]
    if len(matches) != 1:
        raise GeneratedTestAuthorityError(
            "test-generation plan does not identify exactly one selected scenario"
        )
    return matches[0]


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
        targeted_authority = _TARGETED_EXECUTION_AUTHORITY if scope == "targeted" else None
        targeted_executed_pass_paths: list[str] = []
        targeted_executed_pass_count = len(targeted_executed_pass_paths)
        summary = (
            (result.block_reason or "pytest sandbox blocked target-code execution")
            if not result.execution_started
            else (
                "pytest regression exit was zero but no controller-bound suite identity was proven"
                if scope == "regression" and status is ValidationStatus.NOT_VERIFIED
                else (
                    "pytest exited with 0; no trusted out-of-process executed-test outcome authority is available for mutation closure"
                    if scope == "targeted" and status is ValidationStatus.PASS
                    else f"pytest exited with {result.exit_code}"
                )
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
                    "targeted_execution_authority": targeted_authority,
                    "targeted_outcome_report_verified": False,
                    "targeted_execution_id": None,
                    "targeted_executed_pass_count": targeted_executed_pass_count,
                    "targeted_executed_pass_paths": targeted_executed_pass_paths,
                    "targeted_execution": None,
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
            "targeted_execution_authority": targeted_authority,
            "targeted_outcome_report_verified": False,
            "targeted_executed_pass_count": targeted_executed_pass_count,
            "targeted_executed_pass_paths": targeted_executed_pass_paths,
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
            or coverage_evidence.structured_data.get("repository_subject_verified") is not True
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: test planning requires repository-subject-bound observed coverage-search evidence",
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
        try:
            current_subject = capture_generated_test_repository_subject(
                services.workspace,
                expected_root_identity=services.workspace_root_identity,
                change_revision=services.state.change_revision,
            )
            require_same_generated_test_repository_subject(
                coverage_evidence.structured_data.get("repository_subject"),
                current_subject,
            )
            result = TestGenerationPlanner().plan(
                requirement,
                existing_coverage=existing_coverage,
            )
            final_subject = capture_generated_test_repository_subject(
                services.workspace,
                expected_root_identity=services.workspace_root_identity,
                change_revision=services.state.change_revision,
            )
            if final_subject != current_subject:
                raise GeneratedTestAuthorityError("repository subject changed during test planning")
        except GeneratedTestAuthorityError as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        selected = _plan_selected_scenario(result)
        coverage_complete = coverage_evidence.structured_data.get("complete") is True
        coverage_evidence_digest = _evidence_digest(coverage_evidence)
        existing_coverage_digest = canonical_sha256(existing_coverage)
        requirement_item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.REQUIREMENT,
                nature=EvidenceNature.MODEL_INTERPRETATION,
                source="test_generation_requirement_input",
                source_identifier=coverage_evidence.id,
                summary="Generated-test requirement input captured for exact plan provenance",
                content_hash=result.requirement_digest,
                structured_data={
                    "requirement_digest": result.requirement_digest,
                    "requirement_provenance": _REQUIREMENT_PROVENANCE,
                    "repository_subject": current_subject.as_dict(),
                },
            )
        )
        services.state.evidence_ids.append(requirement_item.id)
        requirement_evidence_digest = _evidence_digest(requirement_item)
        plan_dump = result.model_dump(mode="json")
        plan_subject = generated_test_plan_subject(
            coverage_evidence_id=coverage_evidence.id,
            coverage_evidence_digest=coverage_evidence_digest,
            coverage_complete=coverage_complete,
            requirement_evidence_id=requirement_item.id,
            requirement_evidence_digest=requirement_evidence_digest,
            requirement_digest=result.requirement_digest,
            requirement_provenance=_REQUIREMENT_PROVENANCE,
            repository_subject=current_subject,
            selected_scenario_id=result.selected_scenario_id,
            selected_assertion_contract_digest=selected.assertion_contract_digest,
            advisory_existing_coverage_digest=existing_coverage_digest,
            plan=plan_dump,
        )
        item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.TEST_PLAN,
                nature=EvidenceNature.MODEL_INTERPRETATION,
                source="test_generation_planner",
                source_identifier=coverage_evidence.id,
                summary="Coverage-aware test-generation plan created; semantic implementation remains unverified",
                structured_data={
                    **plan_subject,
                    "coverage_incomplete_reasons": coverage_evidence.structured_data.get(
                        "incomplete_reasons", []
                    ),
                    "semantic_implementation_verified": False,
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
                        {
                            "plan_evidence_id": item.id,
                            "plan_subject_id": plan_subject["plan_subject_id"],
                            "requirement_evidence_id": requirement_item.id,
                            "selected_scenario_id": result.selected_scenario_id,
                            "semantic_implementation_verified": False,
                            "plan": plan_dump,
                        }
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
        "Validate and bind a generated-test proposal; repository mutation is denied unless semantic implementation is deterministically proven.",
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
            or plan_item.structured_data.get("semantic_implementation_verified") is not False
        ):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: test proposal requires a coverage-aware plan from this run",
                    }
                ],
                "is_error": True,
            }
        try:
            plan = TestGenerationPlan.model_validate(plan_item.structured_data.get("plan"))
            selected = _plan_selected_scenario(plan)
            if plan_item.structured_data.get("requirement_digest") != plan.requirement_digest:
                raise GeneratedTestAuthorityError(
                    "test-generation requirement digest does not match the plan"
                )
            if plan_item.structured_data.get("selected_scenario_id") != selected.scenario_id:
                raise GeneratedTestAuthorityError(
                    "test-generation selected scenario does not match the plan"
                )
            if (
                plan_item.structured_data.get("selected_assertion_contract_digest")
                != selected.assertion_contract_digest
            ):
                raise GeneratedTestAuthorityError(
                    "test-generation assertion contract does not match the plan"
                )
            coverage_evidence_id = plan_item.structured_data.get("coverage_evidence_id")
            requirement_evidence_id = plan_item.structured_data.get("requirement_evidence_id")
            if not isinstance(coverage_evidence_id, str) or not isinstance(
                requirement_evidence_id, str
            ):
                raise GeneratedTestAuthorityError(
                    "test-generation plan evidence provenance is invalid"
                )
            if plan_item.source_identifier != coverage_evidence_id:
                raise GeneratedTestAuthorityError(
                    "test-generation plan source does not match coverage provenance"
                )
            coverage_evidence = services.evidence.get(coverage_evidence_id)
            requirement_evidence = services.evidence.get(requirement_evidence_id)
            if (
                coverage_evidence.id not in services.state.evidence_ids
                or coverage_evidence.kind != EvidenceKind.SOURCE_OBSERVATION
                or coverage_evidence.nature != EvidenceNature.OBSERVED_FACT
                or coverage_evidence.source != "repository_test_coverage_search"
                or coverage_evidence.structured_data.get("repository_subject_verified") is not True
            ):
                raise GeneratedTestAuthorityError(
                    "test-generation coverage provenance is not authoritative"
                )
            if (
                requirement_evidence.id not in services.state.evidence_ids
                or requirement_evidence.kind != EvidenceKind.REQUIREMENT
                or requirement_evidence.nature != EvidenceNature.MODEL_INTERPRETATION
                or requirement_evidence.source != "test_generation_requirement_input"
                or requirement_evidence.source_identifier != coverage_evidence.id
                or requirement_evidence.content_hash != plan.requirement_digest
                or requirement_evidence.structured_data.get("requirement_digest")
                != plan.requirement_digest
                or requirement_evidence.structured_data.get("requirement_provenance")
                != _REQUIREMENT_PROVENANCE
            ):
                raise GeneratedTestAuthorityError(
                    "test-generation requirement provenance is not authoritative"
                )
            if (
                plan_item.structured_data.get("coverage_complete") is not True
                or coverage_evidence.structured_data.get("complete") is not True
            ):
                raise GeneratedTestAuthorityError(
                    "test-generation coverage observation is incomplete; duplicate coverage cannot be excluded"
                )
            current_subject = capture_generated_test_repository_subject(
                services.workspace,
                expected_root_identity=services.workspace_root_identity,
                change_revision=services.state.change_revision,
            )
            require_same_generated_test_repository_subject(
                plan_item.structured_data.get("repository_subject"),
                current_subject,
            )
            require_same_generated_test_repository_subject(
                coverage_evidence.structured_data.get("repository_subject"),
                current_subject,
            )
            require_same_generated_test_repository_subject(
                requirement_evidence.structured_data.get("repository_subject"),
                current_subject,
            )
            coverage_evidence_digest = _evidence_digest(coverage_evidence)
            requirement_evidence_digest = _evidence_digest(requirement_evidence)
            if (
                plan_item.structured_data.get("coverage_evidence_digest")
                != coverage_evidence_digest
                or plan_item.structured_data.get("requirement_evidence_digest")
                != requirement_evidence_digest
            ):
                raise GeneratedTestAuthorityError(
                    "test-generation plan evidence digest does not match exact provenance"
                )
            advisory_existing_coverage_digest = plan_item.structured_data.get(
                "advisory_existing_coverage_digest"
            )
            if not isinstance(advisory_existing_coverage_digest, str):
                raise GeneratedTestAuthorityError(
                    "test-generation advisory coverage digest is invalid"
                )
            recomputed_plan_subject = generated_test_plan_subject(
                coverage_evidence_id=coverage_evidence.id,
                coverage_evidence_digest=coverage_evidence_digest,
                coverage_complete=True,
                requirement_evidence_id=requirement_evidence.id,
                requirement_evidence_digest=requirement_evidence_digest,
                requirement_digest=plan.requirement_digest,
                requirement_provenance=_REQUIREMENT_PROVENANCE,
                repository_subject=current_subject,
                selected_scenario_id=selected.scenario_id,
                selected_assertion_contract_digest=selected.assertion_contract_digest,
                advisory_existing_coverage_digest=advisory_existing_coverage_digest,
                plan=plan.model_dump(mode="json"),
            )
            plan_subject_id = recomputed_plan_subject["plan_subject_id"]
            if plan_item.structured_data.get("plan_subject_id") != plan_subject_id:
                raise GeneratedTestAuthorityError(
                    "test-generation plan subject does not match exact evidence lineage"
                )
            for existing in services.evidence.all():
                if (
                    existing.kind == EvidenceKind.TEST_GENERATION_PROPOSAL
                    and existing.source == "generated_test_proposal"
                    and existing.structured_data.get("scenario_id") == selected.scenario_id
                ):
                    raise GeneratedTestAuthorityError(
                        "selected generated-test scenario already has a proposal in this run"
                    )
            normalized_path, content_sha256, synthetic_diff = _validate_generated_test_proposal(
                services,
                relative_path=str(args["path"]),
                content=str(args["content"]),
            )
            final_subject = capture_generated_test_repository_subject(
                services.workspace,
                expected_root_identity=services.workspace_root_identity,
                change_revision=services.state.change_revision,
            )
            if final_subject != current_subject:
                raise GeneratedTestAuthorityError(
                    "repository subject changed during generated-test proposal validation"
                )
            proposal_subject = generated_test_proposal_subject(
                coverage_evidence_id=coverage_evidence.id,
                coverage_evidence_digest=coverage_evidence_digest,
                requirement_evidence_id=requirement_evidence.id,
                requirement_digest=plan.requirement_digest,
                plan_evidence_id=plan_item.id,
                plan_subject_id=plan_subject_id,
                scenario_id=selected.scenario_id,
                layer=selected.layer.value,
                assertion_contract_digest=selected.assertion_contract_digest,
                target_path=normalized_path,
                content_sha256=content_sha256,
                repository_subject=current_subject,
            )
        except KeyError:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "DENIED: test-generation coverage or requirement evidence is unavailable",
                    }
                ],
                "is_error": True,
            }
        except (
            GeneratedTestAuthorityError,
            PermissionError,
            ValueError,
            SyntaxError,
            FileExistsError,
        ) as exc:
            return {
                "content": [{"type": "text", "text": f"DENIED: {redact_text(str(exc))}"}],
                "is_error": True,
            }
        item = services.evidence.add(
            EvidenceItem(
                run_id=services.state.run_id,
                kind=EvidenceKind.TEST_GENERATION_PROPOSAL,
                nature=EvidenceNature.MODEL_INTERPRETATION,
                source="generated_test_proposal",
                source_identifier=plan_item.id,
                summary="Generated test proposal passed deterministic static safety checks; semantic coverage remains unverified and no file was written",
                content_hash=content_sha256,
                structured_data={
                    **proposal_subject,
                    "scenario_name": selected.name,
                    "scenario_purpose": selected.purpose,
                    "assertions": list(selected.assertions),
                    "static_safety_verified": True,
                    "synthetic_diff_sha256": text_sha256(synthetic_diff),
                    "mutation_authorized": False,
                    "required_next_authority": (
                        "target-specific deterministic semantic implementation gate or explicit human approval"
                    ),
                },
            )
        )
        services.state.evidence_ids.append(item.id)
        services.state.validation_results.append(
            ValidationResult(
                name="generated_test_proposal_static_safety",
                gate_id=f"generated_test_proposal_static_safety:{proposal_subject['proposal_subject_id']}",
                revision=services.state.change_revision,
                status=ValidationStatus.PASS,
                summary=(
                    "Generated test proposal passed deterministic syntax, path, assertion, and unsafe-diff checks; semantic coverage was not verified."
                ),
                evidence_ids=[item.id],
                details={
                    "path": normalized_path,
                    "scenario_id": selected.scenario_id,
                    "proposal_subject_id": proposal_subject["proposal_subject_id"],
                    "scope": "static_proposal_safety",
                    "semantic_implementation_verified": False,
                    "mutation_authorized": False,
                },
            )
        )
        services.checkpoint()
        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"PROPOSAL_RECORDED evidence_id={item.id} "
                        f"proposal_subject_id={proposal_subject['proposal_subject_id']}; "
                        "DENIED: no deterministic semantic implementation gate or explicit human approval authorizes repository mutation; no file was written"
                    ),
                }
            ],
            "is_error": True,
        }

    return {
        "run_pytest": run_pytest,
        "plan_tests": plan_tests,
        "prioritize_regression": prioritize_regression,
        "review_python_test": review_python_test,
        "create_test_file": create_test_file,
    }
