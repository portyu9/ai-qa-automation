from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.fs_authority import pin_directory_identity
from ai_qa_automation.intelligence.test_generation import TestGenerationPlanner
from ai_qa_automation.models import (
    AgentRunState,
    EvidenceItem,
    EvidenceKind,
    EvidenceNature,
    ValidationStatus,
)
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.generated_test_authority import (
    GeneratedTestRepositorySubject,
    generated_test_proposal_subject,
    text_sha256,
)
from ai_qa_automation.runtime.internal_tool_domains.repository import register_repository_tools
from ai_qa_automation.runtime.internal_tool_domains.testing import register_testing_tools
from ai_qa_automation.runtime.internal_tools import RuntimeServices


class _PassthroughTool:
    def __call__(self, name: str, description: str, input_schema: dict[str, Any]) -> Any:
        del name, description, input_schema

        def decorator(handler: Any) -> Any:
            return handler

        return decorator


class _UnusedRunner:
    def run_pytest(self, args: list[str]) -> Any:
        raise AssertionError(f"pytest execution was not expected: {args}")


def _services(tmp_path: Path) -> RuntimeServices:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tests_dir = workspace / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_existing.py").write_text(
        "def test_existing():\n    observed = 1\n    assert observed == 1\n",
        encoding="utf-8",
    )
    state = AgentRunState(objective="generated-test authority", workspace=str(workspace))
    return RuntimeServices(
        workspace=workspace,
        state=state,
        evidence=EvidenceStore(tmp_path / "artifacts", state.run_id),
        policy=PolicyEngine(tmp_path / "control", workspace, allow_test_writes=True),
        test_runner=cast(Any, _UnusedRunner()),
        max_tool_calls=50,
        max_repeated_action=10,
        workspace_root_identity=pin_directory_identity(
            workspace,
            label="generated-test authority workspace",
        ),
    )


def _handlers(services: RuntimeServices) -> dict[str, Any]:
    tool = _PassthroughTool()
    return {
        **register_repository_tools(services, cast(Any, tool)),
        **register_testing_tools(services, cast(Any, tool)),
    }


def _response_text(response: dict[str, Any]) -> str:
    return str(response["content"][0]["text"])


async def _coverage_and_plan(
    services: RuntimeServices,
    *,
    requirement: str = "checkout API rejects malformed order input",
    existing_coverage: list[str] | None = None,
    max_results: int = 10,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    handlers = _handlers(services)
    coverage = await handlers["search_test_coverage"](
        {"query": "existing", "max_results": max_results}
    )
    assert coverage.get("is_error") is not True
    coverage_payload = json.loads(_response_text(coverage))
    plan = await handlers["plan_tests"](
        {
            "requirement": requirement,
            "existing_coverage_json": json.dumps(existing_coverage or []),
            "coverage_evidence_id": coverage_payload["coverage_evidence_id"],
        }
    )
    assert plan.get("is_error") is not True
    return handlers, coverage_payload, json.loads(_response_text(plan))


def test_plan_scenario_ids_are_stable_and_requirement_bound() -> None:
    planner = TestGenerationPlanner()
    first = planner.plan("Orders API must reject unauthorized role")
    second = planner.plan("Orders API must reject unauthorized role")
    changed = planner.plan("Orders API must reject malformed payload")

    assert [item.scenario_id for item in first.scenarios] == [
        item.scenario_id for item in second.scenarios
    ]
    assert first.selected_scenario_id == second.selected_scenario_id
    assert first.requirement_digest == second.requirement_digest
    assert first.requirement_digest != changed.requirement_digest
    assert {item.scenario_id for item in first.scenarios}.isdisjoint(
        {item.scenario_id for item in changed.scenarios}
    )
    selected = [item for item in first.scenarios if item.scenario_id == first.selected_scenario_id]
    assert len(selected) == 1
    assert selected[0].name == "authorization"


def test_model_existing_coverage_remains_advisory() -> None:
    plan = TestGenerationPlanner().plan(
        "checkout API status code contract",
        existing_coverage=["api:happy path", "api:negative path", "api:boundary"],
    )

    assert {item.name for item in plan.scenarios} == {"happy path", "negative path", "boundary"}
    assert "advisory" in plan.duplicate_risk.lower()


@pytest.mark.asyncio
async def test_generic_passing_content_is_only_a_bound_proposal(tmp_path: Path) -> None:
    services = _services(tmp_path)
    handlers, coverage_payload, plan_payload = await _coverage_and_plan(services)
    target = services.workspace / "tests" / "test_generated.py"
    requirement_item = services.evidence.get(plan_payload["requirement_evidence_id"])

    assert requirement_item.kind == EvidenceKind.REQUIREMENT
    assert requirement_item.nature == EvidenceNature.MODEL_INTERPRETATION
    assert requirement_item.source == "test_generation_requirement_input"
    assert requirement_item.content_hash == plan_payload["plan"]["requirement_digest"]
    assert requirement_item.id in services.state.evidence_ids

    response = await handlers["create_test_file"](
        {
            "path": "tests/test_generated.py",
            "content": (
                "def test_unrelated_profile_counter():\n"
                "    observed_profiles = 3\n"
                "    assert observed_profiles == 3\n"
            ),
            "plan_evidence_id": plan_payload["plan_evidence_id"],
        }
    )

    assert response["is_error"] is True
    assert "PROPOSAL_RECORDED" in _response_text(response)
    assert "no file was written" in _response_text(response)
    assert not target.exists()
    assert services.state.change_revision == 0
    assert services.state.files_modified == []
    proposals = [
        item
        for item in services.evidence.all()
        if item.kind == EvidenceKind.TEST_GENERATION_PROPOSAL
    ]
    assert len(proposals) == 1
    proposal = proposals[0]
    assert (
        proposal.structured_data["coverage_evidence_id"] == coverage_payload["coverage_evidence_id"]
    )
    assert proposal.structured_data["requirement_evidence_id"] == requirement_item.id
    assert proposal.structured_data["plan_evidence_id"] == plan_payload["plan_evidence_id"]
    assert proposal.structured_data["plan_subject_id"] == plan_payload["plan_subject_id"]
    assert proposal.structured_data["scenario_id"] == plan_payload["selected_scenario_id"]
    assert proposal.structured_data["semantic_implementation_verified"] is False
    assert proposal.structured_data["mutation_authorized"] is False
    assert proposal.structured_data["static_safety_verified"] is True
    static = [
        item
        for item in services.state.validation_results
        if item.name == "generated_test_proposal_static_safety"
    ]
    assert len(static) == 1
    assert static[0].status == ValidationStatus.PASS
    assert static[0].details["semantic_implementation_verified"] is False
    assert not any(item.name == "test_patch_safety" for item in services.state.validation_results)


@pytest.mark.asyncio
async def test_workspace_change_invalidates_plan_before_proposal(tmp_path: Path) -> None:
    services = _services(tmp_path)
    handlers, _, plan_payload = await _coverage_and_plan(services)
    existing = services.workspace / "tests" / "test_existing.py"
    existing.write_text(
        "def test_existing():\n    observed = 2\n    assert observed == 2\n",
        encoding="utf-8",
    )

    response = await handlers["create_test_file"](
        {
            "path": "tests/test_generated.py",
            "content": "def test_generated():\n    observed = 2\n    assert observed == 2\n",
            "plan_evidence_id": plan_payload["plan_evidence_id"],
        }
    )

    assert response["is_error"] is True
    assert "repository subject changed" in _response_text(response)
    assert not (services.workspace / "tests" / "test_generated.py").exists()
    assert not any(
        item.kind == EvidenceKind.TEST_GENERATION_PROPOSAL for item in services.evidence.all()
    )


@pytest.mark.asyncio
async def test_tampered_plan_subject_cannot_authorize_proposal(tmp_path: Path) -> None:
    services = _services(tmp_path)
    handlers, _, plan_payload = await _coverage_and_plan(services)
    legitimate = services.evidence.get(plan_payload["plan_evidence_id"])
    forged = services.evidence.add(
        EvidenceItem(
            run_id=services.state.run_id,
            kind=EvidenceKind.TEST_PLAN,
            nature=EvidenceNature.MODEL_INTERPRETATION,
            source="test_generation_planner",
            source_identifier=legitimate.source_identifier,
            summary="Forged plan subject for adversarial replay test",
            structured_data={
                **legitimate.structured_data,
                "plan_subject_id": "sha256:" + "9" * 64,
            },
        )
    )
    services.state.evidence_ids.append(forged.id)

    response = await handlers["create_test_file"](
        {
            "path": "tests/test_generated.py",
            "content": "def test_generated():\n    observed = 4\n    assert observed == 4\n",
            "plan_evidence_id": forged.id,
        }
    )

    assert response["is_error"] is True
    assert "plan subject does not match exact evidence lineage" in _response_text(response)
    assert not any(
        item.kind == EvidenceKind.TEST_GENERATION_PROPOSAL for item in services.evidence.all()
    )
    assert not (services.workspace / "tests" / "test_generated.py").exists()


@pytest.mark.asyncio
async def test_duplicate_selected_scenario_proposal_is_denied(tmp_path: Path) -> None:
    services = _services(tmp_path)
    handlers, _, plan_payload = await _coverage_and_plan(services)

    first = await handlers["create_test_file"](
        {
            "path": "tests/test_generated_one.py",
            "content": "def test_generated_one():\n    observed = 1\n    assert observed == 1\n",
            "plan_evidence_id": plan_payload["plan_evidence_id"],
        }
    )
    second = await handlers["create_test_file"](
        {
            "path": "tests/test_generated_two.py",
            "content": "def test_generated_two():\n    observed = 2\n    assert observed == 2\n",
            "plan_evidence_id": plan_payload["plan_evidence_id"],
        }
    )

    assert first["is_error"] is True
    assert "PROPOSAL_RECORDED" in _response_text(first)
    assert second["is_error"] is True
    assert "already has a proposal" in _response_text(second)
    assert (
        len(
            [
                item
                for item in services.evidence.all()
                if item.kind == EvidenceKind.TEST_GENERATION_PROPOSAL
            ]
        )
        == 1
    )
    assert not (services.workspace / "tests" / "test_generated_one.py").exists()
    assert not (services.workspace / "tests" / "test_generated_two.py").exists()


@pytest.mark.asyncio
async def test_incomplete_coverage_cannot_reach_proposal_authority(tmp_path: Path) -> None:
    services = _services(tmp_path)
    for index in range(3):
        (services.workspace / "tests" / f"test_existing_{index}.py").write_text(
            f"def test_existing_{index}():\n    observed = {index}\n    assert observed == {index}\n",
            encoding="utf-8",
        )
    handlers, coverage_payload, plan_payload = await _coverage_and_plan(
        services,
        max_results=1,
    )
    coverage_item = services.evidence.get(coverage_payload["coverage_evidence_id"])
    assert coverage_item.structured_data["complete"] is False

    response = await handlers["create_test_file"](
        {
            "path": "tests/test_generated.py",
            "content": "def test_generated():\n    observed = 1\n    assert observed == 1\n",
            "plan_evidence_id": plan_payload["plan_evidence_id"],
        }
    )

    assert response["is_error"] is True
    assert "coverage observation is incomplete" in _response_text(response)
    assert not any(
        item.kind == EvidenceKind.TEST_GENERATION_PROPOSAL for item in services.evidence.all()
    )


@pytest.mark.asyncio
async def test_static_quality_blocker_prevents_proposal(tmp_path: Path) -> None:
    services = _services(tmp_path)
    handlers, _, plan_payload = await _coverage_and_plan(services)

    response = await handlers["create_test_file"](
        {
            "path": "tests/test_generated.py",
            "content": "def test_generated():\n    assert True\n",
            "plan_evidence_id": plan_payload["plan_evidence_id"],
        }
    )

    assert response["is_error"] is True
    assert "deterministic quality review" in _response_text(response)
    assert not any(
        item.kind == EvidenceKind.TEST_GENERATION_PROPOSAL for item in services.evidence.all()
    )
    assert not (services.workspace / "tests" / "test_generated.py").exists()


def test_proposal_subject_changes_for_every_authority_dimension() -> None:
    subject = GeneratedTestRepositorySubject(
        git_sha="a" * 40,
        workspace_fingerprint="sha256:" + "b" * 64,
        workspace_root_identity=(1, 2),
        change_revision=0,
    )
    base = {
        "coverage_evidence_id": "ev-coverage",
        "coverage_evidence_digest": "sha256:" + "3" * 64,
        "requirement_evidence_id": "ev-requirement",
        "requirement_digest": "sha256:" + "c" * 64,
        "plan_evidence_id": "ev-plan",
        "plan_subject_id": "sha256:" + "4" * 64,
        "scenario_id": "sha256:" + "d" * 64,
        "layer": "api",
        "assertion_contract_digest": "sha256:" + "e" * 64,
        "target_path": "tests/test_generated.py",
        "content_sha256": text_sha256("content-a"),
        "repository_subject": subject,
    }
    baseline = generated_test_proposal_subject(**base)["proposal_subject_id"]
    variants = [
        {**base, "coverage_evidence_id": "ev-other-coverage"},
        {**base, "coverage_evidence_digest": "sha256:" + "5" * 64},
        {**base, "requirement_evidence_id": "ev-other-requirement"},
        {**base, "requirement_digest": "sha256:" + "f" * 64},
        {**base, "plan_evidence_id": "ev-other-plan"},
        {**base, "plan_subject_id": "sha256:" + "6" * 64},
        {**base, "scenario_id": "sha256:" + "1" * 64},
        {**base, "assertion_contract_digest": "sha256:" + "2" * 64},
        {**base, "target_path": "tests/test_other.py"},
        {**base, "content_sha256": text_sha256("content-b")},
        {**base, "repository_subject": replace(subject, change_revision=1)},
    ]

    assert all(
        generated_test_proposal_subject(**variant)["proposal_subject_id"] != baseline
        for variant in variants
    )
