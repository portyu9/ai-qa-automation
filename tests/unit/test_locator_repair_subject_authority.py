from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.fs_authority import pin_directory_identity
from ai_qa_automation.intelligence.failure_analysis import FailureAnalyzer
from ai_qa_automation.models import (
    AgentRunState,
    EvidenceItem,
    EvidenceKind,
    FailureClass,
    LocatorCandidate,
    ValidationResult,
    ValidationStatus,
)
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.internal_tool_domains.browser import register_browser_tools
from ai_qa_automation.runtime.internal_tool_domains.common import RuntimeServices
from ai_qa_automation.runtime.locator_repair import (
    LocatorRepairAuthorityError,
    resolve_locator_repair_authority,
)
from ai_qa_automation.runtime.validation_truth import evaluate_revision_closure

_ORIGINAL = 'page.get_by_test_id("save-profile")'
_CANDIDATE = 'page.get_by_role("button", name="Save Profile")'


def _git(workspace: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _test_source(locator: str = _ORIGINAL) -> str:
    return (
        "def test_save_profile(page):\n"
        f"    {locator}.click()\n"
        "    assert True\n"
    )


def _make_services(tmp_path: Path) -> RuntimeServices:
    workspace = tmp_path / "workspace"
    (workspace / "tests").mkdir(parents=True)
    (workspace / "tests" / "test_a.py").write_text(_test_source(), encoding="utf-8")
    (workspace / "tests" / "test_b.py").write_text(_test_source(), encoding="utf-8")
    (workspace / "conftest.py").write_text("# stable setup\n", encoding="utf-8")
    _git(workspace, "init", "-q")
    _git(workspace, "config", "user.email", "qa@example.test")
    _git(workspace, "config", "user.name", "QA Test")
    _git(workspace, "add", ".")
    _git(workspace, "commit", "-qm", "baseline")
    state = AgentRunState(
        objective="exercise locator repair subject authority",
        workspace=str(workspace),
        target_git_sha=_git(workspace, "rev-parse", "HEAD"),
    )
    return RuntimeServices(
        workspace=workspace,
        state=state,
        evidence=EvidenceStore(tmp_path / "artifacts", state.run_id),
        policy=PolicyEngine(tmp_path / "control", workspace, allow_test_writes=True),
        test_runner=cast(Any, object()),
        max_tool_calls=40,
        max_repeated_action=5,
        allowed_network_hosts={"example.test"},
        allow_external_network=True,
        api_browser_external_egress_enforced=True,
        workspace_root_identity=pin_directory_identity(
            workspace, label="locator repair test workspace"
        ),
    )


def _add_failing_pytest(
    services: RuntimeServices,
    *,
    selector: str = "tests/test_a.py::test_save_profile",
) -> ValidationResult:
    exit_item = services.evidence.add(
        EvidenceItem(
            run_id=services.state.run_id,
            kind=EvidenceKind.EXIT_CODE,
            source="pytest",
            source_identifier=f"python -m pytest {selector}",
            summary="pytest exited with code 1",
            structured_data={"exit_code": 1},
        )
    )
    exception_item = services.evidence.add(
        EvidenceItem(
            run_id=services.state.run_id,
            kind=EvidenceKind.EXCEPTION,
            source="pytest",
            source_identifier=f"python -m pytest {selector}",
            summary="pytest tests failed",
            structured_data={"exit_code": 1},
        )
    )
    services.state.evidence_ids.extend([exit_item.id, exception_item.id])
    validation = ValidationResult(
        name="pytest",
        gate_id=f"pytest:{selector}",
        revision=services.state.change_revision,
        status=ValidationStatus.FAIL,
        summary="targeted pytest failed",
        evidence_ids=[exit_item.id, exception_item.id],
        details={
            "scope": "targeted",
            "args": [selector],
            "execution_started": True,
        },
    )
    services.state.validation_results.append(validation)
    return validation


def _candidate() -> LocatorCandidate:
    return LocatorCandidate(
        locator=_CANDIDATE,
        strategy="role_name",
        uniqueness_count=999,
        semantic_match=0.0,
        stability_score=0.0,
    )


class SubjectBrowserProbe:
    original_count = 0
    include_context = True

    def __init__(
        self,
        evidence: EvidenceStore,
        *,
        allow_hosts: set[str],
        timeout_ms: int = 15_000,
    ) -> None:
        del timeout_ms
        self.evidence = evidence
        self.allow_hosts = allow_hosts

    async def verify_locator_candidates(
        self,
        url: str,
        original_locator: str,
        candidates: list[LocatorCandidate],
    ) -> tuple[list[LocatorCandidate], str]:
        assert "example.test" in self.allow_hosts
        verified = [
            item.model_copy(
                update={
                    "uniqueness_count": 1,
                    "semantic_match": 1.0,
                    "rejected_reason": None,
                }
            )
            for item in candidates
        ]
        context_ids: list[str] = []
        if self.include_context:
            screenshot = self.evidence.add(
                EvidenceItem(
                    run_id=self.evidence.run_id,
                    kind=EvidenceKind.SCREENSHOT,
                    source="playwright_locator_verification",
                    source_identifier=url,
                    summary="same DOM screenshot",
                )
            )
            accessibility = self.evidence.add(
                EvidenceItem(
                    run_id=self.evidence.run_id,
                    kind=EvidenceKind.ACCESSIBILITY_SNAPSHOT,
                    source="playwright_locator_verification",
                    source_identifier=url,
                    summary="same DOM accessibility",
                )
            )
            context_ids = [screenshot.id, accessibility.id]
        verification = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.SOURCE_OBSERVATION,
                source="playwright_locator_verification",
                source_identifier=url,
                summary="measured locator candidates",
                structured_data={
                    "original_locator": original_locator,
                    "original_count": self.original_count,
                    "candidates": [
                        {
                            "locator": item.locator,
                            "strategy": item.strategy,
                            "uniqueness_count": item.uniqueness_count,
                            "semantic_match": item.semantic_match,
                            "rejected_reason": item.rejected_reason,
                        }
                        for item in verified
                    ],
                    "context_evidence_ids": context_ids,
                },
            )
        )
        return verified, verification.id


def _tool_decorator(
    _name: str,
    _description: str,
    _schema: dict[str, Any],
) -> Any:
    def decorator(function: Any) -> Any:
        return function

    return decorator


def _tools(
    services: RuntimeServices,
    probe_cls: type[SubjectBrowserProbe] = SubjectBrowserProbe,
) -> dict[str, Any]:
    return register_browser_tools(
        services,
        cast(Any, _tool_decorator),
        browser_probe_cls=probe_cls,
    )


def _json_response(response: dict[str, Any]) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(response["content"][0]["text"]))


async def _verified_subject(
    services: RuntimeServices,
    *,
    probe_cls: type[SubjectBrowserProbe] = SubjectBrowserProbe,
) -> tuple[dict[str, Any], ValidationResult]:
    failure = _add_failing_pytest(services)
    response = await _tools(services, probe_cls)["verify_locator_candidates"](
        {
            "url": "https://example.test/profile",
            "failure_validation_id": failure.id,
            "original_locator": _ORIGINAL,
            "candidates_json": json.dumps([_candidate().model_dump(mode="json")]),
        }
    )
    payload = _json_response(response)
    subjects = [
        item
        for item in services.state.validation_results
        if item.name == "locator_repair_subject"
    ]
    assert len(subjects) == 1
    return response, subjects[0]


@pytest.mark.asyncio
async def test_exact_failing_node_and_browser_evidence_create_repair_subject(
    tmp_path: Path,
) -> None:
    services = _make_services(tmp_path)

    response, subject = await _verified_subject(services)

    assert response.get("is_error") is not True
    assert subject.status is ValidationStatus.PASS
    assert subject.details["path"] == "tests/test_a.py"
    assert subject.details["pytest_selector"] == "tests/test_a.py::test_save_profile"
    assert subject.details["failing_node_id"] == "tests/test_a.py::test_save_profile"
    assert subject.details["failure_validation_id"] == services.state.validation_results[0].id
    assert subject.details["classification"] == FailureClass.LOCATOR_UI_CONTRACT_CHANGE.value
    assert subject.details["workspace_revision"] == 0
    assert subject.details["workspace_git_sha"] == services.state.target_git_sha
    assert str(subject.details["workspace_fingerprint"])
    assert len(subject.details["failure_evidence_ids"]) == 2
    assert len(subject.details["context_evidence_ids"]) == 2


@pytest.mark.asyncio
async def test_test_a_subject_cannot_redirect_locator_mutation_to_test_b(
    tmp_path: Path,
) -> None:
    services = _make_services(tmp_path)
    response, subject = await _verified_subject(services)
    assert response.get("is_error") is not True
    tools = _tools(services)

    proposal_response = await tools["propose_locator_heal"](
        {
            "repair_subject_id": subject.gate_id,
            "candidates_json": json.dumps([_candidate().model_dump(mode="json")]),
            "path": "tests/test_b.py",
            "expected_sha256": "0" * 64,
        }
    )
    proposal_payload = _json_response(proposal_response)
    assert proposal_response.get("is_error") is not True
    proposal_id = str(proposal_payload["proposal_evidence_id"])

    before_b = (services.workspace / "tests" / "test_b.py").read_text(encoding="utf-8")
    apply_response = await tools["apply_locator_heal"](
        {"proposal_evidence_id": proposal_id, "path": "tests/test_b.py"}
    )

    assert apply_response.get("is_error") is not True
    assert _CANDIDATE in (services.workspace / "tests" / "test_a.py").read_text(encoding="utf-8")
    assert (services.workspace / "tests" / "test_b.py").read_text(encoding="utf-8") == before_b
    closure = evaluate_revision_closure(
        services.state.validation_results,
        current_revision=services.state.change_revision,
    )
    assert closure.closed is False
    assert closure.code == "missing_pytest"


@pytest.mark.asyncio
async def test_target_file_change_invalidates_subject_before_proposal(
    tmp_path: Path,
) -> None:
    services = _make_services(tmp_path)
    _response, subject = await _verified_subject(services)
    target = services.workspace / "tests" / "test_a.py"
    target.write_text(target.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")

    response = await _tools(services)["propose_locator_heal"](
        {
            "repair_subject_id": subject.gate_id,
            "candidates_json": json.dumps([_candidate().model_dump(mode="json")]),
        }
    )

    assert response["is_error"] is True
    assert "workspace revision or fingerprint changed" in response["content"][0]["text"]


@pytest.mark.asyncio
async def test_unrelated_workspace_change_invalidates_proposal_even_when_target_sha_is_unchanged(
    tmp_path: Path,
) -> None:
    services = _make_services(tmp_path)
    _response, subject = await _verified_subject(services)
    tools = _tools(services)
    proposal_response = await tools["propose_locator_heal"](
        {
            "repair_subject_id": subject.gate_id,
            "candidates_json": json.dumps([_candidate().model_dump(mode="json")]),
        }
    )
    proposal_id = str(_json_response(proposal_response)["proposal_evidence_id"])
    assert proposal_response.get("is_error") is not True
    target_before = (services.workspace / "tests" / "test_a.py").read_text(encoding="utf-8")

    (services.workspace / "conftest.py").write_text("# changed setup\n", encoding="utf-8")
    apply_response = await tools["apply_locator_heal"]({"proposal_evidence_id": proposal_id})

    assert apply_response["is_error"] is True
    assert "workspace revision or fingerprint changed" in apply_response["content"][0]["text"]
    assert (services.workspace / "tests" / "test_a.py").read_text(encoding="utf-8") == target_before


@pytest.mark.asyncio
async def test_newer_change_revision_cannot_reactivate_older_repair_subject(
    tmp_path: Path,
) -> None:
    services = _make_services(tmp_path)
    _response, subject = await _verified_subject(services)
    services.state.change_revision = 1

    with pytest.raises(LocatorRepairAuthorityError, match="active verified authority"):
        resolve_locator_repair_authority(
            subject_id=str(subject.gate_id),
            workspace=services.workspace,
            expected_root_identity=services.workspace_root_identity,
            state=services.state,
            evidence=services.evidence,
        )


class NonFailingLocatorProbe(SubjectBrowserProbe):
    original_count = 1


def _add_unrelated_locator_signal(services: RuntimeServices) -> None:
    url = "https://example.test/unrelated"
    screenshot = services.evidence.add(
        EvidenceItem(
            run_id=services.state.run_id,
            kind=EvidenceKind.SCREENSHOT,
            source="playwright_locator_verification",
            source_identifier=url,
            summary="unrelated screenshot",
        )
    )
    accessibility = services.evidence.add(
        EvidenceItem(
            run_id=services.state.run_id,
            kind=EvidenceKind.ACCESSIBILITY_SNAPSHOT,
            source="playwright_locator_verification",
            source_identifier=url,
            summary="unrelated accessibility",
        )
    )
    verification = services.evidence.add(
        EvidenceItem(
            run_id=services.state.run_id,
            kind=EvidenceKind.SOURCE_OBSERVATION,
            source="playwright_locator_verification",
            source_identifier=url,
            summary="unrelated locator signal",
            structured_data={
                "original_locator": _ORIGINAL,
                "original_count": 0,
                "candidates": [
                    {
                        "locator": _CANDIDATE,
                        "strategy": "role_name",
                        "uniqueness_count": 1,
                        "rejected_reason": None,
                    }
                ],
                "context_evidence_ids": [screenshot.id, accessibility.id],
            },
        )
    )
    services.state.evidence_ids.extend([screenshot.id, accessibility.id, verification.id])


@pytest.mark.asyncio
async def test_unrelated_run_evidence_cannot_raise_bound_repair_classification(
    tmp_path: Path,
) -> None:
    services = _make_services(tmp_path)
    _add_unrelated_locator_signal(services)
    global_result_before = FailureAnalyzer().classify(services.evidence.all())
    assert global_result_before.classification is FailureClass.LOCATOR_UI_CONTRACT_CHANGE

    response, subject = await _verified_subject(services, probe_cls=NonFailingLocatorProbe)

    assert response["is_error"] is True
    assert subject.status is ValidationStatus.NOT_VERIFIED
    assert subject.details["classification"] == FailureClass.INSUFFICIENT_EVIDENCE.value
    assert set(subject.details["classification_evidence_ids"]).isdisjoint(
        set(services.state.evidence_ids[:3])
    )


class MissingContextProbe(SubjectBrowserProbe):
    include_context = False


@pytest.mark.asyncio
async def test_same_dom_context_remains_mandatory_for_repair_subject(
    tmp_path: Path,
) -> None:
    services = _make_services(tmp_path)
    failure = _add_failing_pytest(services)

    response = await _tools(services, MissingContextProbe)["verify_locator_candidates"](
        {
            "url": "https://example.test/profile",
            "failure_validation_id": failure.id,
            "original_locator": _ORIGINAL,
            "candidates_json": json.dumps([_candidate().model_dump(mode="json")]),
        }
    )

    assert response["is_error"] is True
    assert "same-DOM context evidence" in response["content"][0]["text"]
    assert not any(
        item.name == "locator_repair_subject" for item in services.state.validation_results
    )
