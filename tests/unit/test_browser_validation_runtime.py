from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

import ai_qa_automation.runtime.internal_tools as internal_tools
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.fs_authority import pin_directory_identity
from ai_qa_automation.models import (
    AgentRunState,
    EvidenceItem,
    EvidenceKind,
    LocatorCandidate,
    TerminalStatus,
    ValidationResult,
    ValidationStatus,
)
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.browser_validation import (
    browser_inspection_subject,
    browser_locator_verification_subject,
)
from ai_qa_automation.runtime.internal_tools import RuntimeServices, build_internal_mcp_server
from ai_qa_automation.runtime.validation_truth import determine_terminal_outcome
from ai_qa_automation.tools.browser_evidence import (
    BrowserEvidenceResult,
    BrowserProbeExecutionError,
)
from ai_qa_automation.tools.repository import RepositoryInspector


def fake_tool(
    _name: str,
    _description: str,
    _schema: dict[str, Any],
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(function: Callable[..., Any]) -> Callable[..., Any]:
        return function

    return decorator


def fake_create_sdk_mcp_server(*, name: str, version: str, tools: list[Any]) -> dict[str, Any]:
    return {"name": name, "version": version, "tools": tools}


@pytest.fixture
def fake_sdk(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    module = ModuleType("claude_agent_sdk")
    module.tool = fake_tool
    module.create_sdk_mcp_server = fake_create_sdk_mcp_server
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", module)
    return module


def _git(workspace: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def make_services(tmp_path: Path) -> RuntimeServices:
    workspace = tmp_path / "workspace"
    test_file = workspace / "tests" / "test_locator.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "def test_locator(page):\n"
        '    page.get_by_role("button", name="Sign in").click()\n'
        "    assert True\n",
        encoding="utf-8",
    )
    _git(workspace, "init", "-q")
    _git(workspace, "config", "user.email", "qa@example.test")
    _git(workspace, "config", "user.name", "QA Test")
    _git(workspace, "add", ".")
    _git(workspace, "commit", "-qm", "baseline")
    state = AgentRunState(
        objective="exercise browser validation lineage",
        workspace=str(workspace),
        target_git_sha=_git(workspace, "rev-parse", "HEAD"),
    )
    return RuntimeServices(
        workspace=workspace,
        state=state,
        evidence=EvidenceStore(tmp_path / "artifacts", state.run_id),
        policy=PolicyEngine(tmp_path / "control", workspace),
        test_runner=cast(Any, object()),
        max_tool_calls=20,
        max_repeated_action=5,
        allowed_network_hosts={"example.test"},
        allow_external_network=True,
        api_browser_external_egress_enforced=True,
        workspace_root_identity=pin_directory_identity(
            workspace, label="browser validation test workspace"
        ),
    )


def tool_map(services: RuntimeServices) -> dict[str, Any]:
    server, _names = build_internal_mcp_server(services)
    tool_list = cast(list[Any], cast(dict[str, Any], server)["tools"])
    return {str(tool.__name__): tool for tool in tool_list}


def _add_evidence(store: EvidenceStore, *, kind: EvidenceKind, source: str, url: str) -> str:
    item = store.add(
        EvidenceItem(
            run_id=store.run_id,
            kind=kind,
            source=source,
            source_identifier=url,
            summary=f"{source} test evidence",
        )
    )
    return item.id


def _current_subject(services: RuntimeServices) -> tuple[str, str]:
    snapshot = RepositoryInspector(
        services.workspace,
        expected_root_identity=services.workspace_root_identity,
    ).snapshot()
    assert snapshot.git_sha
    assert snapshot.fingerprint_complete is True
    assert snapshot.fingerprint
    return snapshot.git_sha, snapshot.fingerprint


def _add_failing_locator_validation(services: RuntimeServices) -> ValidationResult:
    selector = "tests/test_locator.py::test_locator"
    git_sha, fingerprint = _current_subject(services)
    exit_item = services.evidence.add(
        EvidenceItem(
            run_id=services.state.run_id,
            kind=EvidenceKind.EXIT_CODE,
            source="pytest",
            source_identifier=f"python -m pytest {selector}",
            summary="pytest exited with code 1",
            structured_data={
                "exit_code": 1,
                "workspace_integrity_verified": True,
                "workspace_fingerprint_before": fingerprint,
                "workspace_fingerprint_after": fingerprint,
                "execution_subject": {
                    "git_sha": git_sha,
                    "source_fingerprint": fingerprint,
                },
            },
        )
    )
    exception_item = services.evidence.add(
        EvidenceItem(
            run_id=services.state.run_id,
            kind=EvidenceKind.EXCEPTION,
            source="pytest",
            source_identifier=f"python -m pytest {selector}",
            summary="test framework locator failure",
            structured_data={"exit_code": 1, "test_framework_error": True},
        )
    )
    services.state.evidence_ids.extend([exit_item.id, exception_item.id])
    validation = ValidationResult(
        name="pytest",
        gate_id="pytest:locator-failure",
        revision=services.state.change_revision,
        status=ValidationStatus.FAIL,
        summary="targeted locator test failed",
        evidence_ids=[exit_item.id, exception_item.id],
        details={
            "scope": "targeted",
            "args": [selector],
            "execution_started": True,
        },
    )
    services.state.validation_results.append(validation)
    return validation


class SuccessfulBrowserProbe:
    def __init__(
        self,
        evidence: EvidenceStore,
        *,
        allow_hosts: set[str],
        timeout_ms: int = 15_000,
    ) -> None:
        self.evidence = evidence
        self.allow_hosts = allow_hosts
        self.timeout_ms = timeout_ms

    async def inspect(self, url: str) -> BrowserEvidenceResult:
        screenshot_id = _add_evidence(
            self.evidence,
            kind=EvidenceKind.SCREENSHOT,
            source="playwright",
            url=url,
        )
        dom_id = _add_evidence(
            self.evidence,
            kind=EvidenceKind.ACCESSIBILITY_SNAPSHOT,
            source="playwright",
            url=url,
        )
        return BrowserEvidenceResult(
            url=url,
            title="Example",
            accessibility_snapshot="- document Example",
            screenshot_evidence_id=screenshot_id,
            dom_evidence_id=dom_id,
        )

    async def verify_locator_candidates(
        self,
        url: str,
        original_locator: str,
        candidates: list[LocatorCandidate],
    ) -> tuple[list[LocatorCandidate], str]:
        screenshot_id = _add_evidence(
            self.evidence,
            kind=EvidenceKind.SCREENSHOT,
            source="playwright_locator_verification",
            url=url,
        )
        accessibility_id = _add_evidence(
            self.evidence,
            kind=EvidenceKind.ACCESSIBILITY_SNAPSHOT,
            source="playwright_locator_verification",
            url=url,
        )
        verification = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.SOURCE_OBSERVATION,
                source="playwright_locator_verification",
                source_identifier=url,
                summary="Measured locator candidates",
                structured_data={
                    "original_locator": original_locator,
                    "original_count": 0,
                    "candidates": [
                        {
                            "locator": item.locator,
                            "strategy": item.strategy,
                            "uniqueness_count": item.uniqueness_count,
                            "semantic_match": item.semantic_match,
                            "rejected_reason": item.rejected_reason,
                        }
                        for item in candidates
                    ],
                    "context_evidence_ids": [screenshot_id, accessibility_id],
                },
            )
        )
        return candidates, verification.id


class FailingBrowserProbe(SuccessfulBrowserProbe):
    def _failure(self, url: str, source: str) -> BrowserProbeExecutionError:
        evidence_id = _add_evidence(
            self.evidence,
            kind=EvidenceKind.EXCEPTION,
            source=source,
            url=url,
        )
        return BrowserProbeExecutionError("synthetic browser execution failure", evidence_id)

    async def inspect(self, url: str) -> BrowserEvidenceResult:
        raise self._failure(url, "playwright")

    async def verify_locator_candidates(
        self,
        url: str,
        original_locator: str,
        candidates: list[LocatorCandidate],
    ) -> tuple[list[LocatorCandidate], str]:
        del original_locator, candidates
        raise self._failure(url, "playwright_locator_verification")


class RuntimeFailingLocatorProbe(SuccessfulBrowserProbe):
    async def verify_locator_candidates(
        self,
        url: str,
        original_locator: str,
        candidates: list[LocatorCandidate],
    ) -> tuple[list[LocatorCandidate], str]:
        del url, original_locator, candidates
        raise RuntimeError("synthetic browser runtime unavailable")


@pytest.mark.asyncio
async def test_inspect_browser_tool_persists_subject_gate_and_exact_evidence(
    tmp_path: Path,
    fake_sdk: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_sdk
    services = make_services(tmp_path)
    monkeypatch.setattr(internal_tools, "BrowserProbe", SuccessfulBrowserProbe)
    tools = tool_map(services)
    url = "https://example.test/checkout?session=opaque-value"

    response = await tools["inspect_browser"]({"url": url})

    subject = browser_inspection_subject(url)
    validation = services.state.validation_results[-1]
    assert validation.name == "browser_inspection"
    assert validation.gate_id == subject.gate_id
    assert validation.status is ValidationStatus.PASS
    assert validation.evidence_ids
    assert set(validation.evidence_ids) <= set(services.state.evidence_ids)
    assert response.get("is_error") is not True
    payload = json.loads(response["content"][0]["text"])
    assert payload["gate_id"] == subject.gate_id
    assert "opaque-value" not in repr(validation.details)


@pytest.mark.asyncio
async def test_inspect_browser_failure_records_same_gate_not_verified_and_defeats_stale_pass(
    tmp_path: Path,
    fake_sdk: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_sdk
    services = make_services(tmp_path)
    url = "https://example.test/checkout"
    subject = browser_inspection_subject(url)
    tools = tool_map(services)

    monkeypatch.setattr(internal_tools, "BrowserProbe", SuccessfulBrowserProbe)
    await tools["inspect_browser"]({"url": url})
    monkeypatch.setattr(internal_tools, "BrowserProbe", FailingBrowserProbe)
    response = await tools["inspect_browser"]({"url": url})

    matching = [
        item for item in services.state.validation_results if item.gate_id == subject.gate_id
    ]
    assert [item.status for item in matching] == [
        ValidationStatus.PASS,
        ValidationStatus.NOT_VERIFIED,
    ]
    assert matching[-1].evidence_ids[0] in services.state.evidence_ids
    assert response["is_error"] is True

    status, reason = determine_terminal_outcome(
        "success",
        services.state.validation_results,
        current_revision=0,
        objective_gate_id=subject.gate_id,
    )
    assert status is TerminalStatus.NOT_VERIFIED
    assert "incomplete" in reason.casefold()


@pytest.mark.asyncio
async def test_locator_verification_tool_persists_browser_and_repair_subjects(
    tmp_path: Path,
    fake_sdk: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_sdk
    services = make_services(tmp_path)
    failure = _add_failing_locator_validation(services)
    monkeypatch.setattr(internal_tools, "BrowserProbe", SuccessfulBrowserProbe)
    tools = tool_map(services)
    url = "https://example.test/login"
    original = 'page.get_by_role("button", name="Sign in")'
    candidates = [
        LocatorCandidate(
            locator='page.get_by_test_id("login")',
            strategy="test_id",
            uniqueness_count=0,
            semantic_match=0.0,
            stability_score=0.8,
        )
    ]

    response = await tools["verify_locator_candidates"](
        {
            "url": url,
            "failure_validation_id": failure.id,
            "original_locator": original,
            "candidates_json": json.dumps([item.model_dump(mode="json") for item in candidates]),
        }
    )

    browser_subject = browser_locator_verification_subject(url, original, candidates)
    browser_validation = next(
        item
        for item in services.state.validation_results
        if item.name == "browser_locator_verification"
    )
    repair_subject = next(
        item for item in services.state.validation_results if item.name == "locator_repair_subject"
    )
    assert browser_validation.gate_id == browser_subject.gate_id
    assert browser_validation.status is ValidationStatus.PASS
    assert len(browser_validation.evidence_ids) == 3
    assert set(browser_validation.evidence_ids) <= set(services.state.evidence_ids)
    assert repair_subject.status is ValidationStatus.PASS
    assert repair_subject.details["failure_validation_id"] == failure.id
    assert repair_subject.details["path"] == "tests/test_locator.py"
    assert browser_validation.details["repair_subject_id"] == repair_subject.gate_id
    assert browser_validation.details["failure_validation_id"] == failure.id
    assert browser_validation.details["path"] == repair_subject.details["path"]
    assert (
        browser_validation.details["workspace_git_sha"]
        == repair_subject.details["workspace_git_sha"]
    )
    assert (
        browser_validation.details["workspace_fingerprint"]
        == repair_subject.details["workspace_fingerprint"]
    )
    payload = json.loads(response["content"][0]["text"])
    assert payload["gate_id"] == browser_subject.gate_id
    assert payload["repair_subject_id"] == repair_subject.gate_id
    assert response.get("is_error") is not True


@pytest.mark.asyncio
async def test_locator_browser_failure_is_subject_bound_and_registers_failure_evidence(
    tmp_path: Path,
    fake_sdk: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_sdk
    services = make_services(tmp_path)
    failure = _add_failing_locator_validation(services)
    monkeypatch.setattr(internal_tools, "BrowserProbe", FailingBrowserProbe)
    tools = tool_map(services)
    url = "https://example.test/login"
    original = 'page.get_by_role("button", name="Sign in")'
    candidates = [
        LocatorCandidate(
            locator='page.get_by_test_id("login")',
            strategy="test_id",
            uniqueness_count=0,
            semantic_match=0.0,
            stability_score=0.8,
        )
    ]

    response = await tools["verify_locator_candidates"](
        {
            "url": url,
            "failure_validation_id": failure.id,
            "original_locator": original,
            "candidates_json": json.dumps([item.model_dump(mode="json") for item in candidates]),
        }
    )

    subject = browser_locator_verification_subject(url, original, candidates)
    validation = next(
        item for item in services.state.validation_results if item.gate_id == subject.gate_id
    )
    assert validation.status is ValidationStatus.NOT_VERIFIED
    assert len(validation.evidence_ids) == 1
    assert validation.evidence_ids[0] in services.state.evidence_ids
    assert response["is_error"] is True
    assert subject.gate_id in response["content"][0]["text"]
    assert not any(
        item.name == "locator_repair_subject" for item in services.state.validation_results
    )


@pytest.mark.asyncio
async def test_locator_browser_runtime_failure_after_subject_is_not_verified(
    tmp_path: Path,
    fake_sdk: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_sdk
    services = make_services(tmp_path)
    failure = _add_failing_locator_validation(services)
    monkeypatch.setattr(internal_tools, "BrowserProbe", RuntimeFailingLocatorProbe)
    tools = tool_map(services)
    url = "https://example.test/login"
    original = 'page.get_by_role("button", name="Sign in")'
    candidates = [
        LocatorCandidate(
            locator='page.get_by_test_id("login")',
            strategy="test_id",
            uniqueness_count=0,
            semantic_match=0.0,
            stability_score=0.8,
        )
    ]

    response = await tools["verify_locator_candidates"](
        {
            "url": url,
            "failure_validation_id": failure.id,
            "original_locator": original,
            "candidates_json": json.dumps([item.model_dump(mode="json") for item in candidates]),
        }
    )

    subject = browser_locator_verification_subject(url, original, candidates)
    validation = next(
        item for item in services.state.validation_results if item.gate_id == subject.gate_id
    )
    assert validation.status is ValidationStatus.NOT_VERIFIED
    assert validation.details["failure_kind"] == "browser_runtime"
    assert response["is_error"] is True
    assert subject.gate_id in response["content"][0]["text"]
    assert not any(
        item.name == "locator_repair_subject" for item in services.state.validation_results
    )
