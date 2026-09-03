from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

import ai_qa_automation.runtime.internal_tools as internal_tools
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import (
    AgentRunState,
    EvidenceItem,
    EvidenceKind,
    LocatorCandidate,
    TerminalStatus,
    ValidationStatus,
)
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


def make_services(tmp_path: Path) -> RuntimeServices:
    state = AgentRunState(objective="exercise browser validation lineage", workspace=str(tmp_path))
    return RuntimeServices(
        workspace=tmp_path,
        state=state,
        evidence=EvidenceStore(tmp_path / "artifacts", state.run_id),
        policy=cast(Any, object()),
        test_runner=cast(Any, object()),
        max_tool_calls=20,
        max_repeated_action=5,
        allowed_network_hosts={"example.test"},
        allow_external_network=True,
        api_browser_external_egress_enforced=True,
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
async def test_locator_verification_tool_persists_exact_subject_and_context_evidence(
    tmp_path: Path,
    fake_sdk: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_sdk
    services = make_services(tmp_path)
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
            "original_locator": original,
            "candidates_json": json.dumps([item.model_dump(mode="json") for item in candidates]),
        }
    )

    subject = browser_locator_verification_subject(url, original, candidates)
    validation = services.state.validation_results[-1]
    assert validation.name == "browser_locator_verification"
    assert validation.gate_id == subject.gate_id
    assert validation.status is ValidationStatus.PASS
    assert len(validation.evidence_ids) == 3
    assert set(validation.evidence_ids) <= set(services.state.evidence_ids)
    payload = json.loads(response["content"][0]["text"])
    assert payload["gate_id"] == subject.gate_id


@pytest.mark.asyncio
async def test_locator_browser_failure_is_subject_bound_and_registers_failure_evidence(
    tmp_path: Path,
    fake_sdk: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_sdk
    services = make_services(tmp_path)
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
            "original_locator": original,
            "candidates_json": json.dumps([item.model_dump(mode="json") for item in candidates]),
        }
    )

    subject = browser_locator_verification_subject(url, original, candidates)
    validation = services.state.validation_results[-1]
    assert validation.gate_id == subject.gate_id
    assert validation.status is ValidationStatus.NOT_VERIFIED
    assert len(validation.evidence_ids) == 1
    assert validation.evidence_ids[0] in services.state.evidence_ids
    assert response["is_error"] is True
    assert subject.gate_id in response["content"][0]["text"]
