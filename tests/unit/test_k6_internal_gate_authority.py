from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import AgentRunState, ValidationStatus
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime import internal_tools
from ai_qa_automation.runtime.internal_tools import (
    RuntimeServices,
    _stable_gate_id,
    build_internal_mcp_server,
)
from ai_qa_automation.runtime.k6_authority import k6_gate_payload
from ai_qa_automation.tools.performance import K6ExecutionMetrics


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
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = AgentRunState(objective="exercise k6 gate authority", workspace=str(workspace))
    return RuntimeServices(
        workspace=workspace,
        state=state,
        evidence=EvidenceStore(tmp_path / "artifacts", state.run_id),
        policy=PolicyEngine(tmp_path / "control", workspace),
        test_runner=cast(Any, object()),
        max_tool_calls=20,
        max_repeated_action=5,
        allowed_network_hosts={"127.0.0.1"},
        k6_external_egress_enforced=True,
    )


def tool_map(services: RuntimeServices) -> dict[str, Any]:
    server, _names = build_internal_mcp_server(services)
    tools = cast(list[Any], cast(dict[str, Any], server)["tools"])
    return {str(tool.__name__): tool for tool in tools}


def request() -> dict[str, object]:
    return {
        "script": "performance/load.js",
        "target_url": "http://127.0.0.1:8000",
        "environment": "local",
        "max_p95_ms": 500.0,
        "max_error_rate": 0.01,
        "min_request_rate": 1.0,
    }


@pytest.mark.asyncio
async def test_invalid_threshold_is_denied_before_k6_runner_construction(
    tmp_path: Path,
    fake_sdk: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_sdk
    services = make_services(tmp_path)

    class RunnerMustNotBeConstructed:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("K6Runner was constructed before threshold validation")

    monkeypatch.setattr(internal_tools, "K6Runner", RunnerMustNotBeConstructed)
    payload = request()
    payload["max_error_rate"] = 1.5

    response = await tool_map(services)["run_k6"](payload)

    assert response["is_error"] is True
    assert "max_error_rate" in response["content"][0]["text"]
    assert services.state.validation_results == []


@pytest.mark.asyncio
async def test_runtime_failure_gate_uses_complete_threshold_subject(
    tmp_path: Path,
    fake_sdk: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_sdk
    services = make_services(tmp_path)

    class FailingRunner:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, *_args: object, **_kwargs: object) -> None:
            raise RuntimeError("synthetic k6 runtime failure")

    monkeypatch.setattr(internal_tools, "K6Runner", FailingRunner)
    first = request()

    first_response = await tool_map(services)["run_k6"](first)
    first_validation = services.state.validation_results[-1]

    assert first_response["is_error"] is True
    assert first_validation.status is ValidationStatus.NOT_VERIFIED
    assert first_validation.gate_id == _stable_gate_id("k6", k6_gate_payload(first))

    second = request()
    second["max_p95_ms"] = 750.0
    second_response = await tool_map(services)["run_k6"](second)
    second_validation = services.state.validation_results[-1]

    assert second_response["is_error"] is True
    assert second_validation.status is ValidationStatus.NOT_VERIFIED
    assert second_validation.gate_id == _stable_gate_id("k6", k6_gate_payload(second))
    assert first_validation.gate_id != second_validation.gate_id


@pytest.mark.asyncio
async def test_successful_k6_evidence_persists_exact_validated_snapshot_identity(
    tmp_path: Path,
    fake_sdk: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_sdk
    services = make_services(tmp_path)
    snapshot_sha = "a" * 64

    class SuccessfulRunner:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, *_args: object, **_kwargs: object) -> K6ExecutionMetrics:
            return K6ExecutionMetrics(
                p50_ms=1.0,
                p90_ms=2.0,
                p95_ms=3.0,
                p99_ms=4.0,
                request_rate=5.0,
                error_rate=0.0,
                module_snapshot_sha256=snapshot_sha,
            )

    monkeypatch.setattr(internal_tools, "K6Runner", SuccessfulRunner)
    payload = request()

    response = await tool_map(services)["run_k6"](payload)

    assert response.get("is_error") is not True
    validation = services.state.validation_results[-1]
    assert validation.status is ValidationStatus.PASS
    assert validation.gate_id == _stable_gate_id("k6", k6_gate_payload(payload))
    assert validation.details["metrics"]["module_snapshot_sha256"] == snapshot_sha
    evidence = services.evidence.all()[-1]
    assert evidence.structured_data["metrics"]["module_snapshot_sha256"] == snapshot_sha
