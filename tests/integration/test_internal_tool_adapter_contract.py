from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.fs_authority import pin_directory_identity
from ai_qa_automation.models import AgentRunState
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.internal_tools import RuntimeServices, build_internal_mcp_server


EXPECTED_SCHEMAS: dict[str, dict[str, object]] = {
    "inspect_repository": {},
    "run_pytest": {"args": list[str]},
    "probe_api": {"method": str, "url": str},
    "inspect_browser": {"url": str},
    "classify_failure": {},
    "read_test_file": {"path": str},
    "search_test_coverage": {"query": str, "max_results": int},
    "plan_tests": {"requirement": str, "existing_coverage_json": str, "coverage_evidence_id": str},
    "prioritize_regression": {"candidates_json": str, "dependency_confidence": float},
    "review_python_test": {"path": str},
    "create_test_file": {"path": str, "content": str, "plan_evidence_id": str},
    "verify_locator_candidates": {"url": str, "original_locator": str, "candidates_json": str},
    "propose_locator_heal": {
        "path": str,
        "expected_sha256": str,
        "original_locator": str,
        "candidates_json": str,
        "verification_evidence_id": str,
    },
    "apply_locator_heal": {"proposal_evidence_id": str, "path": str},
    "validate_json_contract": {"instance_json": str, "schema_json": str},
    "analyze_ci_failure": {"exit_code": int, "log_tail": str},
    "inspect_mobile_runtime": {},
    "run_k6": {
        "script": str,
        "target_url": str,
        "environment": str,
        "max_p95_ms": float,
        "max_error_rate": float,
        "min_request_rate": float,
    },
}


def fake_tool(
    name: str,
    _description: str,
    schema: dict[str, object],
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(function: Callable[..., Any]) -> Callable[..., Any]:
        setattr(function, "_sdk_tool_name", name)
        setattr(function, "_sdk_tool_schema", schema)
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


class FakeTestRunner:
    def run_pytest(self, args: list[str]) -> SimpleNamespace:
        assert args == []
        return SimpleNamespace(
            command=("python", "-m", "pytest"),
            evidence_ids=[],
            exit_code=0,
            duration_seconds=0.01,
            stdout="1 passed",
            stderr="",
        )


def make_services(tmp_path: Path) -> RuntimeServices:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    test_file = workspace / "tests" / "test_sample.py"
    test_file.parent.mkdir()
    test_file.write_text("def test_sample():\n    assert 2 + 2 == 4\n", encoding="utf-8")
    state = AgentRunState(objective="exercise every registered QA adapter", workspace=str(workspace))
    return RuntimeServices(
        workspace=workspace,
        state=state,
        evidence=EvidenceStore(tmp_path / "artifacts", state.run_id),
        policy=PolicyEngine(tmp_path / "control", workspace),
        test_runner=cast(Any, FakeTestRunner()),
        max_tool_calls=30,
        max_repeated_action=5,
        allowed_network_hosts={"127.0.0.1"},
        workspace_root_identity=pin_directory_identity(workspace, label="adapter test workspace"),
    )


def registered_tools(services: RuntimeServices) -> dict[str, Any]:
    server, names = build_internal_mcp_server(services)
    raw_tools = cast(list[Any], cast(dict[str, Any], server)["tools"])
    tools = {cast(str, getattr(item, "_sdk_tool_name")): item for item in raw_tools}
    assert names == [f"mcp__qa__{name}" for name in EXPECTED_SCHEMAS]
    assert set(tools) == set(EXPECTED_SCHEMAS)
    for name, expected_schema in EXPECTED_SCHEMAS.items():
        assert getattr(tools[name], "_sdk_tool_schema") == expected_schema
    return tools


@pytest.mark.asyncio
async def test_every_registered_internal_tool_adapter_is_invoked_through_sdk_boundary(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    del fake_sdk
    services = make_services(tmp_path)
    tools = registered_tools(services)

    repository = await tools["inspect_repository"]({})
    assert repository.get("is_error") is not True

    pytest_response = await tools["run_pytest"]({"args": []})
    assert pytest_response.get("is_error") is not True

    api_response = await tools["probe_api"](
        {"method": "POST", "url": "http://127.0.0.1:9/never-contacted"}
    )
    assert api_response["is_error"] is True

    with pytest.raises(PermissionError, match="not explicitly allowlisted"):
        await tools["inspect_browser"]({"url": "https://blocked.invalid/"})

    classified = await tools["classify_failure"]({})
    assert classified.get("is_error") is not True

    read_response = await tools["read_test_file"]({"path": "tests/test_sample.py"})
    assert read_response.get("is_error") is not True

    coverage_response = await tools["search_test_coverage"](
        {"query": "test_sample", "max_results": 10}
    )
    assert coverage_response.get("is_error") is not True
    coverage_payload = json.loads(coverage_response["content"][0]["text"])

    plan_response = await tools["plan_tests"](
        {
            "requirement": "Preserve arithmetic behavior",
            "existing_coverage_json": '["tests/test_sample.py"]',
            "coverage_evidence_id": coverage_payload["coverage_evidence_id"],
        }
    )
    assert plan_response.get("is_error") is not True

    prioritized = await tools["prioritize_regression"](
        {"candidates_json": "[]", "dependency_confidence": 1.0}
    )
    assert prioritized.get("is_error") is not True

    review = await tools["review_python_test"]({"path": "tests/test_sample.py"})
    assert review.get("is_error") is not True

    creation = await tools["create_test_file"](
        {
            "path": "tests/test_generated.py",
            "content": "def test_generated():\n    assert True\n",
            "plan_evidence_id": "not-needed-while-revision-is-open",
        }
    )
    assert creation["is_error"] is True
    assert not (services.workspace / "tests" / "test_generated.py").exists()

    locator_verification = await tools["verify_locator_candidates"](
        {
            "url": "https://blocked.invalid/",
            "original_locator": "#submit",
            "candidates_json": "[]",
        }
    )
    assert locator_verification["is_error"] is True

    proposal = await tools["propose_locator_heal"](
        {
            "path": "tests/test_sample.py",
            "expected_sha256": "0" * 64,
            "original_locator": "#submit",
            "candidates_json": "[]",
            "verification_evidence_id": "missing",
        }
    )
    assert proposal["is_error"] is True

    application = await tools["apply_locator_heal"](
        {"proposal_evidence_id": "missing", "path": "tests/test_sample.py"}
    )
    assert application["is_error"] is True

    contract = await tools["validate_json_contract"](
        {
            "instance_json": '{"value":4}',
            "schema_json": '{"type":"object","properties":{"value":{"const":4}},"required":["value"]}',
        }
    )
    assert contract.get("is_error") is not True

    ci_analysis = await tools["analyze_ci_failure"](
        {"exit_code": 1, "log_tail": "AssertionError: synthetic"}
    )
    assert ci_analysis.get("is_error") is not True

    mobile = await tools["inspect_mobile_runtime"]({})
    assert mobile.get("is_error") is not True

    k6 = await tools["run_k6"](
        {
            "script": "performance/reference_sut.js",
            "target_url": "http://127.0.0.1:8000",
            "environment": "local",
            "max_p95_ms": 500.0,
            "max_error_rate": 2.0,
            "min_request_rate": 1.0,
        }
    )
    assert k6["is_error"] is True

    assert services.state.tool_call_count == len(EXPECTED_SCHEMAS)
