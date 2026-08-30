from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.fs_authority import pin_directory_identity
from ai_qa_automation.models import AgentRunState, ValidationStatus
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime import internal_tools

EXPECTED_TOOL_NAMES = [
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


EXPECTED_TOOL_PROPERTIES: dict[str, dict[str, dict[str, object]]] = {
    "inspect_repository": {},
    "run_pytest": {"args": {"type": "array", "items": {"type": "string"}}},
    "probe_api": {"method": {"type": "string"}, "url": {"type": "string"}},
    "inspect_browser": {"url": {"type": "string"}},
    "classify_failure": {},
    "read_test_file": {"path": {"type": "string"}},
    "search_test_coverage": {
        "query": {"type": "string"},
        "max_results": {"type": "integer"},
    },
    "plan_tests": {
        "requirement": {"type": "string"},
        "existing_coverage_json": {"type": "string"},
        "coverage_evidence_id": {"type": "string"},
    },
    "prioritize_regression": {
        "candidates_json": {"type": "string"},
        "dependency_confidence": {"type": "number"},
    },
    "review_python_test": {"path": {"type": "string"}},
    "create_test_file": {
        "path": {"type": "string"},
        "content": {"type": "string"},
        "plan_evidence_id": {"type": "string"},
    },
    "verify_locator_candidates": {
        "url": {"type": "string"},
        "original_locator": {"type": "string"},
        "candidates_json": {"type": "string"},
    },
    "propose_locator_heal": {
        "path": {"type": "string"},
        "expected_sha256": {"type": "string"},
        "original_locator": {"type": "string"},
        "candidates_json": {"type": "string"},
        "verification_evidence_id": {"type": "string"},
    },
    "apply_locator_heal": {
        "proposal_evidence_id": {"type": "string"},
        "path": {"type": "string"},
    },
    "validate_json_contract": {
        "instance_json": {"type": "string"},
        "schema_json": {"type": "string"},
    },
    "analyze_ci_failure": {
        "exit_code": {"type": "integer"},
        "log_tail": {"type": "string"},
    },
    "inspect_mobile_runtime": {},
    "run_k6": {
        "script": {"type": "string"},
        "target_url": {"type": "string"},
        "environment": {"type": "string"},
        "max_p95_ms": {"type": "number"},
        "max_error_rate": {"type": "number"},
        "min_request_rate": {"type": "number"},
    },
}


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


def make_services(tmp_path: Path) -> internal_tools.RuntimeServices:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    test_file = workspace / "tests" / "test_sample.py"
    test_file.parent.mkdir()
    test_file.write_text("def test_sample():\n    assert 2 + 2 == 4\n", encoding="utf-8")
    state = AgentRunState(
        objective="exercise the pinned SDK MCP boundary", workspace=str(workspace)
    )
    return internal_tools.RuntimeServices(
        workspace=workspace,
        state=state,
        evidence=EvidenceStore(tmp_path / "artifacts", state.run_id),
        policy=PolicyEngine(tmp_path / "control", workspace),
        test_runner=cast(Any, FakeTestRunner()),
        max_tool_calls=30,
        max_repeated_action=5,
        allowed_network_hosts={"127.0.0.1"},
        workspace_root_identity=pin_directory_identity(
            workspace, label="real SDK adapter workspace"
        ),
    )


def real_sdk_server(services: internal_tools.RuntimeServices) -> Any:
    from mcp.types import CallToolRequest, ListToolsRequest

    server_config, names = internal_tools.build_internal_mcp_server(services)
    assert server_config["type"] == "sdk"
    assert server_config["name"] == "qa"
    assert names == [f"mcp__qa__{name}" for name in EXPECTED_TOOL_NAMES]

    server = server_config["instance"]
    assert ListToolsRequest in server.request_handlers
    assert CallToolRequest in server.request_handlers
    return server


async def call_real_sdk_tool(server: Any, name: str, arguments: dict[str, Any]) -> Any:
    from mcp.types import CallToolRequest, CallToolRequestParams

    handler = server.request_handlers[CallToolRequest]
    request = CallToolRequest(
        method="tools/call",
        params=CallToolRequestParams(name=name, arguments=arguments),
    )
    response = await handler(request)
    return response.root


def response_text(result: Any) -> str:
    assert result.content
    text = getattr(result.content[0], "text", None)
    assert isinstance(text, str)
    return text


@pytest.mark.asyncio
async def test_all_registered_adapters_cross_pinned_sdk_mcp_boundary(tmp_path: Path) -> None:
    from mcp.types import ListToolsRequest

    services = make_services(tmp_path)
    server = real_sdk_server(services)

    list_handler = server.request_handlers[ListToolsRequest]
    listed = await list_handler(ListToolsRequest(method="tools/list"))
    assert [tool.name for tool in listed.root.tools] == EXPECTED_TOOL_NAMES
    listed_by_name = {tool.name: tool for tool in listed.root.tools}
    for name, properties in EXPECTED_TOOL_PROPERTIES.items():
        assert listed_by_name[name].inputSchema == {
            "type": "object",
            "properties": properties,
            "required": list(properties),
        }

    repository = await call_real_sdk_tool(server, "inspect_repository", {})
    assert repository.isError is not True

    pytest_response = await call_real_sdk_tool(server, "run_pytest", {"args": []})
    assert pytest_response.isError is not True

    api_response = await call_real_sdk_tool(
        server,
        "probe_api",
        {"method": "POST", "url": "http://127.0.0.1:9/never-contacted"},
    )
    assert api_response.isError is True

    browser = await call_real_sdk_tool(
        server,
        "inspect_browser",
        {"url": "https://blocked.invalid/"},
    )
    assert browser.isError is True

    classified = await call_real_sdk_tool(server, "classify_failure", {})
    assert classified.isError is not True

    read_response = await call_real_sdk_tool(
        server,
        "read_test_file",
        {"path": "tests/test_sample.py"},
    )
    assert read_response.isError is not True

    coverage_response = await call_real_sdk_tool(
        server,
        "search_test_coverage",
        {"query": "test_sample", "max_results": 10},
    )
    assert coverage_response.isError is not True
    coverage_payload = json.loads(response_text(coverage_response))

    plan_response = await call_real_sdk_tool(
        server,
        "plan_tests",
        {
            "requirement": "Preserve arithmetic behavior",
            "existing_coverage_json": '["tests/test_sample.py"]',
            "coverage_evidence_id": coverage_payload["coverage_evidence_id"],
        },
    )
    assert plan_response.isError is not True

    prioritized = await call_real_sdk_tool(
        server,
        "prioritize_regression",
        {"candidates_json": "[]", "dependency_confidence": 1.0},
    )
    assert prioritized.isError is not True

    review = await call_real_sdk_tool(
        server,
        "review_python_test",
        {"path": "tests/test_sample.py"},
    )
    assert review.isError is not True

    creation = await call_real_sdk_tool(
        server,
        "create_test_file",
        {
            "path": "tests/test_generated.py",
            "content": "def test_generated():\n    assert True\n",
            "plan_evidence_id": "not-authorized",
        },
    )
    assert creation.isError is True
    assert not (services.workspace / "tests" / "test_generated.py").exists()

    locator_verification = await call_real_sdk_tool(
        server,
        "verify_locator_candidates",
        {
            "url": "https://blocked.invalid/",
            "original_locator": "#submit",
            "candidates_json": "[]",
        },
    )
    assert locator_verification.isError is True

    proposal = await call_real_sdk_tool(
        server,
        "propose_locator_heal",
        {
            "path": "tests/test_sample.py",
            "expected_sha256": "0" * 64,
            "original_locator": "#submit",
            "candidates_json": "[]",
            "verification_evidence_id": "missing",
        },
    )
    assert proposal.isError is True

    application = await call_real_sdk_tool(
        server,
        "apply_locator_heal",
        {"proposal_evidence_id": "missing", "path": "tests/test_sample.py"},
    )
    assert application.isError is True

    contract = await call_real_sdk_tool(
        server,
        "validate_json_contract",
        {
            "instance_json": '{"value":4}',
            "schema_json": (
                '{"type":"object","properties":{"value":{"const":4}},"required":["value"]}'
            ),
        },
    )
    assert contract.isError is not True

    ci_analysis = await call_real_sdk_tool(
        server,
        "analyze_ci_failure",
        {"exit_code": 1, "log_tail": "AssertionError: synthetic"},
    )
    assert ci_analysis.isError is not True

    mobile = await call_real_sdk_tool(server, "inspect_mobile_runtime", {})
    assert mobile.isError is not True

    k6 = await call_real_sdk_tool(
        server,
        "run_k6",
        {
            "script": "performance/reference_sut.js",
            "target_url": "http://127.0.0.1:8000",
            "environment": "local",
            "max_p95_ms": 500.0,
            "max_error_rate": 2.0,
            "min_request_rate": 1.0,
        },
    )
    assert k6.isError is True

    assert services.state.tool_call_count == len(EXPECTED_TOOL_NAMES)


@pytest.mark.asyncio
async def test_real_sdk_boundary_blocks_second_mutation_until_revision_closure(
    tmp_path: Path,
) -> None:
    services = make_services(tmp_path)
    services.policy = PolicyEngine(
        tmp_path / "control",
        services.workspace,
        allow_test_writes=True,
    )
    server = real_sdk_server(services)

    coverage_response = await call_real_sdk_tool(
        server,
        "search_test_coverage",
        {"query": "test_sample", "max_results": 10},
    )
    coverage_payload = json.loads(response_text(coverage_response))
    plan_response = await call_real_sdk_tool(
        server,
        "plan_tests",
        {
            "requirement": "Preserve arithmetic behavior",
            "existing_coverage_json": '["tests/test_sample.py"]',
            "coverage_evidence_id": coverage_payload["coverage_evidence_id"],
        },
    )
    plan_payload = json.loads(response_text(plan_response))

    generated_path = "tests/test_generated_behavior.py"
    generated_content = "def test_generated_behavior():\n    value = 2 + 3\n    assert value == 5\n"
    creation = await call_real_sdk_tool(
        server,
        "create_test_file",
        {
            "path": generated_path,
            "content": generated_content,
            "plan_evidence_id": plan_payload["plan_evidence_id"],
        },
    )
    assert creation.isError is not True
    assert (services.workspace / generated_path).read_text(encoding="utf-8") == generated_content
    assert services.state.change_revision == 1

    patch_safety = services.state.validation_results[-1]
    assert patch_safety.name == "test_patch_safety"
    assert patch_safety.revision == 1
    assert patch_safety.status is ValidationStatus.PASS
    assert patch_safety.details["path"] == generated_path

    blocked_path = "tests/test_second_generated_behavior.py"
    second_creation = await call_real_sdk_tool(
        server,
        "create_test_file",
        {
            "path": blocked_path,
            "content": generated_content,
            "plan_evidence_id": plan_payload["plan_evidence_id"],
        },
    )
    assert second_creation.isError is True
    assert "change revision 1 is not closed" in response_text(second_creation)
    assert not (services.workspace / blocked_path).exists()
    assert services.state.change_revision == 1
