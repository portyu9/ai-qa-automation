from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.fs_authority import pin_directory_identity
from ai_qa_automation.models import AgentRunState
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.internal_tools import RuntimeServices, build_internal_mcp_server


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


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def make_services(workspace: Path, artifact_root: Path) -> RuntimeServices:
    state = AgentRunState(objective="exercise confined model-facing tools", workspace=str(workspace))
    return RuntimeServices(
        workspace=workspace,
        state=state,
        evidence=EvidenceStore(artifact_root, state.run_id),
        policy=PolicyEngine(workspace.parent / "control", workspace),
        test_runner=cast(Any, object()),
        max_tool_calls=20,
        max_repeated_action=5,
        workspace_root_identity=pin_directory_identity(workspace, label="test workspace"),
    )


def tool_map(services: RuntimeServices) -> dict[str, Any]:
    server, _names = build_internal_mcp_server(services)
    tools = cast(list[Any], cast(dict[str, Any], server)["tools"])
    return {str(tool.__name__): tool for tool in tools}


@pytest.mark.asyncio
async def test_read_test_file_rejects_policy_allowed_symlink_alias(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    del fake_sdk
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    workspace = tmp_path / "workspace"
    write(workspace / "tests" / "real.py", "def test_real():\n    assert True\n")
    (workspace / "tests" / "alias.py").symlink_to("real.py")
    services = make_services(workspace, tmp_path / "artifacts")

    response = await tool_map(services)["read_test_file"]({"path": "tests/alias.py"})

    assert response["is_error"] is True
    assert "symlink" in response["content"][0]["text"].casefold()
    assert services.state.policy_decisions[-1].decision.value == "ALLOW"
    assert "tests/alias.py" not in services.state.files_read


@pytest.mark.asyncio
async def test_review_python_test_rejects_policy_allowed_symlinked_parent(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    del fake_sdk
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    workspace = tmp_path / "workspace"
    write(workspace / "real-tests" / "test_case.py", "def test_case():\n    assert True\n")
    (workspace / "tests").symlink_to("real-tests", target_is_directory=True)
    services = make_services(workspace, tmp_path / "artifacts")

    response = await tool_map(services)["review_python_test"]({"path": "tests/test_case.py"})

    assert response["is_error"] is True
    assert "symlinked parent" in response["content"][0]["text"].casefold()
    assert services.state.policy_decisions[-1].decision.value == "ALLOW"


@pytest.mark.asyncio
async def test_read_test_file_fails_closed_after_whole_workspace_replacement(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    del fake_sdk
    workspace = tmp_path / "workspace"
    write(workspace / "tests" / "test_subject.py", "ORIGINAL = True\n")
    services = make_services(workspace, tmp_path / "artifacts")
    workspace.rename(tmp_path / "original-workspace")
    write(workspace / "tests" / "test_subject.py", "REPLACEMENT = True\n")

    response = await tool_map(services)["read_test_file"]({"path": "tests/test_subject.py"})

    assert response["is_error"] is True
    assert "root changed identity" in response["content"][0]["text"].casefold()
    assert services.state.policy_decisions[-1].decision.value == "ALLOW"
    assert "REPLACEMENT" not in response["content"][0]["text"]


@pytest.mark.asyncio
async def test_coverage_search_records_unsafe_namespace_as_incomplete(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    del fake_sdk
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    write(workspace / "tests" / "test_safe.py", "def test_safe():\n    assert True\n")
    outside = tmp_path / "outside"
    write(outside / "tests" / "test_hidden.py", "def test_hidden():\n    assert True\n")
    (workspace / "external").symlink_to(outside, target_is_directory=True)
    services = make_services(workspace, tmp_path / "artifacts")

    response = await tool_map(services)["search_test_coverage"](
        {"query": "", "max_results": 100}
    )

    assert response.get("is_error") is not True
    payload = json.loads(response["content"][0]["text"])
    assert payload["complete"] is False
    assert "unsafe_or_special_paths_skipped" in payload["incomplete_reasons"]
    assert [item["path"] for item in payload["results"]] == ["tests/test_safe.py"]
    evidence = services.evidence.get(payload["coverage_evidence_id"])
    assert evidence.structured_data["complete"] is False
    assert evidence.structured_data["unsafe_path_count"] == 1


@pytest.mark.asyncio
async def test_coverage_search_matches_raw_secret_shaped_query_but_persists_only_redaction(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    del fake_sdk
    workspace = tmp_path / "workspace"
    secret_shaped_query = "ghp_ABCDEFGHIJKLMNOPQRST"
    write(
        workspace / "tests" / "test_token.py",
        f"def test_token():\n    observed = '{secret_shaped_query}'\n    assert observed\n",
    )
    services = make_services(workspace, tmp_path / "artifacts")

    response = await tool_map(services)["search_test_coverage"](
        {"query": secret_shaped_query, "max_results": 10}
    )

    assert response.get("is_error") is not True
    payload = json.loads(response["content"][0]["text"])
    assert [item["path"] for item in payload["results"]] == ["tests/test_token.py"]
    assert secret_shaped_query not in response["content"][0]["text"]
    evidence = services.evidence.get(payload["coverage_evidence_id"])
    rendered = evidence.model_dump_json()
    assert secret_shaped_query not in rendered
    assert evidence.source_identifier == "[REDACTED]"
    assert evidence.structured_data["query"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_plan_tests_carries_coverage_incompleteness_forward(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    del fake_sdk
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    write(workspace / "tests" / "test_safe.py", "def test_safe():\n    assert True\n")
    outside = tmp_path / "outside"
    write(outside / "tests" / "test_hidden.py", "def test_hidden():\n    assert True\n")
    (workspace / "external").symlink_to(outside, target_is_directory=True)
    services = make_services(workspace, tmp_path / "artifacts")
    tools = tool_map(services)

    search_response = await tools["search_test_coverage"]({"query": "", "max_results": 100})
    search_payload = json.loads(search_response["content"][0]["text"])
    plan_response = await tools["plan_tests"](
        {
            "requirement": "Validate authorization behavior",
            "existing_coverage_json": json.dumps(["tests/test_safe.py"]),
            "coverage_evidence_id": search_payload["coverage_evidence_id"],
        }
    )

    assert plan_response.get("is_error") is not True
    plan_payload = json.loads(plan_response["content"][0]["text"])
    plan_evidence = services.evidence.get(plan_payload["plan_evidence_id"])
    assert plan_evidence.structured_data["coverage_complete"] is False
    assert "unsafe_or_special_paths_skipped" in plan_evidence.structured_data[
        "coverage_incomplete_reasons"
    ]


def test_runtime_services_rejects_malformed_workspace_identity(tmp_path: Path) -> None:
    state = AgentRunState(objective="identity bounds", workspace=str(tmp_path))

    with pytest.raises(ValueError, match="workspace_root_identity"):
        RuntimeServices(
            workspace=tmp_path,
            state=state,
            evidence=cast(Any, object()),
            policy=cast(Any, object()),
            test_runner=cast(Any, object()),
            max_tool_calls=3,
            max_repeated_action=2,
            workspace_root_identity=(1, -1),
        )
