from __future__ import annotations

from typing import Any

from ..tools.performance import K6Runner
from .internal_tool_domains.browser import register_browser_tools
from .internal_tool_domains.common import (
    MAX_MODEL_SOURCE_CHARS as _MAX_MODEL_SOURCE_CHARS,
    RuntimeServices,
    change_revision_closed as _change_revision_closed,
    coverage_search as _coverage_search,
    pytest_scope as _pytest_scope,
    pytest_validation_status as _pytest_validation_status,
    record_patch_safety_validation as _record_patch_safety_validation,
    require_closed_revision_before_mutation as _require_closed_revision_before_mutation,
    stable_gate_id as _stable_gate_id,
)
from .internal_tool_domains.network import register_network_tools
from .internal_tool_domains.performance import register_performance_tools
from .internal_tool_domains.repository import register_repository_tools
from .internal_tool_domains.testing import register_testing_tools
from .internal_tool_domains.validation import register_validation_tools

_TOOL_NAMES = (
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
)


def _merge_registered_tools(target: dict[str, Any], registered: dict[str, Any]) -> None:
    for name, handler in registered.items():
        if name in target:
            raise RuntimeError(f"duplicate internal MCP tool registration: {name}")
        target[name] = handler


def build_internal_mcp_server(services: RuntimeServices) -> tuple[Any, list[str]]:
    """Create trusted in-process MCP tools owned by this application."""
    try:
        from claude_agent_sdk import create_sdk_mcp_server, tool
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("claude-agent-sdk is required for live agent mode") from exc

    registered: dict[str, Any] = {}
    for registrar in (
        register_repository_tools,
        register_testing_tools,
        register_network_tools,
        register_browser_tools,
        register_validation_tools,
    ):
        _merge_registered_tools(registered, registrar(services, tool))
    _merge_registered_tools(
        registered,
        register_performance_tools(services, tool, k6_runner_cls=K6Runner),
    )

    expected = set(_TOOL_NAMES)
    observed = set(registered)
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        raise RuntimeError(
            f"internal MCP tool registry mismatch: missing={missing!r} extra={extra!r}"
        )

    tools = [
        registered["inspect_repository"],
        registered["run_pytest"],
        registered["probe_api"],
        registered["inspect_browser"],
        registered["classify_failure"],
        registered["read_test_file"],
        registered["search_test_coverage"],
        registered["plan_tests"],
        registered["prioritize_regression"],
        registered["review_python_test"],
        registered["create_test_file"],
        registered["verify_locator_candidates"],
        registered["propose_locator_heal"],
        registered["apply_locator_heal"],
        registered["validate_json_contract"],
        registered["analyze_ci_failure"],
        registered["inspect_mobile_runtime"],
        registered["run_k6"],
    ]
    server = create_sdk_mcp_server(name="qa", version="1.0.0", tools=tools)
    names = [f"mcp__qa__{name}" for name in _TOOL_NAMES]
    return server, names
