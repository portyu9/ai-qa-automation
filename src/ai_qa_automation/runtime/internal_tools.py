from __future__ import annotations

from typing import Any, cast

from ..tools.api_testing import ApiProbe
from ..tools.browser_evidence import BrowserProbe
from ..tools.performance import K6Runner
from .internal_tool_domains import common as _common
from .internal_tool_domains.browser import register_browser_tools
from .internal_tool_domains.network import register_network_tools
from .internal_tool_domains.performance import register_performance_tools
from .internal_tool_domains.repository import register_repository_tools
from .internal_tool_domains.testing import register_testing_tools
from .internal_tool_domains.validation import register_validation_tools

_MAX_MODEL_SOURCE_CHARS = _common.MAX_MODEL_SOURCE_CHARS
RuntimeServices = _common.RuntimeServices
_change_revision_closed = _common.change_revision_closed
_coverage_search = _common.coverage_search
_pytest_scope = _common.pytest_scope
_pytest_validation_status = _common.pytest_validation_status
_record_patch_safety_validation = _common.record_patch_safety_validation
_require_closed_revision_before_mutation = _common.require_closed_revision_before_mutation
_stable_gate_id = _common.stable_gate_id

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

    tool_decorator = cast(_common.ToolDecorator, tool)
    registered: dict[str, Any] = {}
    _merge_registered_tools(registered, register_repository_tools(services, tool_decorator))
    _merge_registered_tools(registered, register_testing_tools(services, tool_decorator))
    _merge_registered_tools(
        registered,
        register_network_tools(services, tool_decorator, api_probe_cls=ApiProbe),
    )
    _merge_registered_tools(
        registered,
        register_browser_tools(services, tool_decorator, browser_probe_cls=BrowserProbe),
    )
    _merge_registered_tools(registered, register_validation_tools(services, tool_decorator))
    _merge_registered_tools(
        registered,
        register_performance_tools(services, tool_decorator, k6_runner_cls=K6Runner),
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
