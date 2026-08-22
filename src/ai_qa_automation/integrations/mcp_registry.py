from __future__ import annotations

from typing import Any

from ..config import Settings
from ..models import MCPStatus, ToolDecision
from ..policy import PolicyEngine
from .atlassian_mcp import atlassian_mcp_config
from .github_mcp import github_mcp_config


def build_external_mcp(settings: Settings, policy: PolicyEngine) -> tuple[dict[str, Any], dict[str, MCPStatus]]:
    servers: dict[str, Any] = {}
    statuses: dict[str, MCPStatus] = {}

    if settings.enable_github_mcp:
        decision = policy.validate_mcp_server("github", "github/github-mcp-server")
        if decision.decision == ToolDecision.ALLOW:
            status, config = github_mcp_config()
            if status is not None:
                statuses["github"] = status
            if config:
                servers["github"] = config
    else:
        statuses["github"] = MCPStatus.NOT_CONFIGURED

    decision = policy.validate_mcp_server("atlassian", "atlassian/rovo-mcp")
    if settings.enable_atlassian_mcp and decision.decision == ToolDecision.ALLOW:
        status, config = atlassian_mcp_config(enabled=True)
        if status is not None:
            statuses["atlassian"] = status
        if config:
            servers["atlassian"] = config
    else:
        statuses["atlassian"] = MCPStatus.NOT_CONFIGURED

    return servers, statuses
