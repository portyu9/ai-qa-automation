from __future__ import annotations

from typing import Any

from ..models import MCPStatus

ATLASSIAN_ROVO_MCP_URL = "https://mcp.atlassian.com/v1/mcp/authv2"


def atlassian_mcp_config(*, enabled: bool) -> tuple[MCPStatus, dict[str, Any] | None]:
    if not enabled:
        return MCPStatus.NOT_CONFIGURED, None
    # Authentication is delegated to the MCP client's supported OAuth/API-token flow.
    return MCPStatus.AVAILABLE, {"type": "http", "url": ATLASSIAN_ROVO_MCP_URL}
