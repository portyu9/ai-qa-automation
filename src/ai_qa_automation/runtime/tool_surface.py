from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

_SERVER_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


def sdk_allowed_tools(
    internal_tool_names: Sequence[str],
    external_servers: Mapping[str, Any],
) -> list[str]:
    """Build the exact Agent SDK allow-surface from trusted configured servers.

    Internal tools remain explicit full names. External providers are granted
    only their MCP namespace prefix; deterministic local policy still decides
    each concrete read/write/destructive action when requested.
    """

    result = list(internal_tool_names)
    for name in sorted(external_servers):
        if not _SERVER_NAME.fullmatch(name):
            raise ValueError(f"invalid trusted MCP server name: {name!r}")
        result.append(f"mcp__{name}")
    return result
