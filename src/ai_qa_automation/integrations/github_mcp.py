from __future__ import annotations

import os
from typing import Any

from ..models import MCPStatus


def github_mcp_config() -> tuple[MCPStatus, dict[str, Any] | None]:
    token = os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
    if not token:
        return MCPStatus.NOT_CONFIGURED, None
    return (
        MCPStatus.AVAILABLE,
        {
            "type": "stdio",
            "command": "docker",
            "args": [
                "run",
                "-i",
                "--rm",
                "-e",
                "GITHUB_PERSONAL_ACCESS_TOKEN",
                "-e",
                "GITHUB_TOOLSETS=repos,issues,pull_requests,actions",
                "ghcr.io/github/github-mcp-server",
            ],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": token},
        },
    )
