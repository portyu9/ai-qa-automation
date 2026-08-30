from __future__ import annotations

import os
from typing import Any

from ..models import MCPStatus

GITHUB_MCP_IMAGE = (
    "ghcr.io/github/github-mcp-server:v1.0.4@"
    "sha256:e3816a476a977cfb836e7d221510011436c654d11861db66ecfd826601aba6a4"
)


def github_mcp_config() -> tuple[MCPStatus | None, dict[str, Any] | None]:
    token = os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
    if not token:
        return MCPStatus.NOT_CONFIGURED, None
    return (
        None,
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
                "-e",
                "GITHUB_READ_ONLY=1",
                GITHUB_MCP_IMAGE,
            ],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": token},
        },
    )
