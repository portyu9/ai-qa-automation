# MCP Integration Policy

## Principle
Use MCP deliberately, not everywhere. External MCP must be first-party/vendor-official and explicitly approved.

## GitHub
The showcase points to GitHub's official `github/github-mcp-server` container and restricts configured toolsets to repositories, issues, pull requests, and actions. It is disabled by default and needs credentials plus a working container runtime.

## Atlassian
The showcase points to Atlassian Rovo MCP's current `/v1/mcp/authv2` endpoint. It is disabled by default and requires organization-approved authentication.

## Runtime isolation
The production-shaped Agent SDK configuration uses `strict_mcp_config=True`; runtime MCP servers are supplied explicitly rather than inherited from target/user/plugin configuration.

## Future integrations
If a vendor has no approved official MCP, use its supported REST/GraphQL/API through a narrow internal adapter or report `NOT_CONFIGURED`. Do not substitute a random community MCP package.
