# MCP Integration Policy

## Principle

External MCP is used only when the server is first-party/vendor-official and explicitly enabled. Server approval does not grant every exposed tool automatically.

## GitHub

The trusted configuration uses GitHub's official `ghcr.io/github/github-mcp-server:v1.0.5` image with `GITHUB_READ_ONLY=1`. The configured toolsets are repositories, issues, pull requests, and actions. The integration is disabled by default. Configuration alone does not set runtime health to `AVAILABLE`; that status is recorded only after a successful observed tool call.

## Atlassian

The trusted configuration uses Atlassian Rovo MCP at `https://mcp.atlassian.com/v1/mcp/authv2`. It is disabled by default.

## Runtime isolation

The Agent SDK runtime sets `strict_mcp_config=True` and supplies its server dictionary explicitly. It does not accept the target repository's `.mcp.json`, user MCP configuration, plugin MCP servers, or unrelated local connectors as runtime authority.

## Tool-level permission policy

- read-only external operations can be allowed
- GitHub MCP is additionally constrained by server-side read-only mode
- external writes from integrations that expose them return `REQUIRE_APPROVAL`
- unattended execution converts approval-required operations to denial
- destructive/high-impact operations are denied by default
- unknown MCP namespaces and unknown external actions fail closed

## Services without an approved MCP

A service without an approved first-party MCP is not connected through a community substitute. Its capability remains `NOT_CONFIGURED` or is implemented through a narrow adapter to the vendor's supported API.

## Failure handling

MCP transport and response failures are normalized as `UNAUTHORIZED`, `RATE_LIMITED`, `UNAVAILABLE`, `INVALID_RESPONSE`, or `FAILED`. An integration failure does not create synthetic GitHub/Jira/Confluence evidence.
