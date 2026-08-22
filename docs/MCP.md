# MCP Integration Policy

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

External MCP is an **integration plane, not an authority extension**. A server can be vendor-official and still expose tools the autonomous runtime should not use or return content that is hostile, misleading, malformed, stale, or instruction-shaped.

The framework therefore separates two decisions:

1. **Provider identity/configuration** — is this an approved vendor path?
2. **Action authorization** — is this specific requested operation allowed under runtime policy?

## Approved integrations

| Provider | Trusted path | Default posture |
|---|---|---|
| GitHub | official `github/github-mcp-server` container pinned to `v1.0.5` | disabled; server-side read-only defense in depth |
| Atlassian | official Rovo MCP endpoint `https://mcp.atlassian.com/v1/mcp/authv2` | disabled; local action policy still authoritative |

Provider versions/endpoints are configuration contracts and should be reviewed deliberately when vendor behavior changes.

## GitHub MCP

Trusted container image:

```text
ghcr.io/github/github-mcp-server:v1.0.5
```

Defense-in-depth configuration:

```text
GITHUB_READ_ONLY=1
GITHUB_TOOLSETS=repos,issues,pull_requests,actions
```

Local prerequisites:

- Docker available to the control process;
- `GITHUB_PERSONAL_ACCESS_TOKEN` injected through the environment;
- `AI_QA_ENABLE_GITHUB_MCP=true`;
- least-privilege repository/resource permissions.

Server-side read-only mode is not the sole authorization boundary. Local policy still classifies every external action.

## Atlassian Rovo MCP

Trusted endpoint:

```text
https://mcp.atlassian.com/v1/mcp/authv2
```

The framework does not persist Atlassian credentials. It enables the vendor endpoint only when `AI_QA_ENABLE_ATLASSIAN_MCP=true`; session/authentication evidence comes from the authorized provider flow.

Jira/Confluence content remains untrusted evidence. A remote page or issue that instructs Claude to change policy, reveal credentials, weaken tests, or use another integration has no control-plane authority.

## Runtime isolation

The live runtime uses `strict_mcp_config=True` and constructs the external server dictionary explicitly.

It does not inherit:

- target `.mcp.json`;
- target `CLAUDE.md` / `.claude/` authority;
- unrelated user MCP config;
- arbitrary plugin/community MCP servers;
- local connectors not built by trusted runtime code.

The root control-plane `.mcp.json` remains a trusted developer artifact, but live runtime identity still comes from the explicit registry/configuration path.

## Tool-action authorization

Approved server identity is not blanket permission.

| Action class | Runtime decision |
|---|---|
| recognized read | may be allowed |
| write/update | `REQUIRE_APPROVAL`; unattended execution fails closed |
| destructive/high-impact | denied by default |
| unknown | requires approval; unattended execution fails closed |
| unknown namespace | denied |

### Mixed-name hardening

Provider tool names do not share one naming convention, so action parsing normalizes snake/camel/mixed names into semantic tokens.

Authorization precedence is conservative:

```text
destructive semantics > write semantics > recognized read semantics
```

Examples:

- `get_issue` → recognized read;
- `getOrCreateIssue` → write semantics dominate the `get` prefix;
- `listAndDeleteIssues` → destructive semantics dominate;
- `getUpdateAndRemoveLabel` → destructive semantics dominate both read/write tokens.

The GitHub resource noun `pull request` is handled explicitly so the word `request` inside that noun does not accidentally classify ordinary pull-request reads as writes.

## External evidence semantics

A successful authorized provider response is sanitized and persisted as **untrusted observed evidence**.

Remote content cannot redefine:

- tool policy;
- trusted settings;
- Skills;
- network/write authority;
- evaluation thresholds;
- runtime result rules.

Configuration alone does not create `AVAILABLE`. Provider availability is recorded only from observed successful interaction.

A failed provider call does not create synthetic remote evidence.

## Failure normalization

Provider failures are normalized into explicit runtime outcomes such as:

- `NOT_CONFIGURED`;
- `UNAUTHORIZED`;
- `RATE_LIMITED`;
- `UNAVAILABLE`;
- `INVALID_RESPONSE`;
- `FAILED`.

The normalizer intentionally distinguishes transport/status context from arbitrary business identifiers. Text such as `issue 403 failed lookup` is not automatically interpreted as HTTP 403. Status-like classification requires explicit response metadata or status-shaped language such as `HTTP 403` / `status code 403`.

Authentication/authorization failure dominates ambiguous retryable text; explicit rate limiting dominates malformed-body side effects so retry/backoff semantics remain deterministic.

See [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) for how provider outcomes remain separate from the QA terminal outcome.

## Outage behavior

A provider outage:

- does not erase valid local evidence;
- does not manufacture remote evidence;
- does not widen local authority;
- does not authorize a switch to an unapproved provider/community server merely to keep the workflow moving.

## Provider approval rule

A service is connected only through:

- an approved first-party/vendor-official MCP; or
- a narrow vendor-supported API adapter with equivalent authentication, authorization, evidence, and failure semantics.

Community substitutes are not introduced merely to increase feature count.

## Related documentation

- [`README.md`](README.md) — documentation landing page
- [`SETUP.md`](SETUP.md) — enablement/credential configuration
- [`SECURITY.md`](SECURITY.md) — deterministic security controls
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — adversarial cases
- [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) — provider and terminal outcome semantics
- [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) — production control model

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
