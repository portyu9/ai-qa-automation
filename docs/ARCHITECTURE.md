# Architecture

## Objective

The system separates probabilistic reasoning from deterministic execution. Claude interprets evidence and selects bounded actions; narrow tools execute; typed records capture observations; deterministic gates decide whether a result is verified.

## Lifecycle

```text
OBJECTIVE → OBSERVE → COLLECT EVIDENCE → FORM/RANK HYPOTHESES
→ SELECT CONTROLLED ACTION → TOOL RESULT → UPDATE STATE
→ EVALUATE EVIDENCE → DETERMINISTIC VALIDATION → TERMINATE/CONTINUE
```

## Control plane

The Python package, runtime system prompt, `CLAUDE.md`, Skills, project settings/hooks, policy engine, MCP allowlist, and evaluation thresholds form the trusted control plane. The runtime sets its working/configuration root explicitly and does not use the target repository as its Claude configuration root.

## Target plane

A target repository/worktree is untrusted. Its source, tests, comments, `.claude`, `CLAUDE.md`, `.mcp.json`, logs, API data, and rendered DOM can supply evidence but cannot alter governing policy.

## Integration plane

External integrations are disabled by default. External MCP configuration is limited to explicitly approved first-party/vendor-official services. Read and write capabilities are evaluated at tool level; approval-required writes fail closed in unattended execution.

## Runtime tool surface

The Agent SDK path uses:

- `tools=[]` for the base built-in tool set
- a project-owned in-process QA MCP server
- explicit external MCP configuration only when enabled
- `strict_mcp_config=True`
- `setting_sources=["project"]` and an explicit five-Skill allowlist
- explicit `disallowed_tools`
- deterministic tool lifecycle hooks plus a programmatic permission handler
- a fail-closed permission handler
- bounded turns, tool calls, repeated actions, time, and model cost

The internal QA server exposes 18 narrow tools covering repository inspection, pytest, API/browser evidence, failure classification, bounded test-file reads, observed coverage search, coverage-bound planning, regression selection, test review/creation, browser-proven locator verification and locator-only healing, schema validation, CI analysis, Appium runtime inspection, and k6 assessment. The runtime does not expose a generic existing-test replacement tool.

## Canonical state and evidence

`AgentRunState` is mutable canonical operational state stored outside conversation history. It records a fingerprint of the trusted runtime configuration and a monotonic test-change revision. `EvidenceItem` separates observed evidence from model interpretation. Evidence and artifact manifests are run-scoped and sanitized. Artifacts are content-hashed and referenced rather than repeatedly copied into model context.

When regulated mode is enabled, evidence/artifact registrations also produce a hash-chained audit log. The control adds traceability and artifact-integrity metadata without making a compliance claim.

## Deterministic terminal status

A model result subtype of `success` is insufficient by itself. Deterministic validation has immutable lineage keyed by gate and change revision. For each gate, the latest revision is authoritative for the current state while older failures remain recorded as history. A later PASS can supersede an older FAIL only for the same gate after an approved mutation advances the revision. Conflicting PASS and FAIL observations for the same gate at the same revision produce `NOT_VERIFIED`, so an ordinary retry cannot hide flakiness.

When a test file changes, the current revision cannot close successfully without patch-safety PASS, targeted pytest PASS, and full-regression pytest PASS. Another mutation is blocked until that revision is closed.

## Network and write boundaries

API and browser access use explicit host allowlists and disable ambient proxy inheritance. API methods are read-only by default. Browser HTTP(S) subresources and WebSocket connections use the same allowlist as initial navigation. Test writes are disabled by default and, when enabled, are restricted to test directories and deterministic patch checks.

k6 execution requires an explicitly non-production target, the runtime host allowlist, a script bound to an injected target URL, and static rejection of remote/extension modules and local-file reads. A non-local target additionally requires trusted configuration to assert infrastructure-level egress enforcement.

## External MCP

GitHub and Atlassian configurations are explicit and disabled by default. Target/user/plugin MCP configuration is not inherited by the runtime. Unknown external MCP namespaces are denied.

Services without an approved official MCP stay `NOT_CONFIGURED` or use a narrow vendor API adapter outside the MCP boundary.

## Root isolation

The live runtime requires the trusted control root and target workspace to be disjoint. The control root must contain the project `CLAUDE.md` and `.claude/settings.json`; target configuration is never accepted as the Agent SDK project root.
