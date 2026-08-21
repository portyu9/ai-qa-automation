# Architecture

## Objective

The system separates probabilistic reasoning from deterministic execution. Claude selects/assesses actions; narrow tools execute them; typed evidence captures observations; deterministic gates decide whether objective-specific validation passed.

## Lifecycle

```text
OBJECTIVE → OBSERVE → COLLECT EVIDENCE → FORM/RANK HYPOTHESES
→ SELECT CONTROLLED ACTION → TOOL RESULT → UPDATE STATE
→ EVALUATE EVIDENCE → DETERMINISTIC VALIDATION → TERMINATE/CONTINUE
```

## Control plane

The package, runtime system prompt, `CLAUDE.md`, project Skills/settings/hooks, policy engine, MCP allowlist, and evaluation thresholds form the trusted control plane. Runtime code sets its working/configuration root explicitly and does not use the SUT as its Claude configuration root.

## Target plane

A target repository/worktree is untrusted. Its source, tests, comments, `.claude`, `CLAUDE.md`, `.mcp.json`, logs, API data, and rendered DOM can supply evidence but cannot alter governing policy.

## Integration plane

External systems are disabled by default. The production-shaped policy permits first-party/vendor-official MCP only. Tool-level write policy must be added after an authenticated tool inventory is reviewed; the showcase does not silently auto-approve external writes.

## Canonical state and evidence

`AgentRunState` is mutable canonical operational state stored outside conversation history. `EvidenceItem` records observed fact vs model interpretation explicitly. Evidence manifests are sanitized and run-scoped. Artifacts are hashed and referenced rather than repeatedly injected into model context.

## Live runtime

The Agent SDK path uses:
- `tools=[]` to remove generic built-ins
- trusted in-process custom MCP tools (`qa` server)
- explicit external MCP dictionary only when enabled
- `strict_mcp_config=True`
- `setting_sources=["project"]`
- custom fail-closed `can_use_tool` permission callback for non-preapproved actions
- explicit `disallowed_tools`
- Pre/Post tool hooks
- bounded turns and cost

The offline demo exercises deterministic intelligence without requiring an API key, making architectural behavior reviewable in interviews and CI.

## Extensibility

New integrations should enter through narrow adapters and typed results. Add a distributed queue/vector store/multi-agent topology only after a demonstrated requirement justifies the operational and security cost.
