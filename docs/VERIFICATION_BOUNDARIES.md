# Verification Boundaries

This document separates repository-contained behavior from capabilities that depend on external infrastructure.

## Repository-contained deterministic behavior

The codebase contains deterministic checks for:

- typed state, evidence, and structured result contracts
- failure classification and regression prioritization
- browser-observed locator uniqueness, semantic self-healing proposal rules, and locator-only patch controls
- observed coverage search, plan-bound test creation, and test-quality/safe-patch rules
- path/tool/MCP/API/performance authorization
- secret redaction
- evidence and artifact manifests
- optional hash-chained audit records
- bounded tool/repetition behavior and revision-aware validation lineage
- trusted runtime configuration fingerprinting
- the 34-scenario adversarial evaluator
- reference-SUT behavior that does not require an external system

These are exercised with the repository test and evaluation commands.

## Environment-dependent status

The following capabilities depend on credentials, binaries, devices, remote systems, or infrastructure outside the repository and are not represented as PASS without execution evidence:

- live Claude Agent SDK requests
- authenticated GitHub MCP sessions
- authenticated Atlassian Rovo MCP sessions
- Playwright against an external target application/browser runtime
- k6 against an actual approved workload, including externally enforced egress for non-local targets
- Appium against an application plus device/emulator/device cloud
- infrastructure-enforced container/VM isolation and outbound egress policy
- organization identity, secret-management, retention, and compliance controls

The code uses `NOT_VERIFIED`, `NOT_CONFIGURED`, explicit failure states, or policy denial rather than substituting a successful model statement for missing execution evidence.

## Artifact boundary

Text evidence is sanitized before model consumption. Binary screenshots are retained as `RAW` artifacts with hashes; they are not described as sanitized and require appropriate filesystem/retention access controls.
