# Verification Boundaries

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

This document defines where verification evidence comes from and which trust boundary owns it. The purpose is to keep repository evidence, local runtime evidence, credentialed-provider evidence, and deployment evidence conceptually separate.

## Evidence classes

| Class | Meaning |
|---|---|
| Repository-contained | Source/configuration plus deterministic tests/evaluators exercise behavior without external credentials/services. |
| Local runtime dependent | Uses a local executable/runtime such as Chromium, Docker, k6, or Appium visibility. |
| Credentialed integration | Uses a real credential/OAuth session and provider response. |
| Target-environment dependent | Uses a real application, device, load target, network boundary, or organization infrastructure. |

A capability can span more than one class. GitHub MCP policy and failure normalization, for example, are repository-contained controls, while provider authentication and repository permissions belong to the credentialed integration boundary.

## Repository-contained deterministic behavior

The codebase defines deterministic controls and evaluation surfaces for areas including:

- typed state, evidence, policy, and structured-result contracts;
- failure classification and regression prioritization;
- browser-evidence semantics and locator-healing proposal rules;
- observed coverage search, plan-bound test creation, and test-quality/safe-patch rules;
- path/tool/MCP/API/performance authorization;
- secret redaction;
- evidence/artifact manifests and content hashes;
- optional hash-chained audit records;
- runtime journal integrity;
- independent tool/network/mutation/repetition/wall-time budgets;
- per-tool failure circuits;
- workspace lease and fingerprint logic;
- transactional mutation and stale-crash recovery rules;
- revision-aware deterministic validation lineage;
- trusted runtime-configuration fingerprinting;
- merge-base change intelligence, CODEOWNERS, test-impact mapping, and OpenAPI drift;
- lineage graph construction and unsigned attestation semantics;
- the fixed 34-scenario primary evaluator;
- the separate H-series holdout evaluator;
- deterministic reference-SUT behavior.

## Local runtime-dependent capabilities

Local/system components provide execution surfaces such as:

- Playwright browser runtime;
- Docker for the configured GitHub MCP container path;
- k6 for performance execution;
- Appium/device tooling for mobile runtime inspection and target-specific execution.

`ai-qa doctor` reports locally observable capabilities without treating package presence as remote authentication evidence.

## Credentialed integrations

Credentialed evidence belongs to the provider session itself:

- Claude Agent SDK requests use `ANTHROPIC_API_KEY`;
- GitHub MCP uses an authorized GitHub credential and provider tool call;
- Atlassian Rovo MCP uses an authorized OAuth/token session and provider tool call.

The runtime records provider availability from observed interaction rather than from configuration presence alone.

## Target-environment capabilities

Target/deployment evidence covers properties such as:

- Playwright behavior against the selected application;
- API behavior against the selected target;
- k6 measurements against the approved workload;
- infrastructure-enforced outbound egress;
- Appium behavior against the selected app/device environment;
- container/VM/process privilege isolation;
- firewall/proxy policy;
- organization identity, secrets, retention, audit, and compliance controls;
- application-specific authorization and data-classification policy.

The framework can enforce prerequisites and policy around these boundaries without pretending to own infrastructure outside its control plane.

## Capability matrix

| Capability | Framework-owned evidence | Environment-owned evidence |
|---|---|---|
| Claude reasoning loop | Agent SDK orchestration, policy, result semantics | credentialed provider request/response |
| GitHub MCP | official server config, provider/tool policy, health normalization | authentication, permissions, provider responses |
| Atlassian MCP | official endpoint config, provider/tool policy, health normalization | OAuth/token flow, site permissions, provider responses |
| Playwright | controlled browser adapter, host/subrequest policy | browser runtime and target application behavior |
| API | host/method policy, `httpx` adapter, schema/evidence paths | target authentication, data, and availability |
| k6 | target/script policy, threshold assessment | executable, approved target, infrastructure egress |
| Appium | runtime capability inspection and policy boundary | app/device/session environment |
| Secret safety | redaction, protected paths, scan definitions | organization secret store, rotation, access control |
| Sandbox/egress | application-layer restrictions and prerequisites | OS/container/firewall/proxy enforcement |
| Traceability | manifests, hashes, journal, lineage, unsigned attestation | external signing/identity/timestamping when required |

## Artifact boundary

Text evidence is sanitized before model consumption along supported evidence paths. Binary screenshots remain `RAW` artifacts with hashes and therefore require appropriate filesystem, access, and retention controls.

Hashing and hash chaining provide integrity and tamper-evidence properties inside the persisted record set; they do not establish an external trusted signer or timestamp.

## Practical operating rule

Use the narrowest evidence statement that matches the source of truth:

- source/configuration establishes implemented control structure;
- deterministic execution establishes repository behavior for the exercised path;
- provider interaction establishes credentialed integration behavior;
- target/deployment observation establishes environment-specific behavior.

See [`SETUP.md`](SETUP.md), [`OPERATIONS.md`](OPERATIONS.md), and [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
