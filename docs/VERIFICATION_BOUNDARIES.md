# Verification Boundaries

This document answers a narrow question: **what can this repository establish by itself, and what still requires evidence from an external runtime/environment?**

The distinction prevents a common portfolio and production-readiness error: describing implemented integration code as though the external integration has actually been exercised.

## Evidence classes

| Class | Meaning |
|---|---|
| Repository-contained | Source/configuration plus deterministic tests/evaluators can exercise the behavior without external credentials/services. |
| Local runtime dependent | Requires a local executable/runtime such as Chromium, Docker, k6, or Appium visibility, but not necessarily a remote account. |
| Credentialed integration | Requires a real credential/OAuth session and provider response. |
| Target-environment dependent | Requires a real application, device, load target, network boundary, or organization infrastructure. |

A capability can span more than one class. For example, GitHub MCP policy/failure normalization is repository-contained, while authenticated GitHub MCP availability is credentialed integration evidence.

## Repository-contained deterministic behavior

The codebase contains deterministic controls/tests/evaluators for areas including:

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
- deterministic reference-SUT behavior that does not require an external service.

These behaviors are **defined** by repository-contained code/tests. They become current-head execution evidence only after the relevant commands are actually run and inspected.

## Local runtime-dependent capabilities

Some repository paths need installed local/system components even though they do not require user credentials:

- Playwright browser execution needs a compatible browser runtime;
- GitHub MCP's current local container shape needs Docker before a credentialed connection is possible;
- k6 execution needs the k6 executable;
- Appium runtime/device checks need the corresponding local/device infrastructure.

`ai-qa doctor` reports locally observable capability. It does not test remote authentication or declare a provider verified.

## Credentialed integrations

The following cannot be represented as verified without real authenticated execution:

- live Claude Agent SDK requests using `ANTHROPIC_API_KEY`;
- GitHub MCP with an authorized GitHub credential and observed tool call;
- Atlassian Rovo MCP with an authorized OAuth/token session and observed tool call.

Configuration presence is not sufficient. The runtime intentionally records external MCP as available only after an observed successful call.

## Target-environment-dependent capabilities

These require a real deployment/target beyond repository-contained fixtures:

- Playwright against an external target application;
- API behavior against a real approved target;
- k6 against an actual approved workload;
- infrastructure-enforced outbound egress for non-local load execution;
- Appium against an actual application plus emulator/device/device cloud;
- container/VM/process privilege isolation;
- network firewall/proxy policy;
- organization identity, secrets, retention, audit, and compliance controls;
- application-specific authorization and data-classification policy.

The repository can enforce prerequisites and refuse unsafe execution, but it cannot prove infrastructure it does not control.

## Capability matrix

| Capability | Repository-contained implementation | What remains to verify externally |
|---|---|---|
| Claude reasoning loop | Agent SDK orchestration, policy, result semantics | real credentialed request/response behavior |
| GitHub MCP | official server config, provider/tool policy, health normalization | auth, permissions, real provider responses |
| Atlassian MCP | official endpoint config, provider/tool policy, health normalization | OAuth/token flow, site permissions, real responses |
| Playwright | controlled browser adapter, host/subrequest policy | browser runtime; external app behavior when applicable |
| API | host/method policy, `httpx` adapter, schema/evidence paths | external target auth/data/availability |
| k6 | target/script policy, threshold assessment | executable + approved target + infrastructure egress |
| Appium | runtime capability inspection | actual app/device/session behavior |
| Secret safety | redaction/protected paths/security-scan definitions | org secret store, rotation, access control, operational handling |
| Sandbox/egress | application-layer restrictions and explicit prerequisites | actual OS/container/firewall/proxy enforcement |
| Traceability | manifests, hashes, journal, lineage, unsigned attestation | external signing/identity/timestamp/compliance if required |

## Artifact boundary

Text evidence is sanitized before model consumption along the supported evidence paths. Binary screenshots remain `RAW` artifacts with hashes; they are not described as sanitized text and require appropriate filesystem/access/retention controls.

Hashing and hash chaining provide integrity/tamper-evidence properties inside the persisted record set. They do not establish an external trusted signer or timestamp.

## Current-head truth rule

A test file, evaluator, workflow, or security scan definition existing in Git is an **implementation artifact**, not a PASS result. Current-head status remains `NOT_VERIFIED` until the applicable gate is deliberately executed and its result is available.

Historical successful execution can be recorded as `PREVIOUSLY_VERIFIED`, but it must not be silently reused as a release certificate for later code.

## Practical operating rule

When describing this project, use the narrowest accurate statement:

- “implemented” when source/configuration exists;
- “verified” only when matching execution evidence exists for the relevant code/environment;
- “environment required” when the repository cannot produce the missing evidence alone;
- “not configured” when an optional integration is deliberately absent;
- “not verified” when execution has not occurred or evidence is unavailable.

See [`SETUP.md`](SETUP.md), [`OPERATIONS.md`](OPERATIONS.md), and the authoritative status matrix in [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).
