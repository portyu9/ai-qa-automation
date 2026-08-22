# Production Readiness

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

The ƳƤ AI QA Automation Framework is designed around a simple release principle:

> **A model can reason about quality, but deterministic controls and observed evidence govern quality decisions.**

This document describes the framework's production-readiness architecture and the controls that support safe operation.

## Readiness model

The framework separates four concerns that are often blurred together in AI-assisted testing:

- **reasoning** — Claude interprets evidence, forms hypotheses, and selects among authorized actions;
- **authority** — deterministic policy and hooks decide what actions are permitted;
- **evidence** — controlled tools capture observations, artifacts, hashes, and provenance;
- **verification** — deterministic validators decide whether required gates passed.

A persuasive model response never substitutes for deterministic validation.

## Architecture and trust model

| Contract requirement | Framework design |
|---|---|
| Agent SDK orchestration | Official Claude Agent SDK loop with bounded turns, cost, and controlled tools |
| Deterministic authority | Policy callbacks, runtime hooks, explicit tool inventory, fail-closed authorization |
| Canonical state | `AgentRunState`, `StateStore`, persisted `state.json` outside conversation history |
| Process control | Separate `runtime.json`, workspace lease, budgets, circuits, mutation metadata, journal head |
| Evidence provenance | Typed evidence, run-scoped manifests, artifact hashes, validation lineage |
| Trust separation | Trusted control plane separated from untrusted SUT/source/DOM/log/API/config content |
| External integrations | Explicit vendor-approved MCP configuration plus independent tool-level authorization |
| Bounded execution | Independent turn/tool/network/mutation/repetition/time/cost limits |

## Runtime security

The runtime security model includes:

- an explicit trusted Agent SDK configuration source;
- a narrow QA tool surface instead of generic Bash/Edit/Write/Web authority;
- fail-closed handling for unknown tools, namespaces, paths, and actions;
- governance-path protection;
- OS-backed workspace ownership;
- content-sensitive workspace fingerprints before mutation;
- rejection of absolute, traversal, workspace-escape, and symlink mutation paths;
- transactional mutation with rollback snapshots and revision closure;
- artifact-root confinement and immutable evidence identities;
- host/method/browser/k6 network controls;
- fail-closed production-load detection;
- credential-minimal subprocess environments and recursive redaction.

## Core QA automation

The framework provides controlled surfaces for:

- pytest execution and evidence capture;
- Playwright browser evidence and locator verification;
- API probing with explicit host/method policy;
- deterministic regression selection;
- k6 performance assessment with target and script controls;
- Appium runtime/capability inspection;
- CI-failure evidence analysis;
- JSON Schema validation;
- coverage-aware test generation;
- semantic locator maintenance;
- test-quality review.

## AI quality controls

### Failure classification

Failure attribution is evidence-weighted. A failed test is not automatically classified as a product defect, and model interpretation alone cannot prove a defect class.

### Safe self-healing

Locator repair is evidence-bound and intent-preserving. Candidate selectors must be browser-observed, semantically appropriate, unique under the controlled observation, and bound to the exact file/hash/classification context.

### Test generation

Generation follows an explicit provenance chain:

```text
observed repository coverage
→ evidence-bound plan
→ guarded test creation
→ deterministic quality and execution validation
```

### Regression prioritization

Mandatory security, safety, regulatory, and smoke coverage is preserved independently of model preference. Low confidence broadens regression rather than justifying omission.

### Prompt-injection resistance

Target source, tests, DOM, logs, API responses, GitHub/Jira content, and target agent configuration are treated as untrusted data. They cannot redefine the trusted control plane.

## Change intelligence

Deterministic bootstrap can capture:

- trusted base-ref and merge-base provenance;
- committed plus dirty/untracked changes;
- risk-domain classification;
- repository/test topology;
- dependency-manifest inventory and hashes;
- CODEOWNERS routing;
- explainable test-impact candidates;
- OpenAPI/Swagger compatibility drift.

Incomplete mapping increases caution; it never becomes proof that omitted testing is safe.

## Reliability and recovery

The framework isolates QA decision state from process-control state and protects interrupted runs through:

- exclusive workspace leases;
- independent execution budgets;
- per-tool failure circuits;
- transactional autonomous mutation;
- fingerprint-aware rollback;
- preservation of newer human changes;
- append-only hash-chained runtime journaling;
- persisted recovery inspection.

## Evidence, traceability, and observability

Run records can include:

- run/session identifiers;
- structured runtime events;
- evidence and artifact manifests;
- SHA-256 content hashes;
- append-only journal linkage;
- optional regulated traceability records;
- evidence-to-validation lineage;
- model/SDK/config provenance;
- observed token/cost information;
- unsigned content-integrity attestations.

Integrity metadata supports traceability; it does not override test results or deterministic validation.

## MCP and external systems

External MCP access is restricted to explicitly approved vendor integrations. Server identity and tool authority are separate decisions.

The policy model distinguishes recognized reads, approval-sensitive writes, destructive actions, unknown actions, authentication failures, throttling, provider unavailability, and invalid responses. Remote content remains untrusted evidence after retrieval.

## Evaluation architecture

The framework's evaluation design includes:

- unit and deterministic integration tests;
- policy and security tests;
- a fixed 34-scenario primary adversarial corpus;
- a physically separate H-series holdout corpus;
- browser-marked tests isolated from the default pytest path;
- credentialed model tests isolated behind explicit configuration;
- predefined hard-safety thresholds that are not relaxed after observing a failure.

## Security red-team questions

The architecture is designed to answer questions such as:

- Can a failed test become a false-positive product defect?
- Can model interpretation become observed evidence without proof?
- Can self-healing select the wrong nearby element or weaken test intent?
- Can generated tests pass while asserting nothing meaningful?
- Can regression selection omit mandatory coverage?
- Can hostile target or remote content redefine runtime authority?
- Can a mixed MCP action name smuggle a write or destructive action behind a read prefix?
- Can secrets enter prompts, logs, subprocess environments, or artifacts?
- Can evidence paths escape trusted storage?
- Can symlink aliases redirect an autonomous mutation?
- Can concurrent or interrupted runs overwrite human work?
- Can retries hide contradictory validation?
- Can provider failures become fabricated evidence?
- Can execution exceed independent resource budgets?
- Can a production-like load target be disguised through caller metadata?
- Can an integrity hash be mistaken for a signature or test result?

A material weakness should be addressed with a deterministic control, safer tool contract, regression test, adversarial evaluation, or explicit deployment boundary rather than model reassurance.

## Manual GitHub Actions

`.github/workflows/ci.yml` is intentionally operator-dispatched with `workflow_dispatch`. The workflow defines quality, deterministic evaluation, holdout, security, browser-reference, and optional credentialed model jobs while keeping execution under explicit operator control.

## Related documentation

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — authority and trust design
- [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) — transaction and recovery mechanics
- [`EVALUATION.md`](EVALUATION.md) — evaluation and holdout governance
- [`SECURITY.md`](SECURITY.md) — security architecture
- [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) — evidence and environment boundaries
- [`TECHNICAL_WALKTHROUGH.md`](TECHNICAL_WALKTHROUGH.md) — end-to-end code-path review

## License

The ƳƤ AI QA Automation Framework is licensed under the MIT License.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
