# Verification Boundaries

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

Verification is meaningful only when the evidence source and trust owner are explicit. The ƳƤ AI QA Automation Framework therefore separates **repository-contained controls**, **local runtime observations**, **credentialed-provider evidence**, and **target/deployment evidence**.

This boundary prevents a common failure in AI/system documentation: allowing implementation presence, configuration presence, or a neighboring green signal to stand in for evidence that belongs to a different trust domain.

## Evidence classes

| Class | Evidence owner | Examples |
|---|---|---|
| Repository-contained | deterministic framework code/tests/evaluators | policy, state/evidence contracts, change intelligence, result logic |
| Local runtime | local executable/runtime environment | Chromium, Docker, k6, Appium visibility |
| Credentialed provider | authorized provider session | Claude, GitHub MCP, Atlassian MCP interaction |
| Target environment | selected application/test environment | browser/API behavior, load target, app/device session |
| Deployment infrastructure | organization/platform controls | process/container isolation, firewall, secrets, identity, retention |

A capability can span multiple classes. GitHub MCP authorization logic is repository-contained; Docker is a local runtime dependency; GitHub authentication and repository permissions are credentialed-provider evidence.

## Repository-contained control surfaces

The codebase defines deterministic control/evaluation surfaces for areas including:

- typed state, evidence, policy, validation, provider, and terminal-outcome contracts;
- terminal truth with gate identity + revision supersession;
- failure classification;
- deterministic locator parsing/semantic scoring;
- same-DOM Playwright candidate verification;
- self-healing authorization and locator-only mutation;
- observed coverage search, plan-bound test generation, and test-quality review;
- regression prioritization and uncertainty broadening;
- canonical host/IP configuration validation;
- path/tool/MCP/API/performance authorization;
- secret-shaped `.env` path protection;
- recursive redaction and credential-minimal subprocess environments;
- evidence/artifact confinement, immutability, and content hashes;
- atomic state and hash-chained runtime journal;
- independent execution budgets and per-tool circuits;
- workspace lease and fingerprint logic;
- transactional mutation and rollback verification;
- stale recovery with path/symlink/fingerprint/hash ownership checks;
- merge-base change intelligence, CODEOWNERS, test impact, OpenAPI drift;
- lineage graph and unsigned attestation semantics;
- fixed primary and independent holdout evaluators;
- deterministic reference-SUT behavior.

These are framework contracts. [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) defines how runtime evidence and validation become terminal truth.

## Local runtime dependencies

Some execution surfaces require local/system components even when no remote account is involved:

- Playwright browser executable;
- Docker for the configured GitHub MCP container path;
- k6 executable;
- Appium/device tooling.

`ai-qa doctor` reports locally observable capability without treating package/executable presence as provider authentication evidence.

## Credentialed provider evidence

Credentialed evidence belongs to the provider interaction:

- Claude Agent SDK request/response behavior with `ANTHROPIC_API_KEY`;
- GitHub MCP behavior with an authorized GitHub credential and provider tool call;
- Atlassian Rovo MCP behavior with an authorized authentication/session and provider call.

The framework records provider `AVAILABLE` only after an observed successful interaction. Local configuration does not manufacture availability.

Provider outcomes remain separate from the QA terminal outcome.

## Target-environment evidence

Target-specific behavior includes:

- Playwright behavior against the selected application;
- API authentication/data/business behavior;
- k6 metrics against the approved workload;
- Appium behavior against the selected app/device environment;
- target-specific database/cache/queue/external dependency behavior;
- application authorization and data-classification rules.

Reference fixtures help exercise framework mechanics but do not define arbitrary external application behavior.

## Deployment-infrastructure evidence

The repository can impose prerequisites and refuse unsafe operations, but it does not pretend to own infrastructure outside its process boundary.

Deployment evidence covers properties such as:

- process/container/VM isolation;
- non-root/security context;
- firewall/proxy/egress enforcement;
- organization identity and secret-management lifecycle;
- artifact encryption/access/retention;
- device/cloud security;
- compliance and legal controls;
- trusted runner/CI infrastructure.

Application-layer allowlists and flags are defense in depth, not substitute evidence for these controls.

## Capability matrix

| Capability | Framework-owned contract | Environment/provider-owned evidence |
|---|---|---|
| Claude reasoning loop | Agent SDK orchestration, policy, result semantics | credentialed provider interaction |
| Terminal truth | gate/revision lineage and result derivation | actual validation observations for the run |
| GitHub MCP | official config, action policy, failure normalization | auth, permissions, provider responses |
| Atlassian MCP | official endpoint config, action policy, failure normalization | auth/session, site permissions, provider responses |
| Network policy | canonical host validation + adapter authorization | DNS/routing/firewall/proxy enforcement |
| Playwright | navigation/subrequest/WebSocket policy, locator evidence contract | browser runtime + target app behavior |
| API | host/method policy, bounded httpx/evidence path | target auth/data/service behavior |
| k6 | target/environment/script/threshold policy | executable, approved target, infrastructure egress |
| Appium | runtime/capability policy boundary | app/device/emulator/cloud session |
| Secret safety | protected paths, redaction, subprocess env, scan definitions | organization secret store, rotation, access policy |
| Mutation integrity | lease, fingerprint, path ownership, transaction/rollback logic | filesystem/process isolation surrounding runtime |
| Traceability | manifests, hashes, journal, lineage, unsigned attestation | external signing/identity/timestamping when required |

## Artifact boundary

Text evidence is sanitized along supported model-facing/text persistence paths. Binary screenshots remain `RAW` artifacts with hashes and require appropriate storage/access/retention controls.

Hashing and hash chaining provide internal tamper-evidence properties. They do not create an external trusted signer, timestamp, identity, or correctness proof.

## Practical claim rule

Use the narrowest statement that matches the evidence owner:

- **implemented control** → established by source/configuration;
- **deterministic behavior** → established by execution/evaluation for the exercised path;
- **provider behavior** → established by authorized provider interaction;
- **target behavior** → established by target-specific observation;
- **deployment property** → established by infrastructure/organization evidence.

Do not move evidence across these boundaries merely because the architecture around it is well designed.

See [`README.md`](README.md), [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md), [`SETUP.md`](SETUP.md), [`OPERATIONS.md`](OPERATIONS.md), and [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
