# Production Readiness Architecture

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

Production readiness in an agentic QA system is not a property of the model. It is a property of the **control system around the model**: authority, evidence, execution boundaries, validation, recovery, security, and deployment discipline.

The ƳƤ AI QA Automation Framework therefore uses one governing principle:

> **Claude may reason about quality; deterministic controls and observed evidence govern quality decisions.**

## Readiness model

The architecture separates concerns that conventional AI agents often blur together:

| Concern | Owner | Rule |
|---|---|---|
| Reasoning | Claude | May interpret evidence and choose among authorized next actions |
| Authority | Policy, hooks, runtime control | Determines whether an action is permitted |
| Observation | Controlled tools | Produces evidence from the target/provider/runtime |
| Validation | Deterministic gates | Determines whether a claim is proven for a scope/revision |
| Mutation integrity | Transaction + workspace ownership | Prevents stale, concurrent, or unsafe writes |
| Terminal truth | Result contract | Derives the final runtime outcome from validation/integrity state |
| Deployment assurance | Infrastructure / organization | Owns isolation, egress, identity, secrets, retention, and target access |

A persuasive model response cannot substitute for any lower layer in this table.

## Production control domains

### 1. Agent orchestration

- official Claude Agent SDK orchestration;
- bounded turn and cost configuration;
- trusted project configuration source;
- explicit Skill inventory;
- explicit internal tool inventory;
- strict external MCP configuration;
- structured final reporting.

### 2. Deterministic runtime authority

- fail-closed tool authorization;
- explicit denial of general Bash/Edit/Write/Web-style authority;
- independent PreToolUse/PostToolUse/failure hooks;
- approval-required actions denied during unattended execution;
- governance/security paths protected from autonomous change;
- network, method, path, and performance-target policies enforced outside the model.

### 3. Evidence provenance

- typed evidence records;
- observed fact versus model interpretation separation;
- run-scoped immutable evidence identities;
- hashed artifacts and manifests;
- credential-aware recursive sanitization;
- raw binary artifacts explicitly identified rather than mislabeled sanitized;
- provider failures recorded without fabricating remote evidence.

### 4. Runtime truth

The final report is governed by [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md).

Key properties include:

- model completion does not imply success;
- missing deterministic validation resolves to `NOT_VERIFIED`;
- current `FAIL` evidence remains failure;
- contradictory PASS/FAIL evidence at the same revision remains unresolved;
- validation is bound to gate identity and change revision;
- changed tests require patch-safety, targeted pytest, and full-regression closure;
- provider availability is independent from QA terminal truth.

### 5. Autonomous mutation safety

- test writes are disabled unless explicitly enabled;
- autonomous writes are restricted to approved test-code directories;
- target must be a Git-backed isolated worktree;
- OS-backed workspace lease establishes cooperating-process ownership;
- content-sensitive fingerprint detects out-of-band drift;
- absolute/traversal/workspace-escape/symlink mutation paths are rejected;
- trusted rollback snapshots are hash-verified;
- one mutation transaction is open at a time;
- a newer human edit is never overwritten merely to complete stale automated rollback.

### 6. Safe self-healing

Locator maintenance requires more than “the new selector works.”

The framework requires:

- compatible deterministic failure classification;
- same-DOM Playwright measurement;
- candidate uniqueness;
- supported literal locator syntax;
- policy-owned stability scoring;
- deterministic semantic-intent overlap between original and candidate locators;
- exact file-hash binding;
- locator-only mutation;
- post-change deterministic closure.

Model-supplied semantic/stability confidence can support reasoning but cannot authorize autonomous mutation.

### 7. Coverage-aware generation

Generated tests follow a provenance chain:

```text
observed repository coverage
→ evidence-bound gap
→ same-run test plan
→ guarded creation
→ deterministic quality checks
→ targeted execution
→ regression closure
```

The framework rejects common false-quality shortcuts such as assertionless tests, tautological assertions, skip/xfail, arbitrary sleeps, focused-only tests, broad exception suppression, and unsupported write paths.

### 8. Change intelligence

Deterministic bootstrap can establish:

- explicit base-ref and merge-base provenance;
- committed plus dirty/untracked change union;
- risk-domain classification;
- repository/test topology;
- dependency inventory and hashes;
- CODEOWNERS routing;
- explainable test-impact candidates;
- conservative OpenAPI/Swagger compatibility drift.

Incomplete mapping increases caution. It never becomes evidence that omitted testing is safe.

### 9. Network and external-system safety

The runtime separates provider identity from tool authority.

- external network access is disabled unless explicitly enabled;
- trusted host allowlists contain canonical host/IP entries only—no wildcard or URL-shaped configuration;
- API probes default to read-only methods;
- browser HTTP(S) and WebSocket traffic passes through host policy;
- ambient proxy inheritance is avoided in controlled HTTP/subprocess paths;
- GitHub and Atlassian MCP use approved vendor paths;
- remote content remains untrusted evidence;
- unknown/mixed external actions fail closed or require approval;
- destructive external actions are denied by default.

### 10. Performance safety

k6 execution requires:

- an explicit HTTP(S) target;
- a recognized non-production environment;
- denial of production-like host labels even when caller metadata conflicts;
- injected target binding;
- bounded local-module analysis;
- rejection of remote modules, `k6/x/*`, local file reads, and unrelated literal network hosts;
- predefined measurement thresholds;
- an explicit infrastructure-egress prerequisite for non-local targets.

Application policy is defense in depth; it is not documented as a replacement for deployment network controls.

### 11. Reliability and recovery

The framework keeps QA decision state and process-control state separate.

Reliability controls include:

- exclusive workspace lease;
- independent execution budgets;
- repeated-action limits;
- per-tool failure circuits;
- atomic persisted state;
- append-only hash-chained operational journal;
- rollback-backed mutation transactions;
- stale recovery only under exact fingerprint and path-ownership conditions;
- recovery inspection without claiming hidden model-conversation replay.

### 12. Traceability and observability

A run can persist:

- run/session identifiers;
- target Git provenance;
- model/SDK/configuration provenance;
- structured runtime events;
- evidence and artifact manifests;
- SHA-256 content hashes;
- validation lineage;
- journal linkage;
- token/cost information when supplied by the provider;
- unsigned content-integrity attestation;
- optional regulated engineering traceability records.

Integrity controls help establish what was persisted and whether it changed. They do not override validation or constitute compliance certification.

## Evaluation architecture

The framework is designed to be evaluated as software.

| Layer | Purpose |
|---|---|
| Unit tests | schemas, policy, evidence, redaction, state, intelligence, budgets, recovery |
| Deterministic integration tests | runtime/evidence/reference-SUT behavior |
| Policy/security tests | authority, path, network, mutation, prompt-injection, fail-closed boundaries |
| Primary evaluator | fixed 34-scenario functional/adversarial corpus |
| Holdout evaluator | physically separate H-series independent corpus |
| Browser-marked tests | Playwright-backed browser behavior |
| Model-marked tests | credentialed Claude Agent SDK behavior |

Hard-safety expectations are predefined and are not weakened after observing a failure.

## Deployment contract

Some controls belong to the framework; others belong to the environment operating it. The design keeps those responsibilities explicit.

| Framework-owned control | Deployment-owned control |
|---|---|
| tool authorization | process/container isolation |
| application host/method policy | firewall/proxy/egress enforcement |
| secret-minimal subprocess environment | organization secret manager and rotation |
| target workspace confinement | filesystem/container/Kubernetes policy |
| evidence hashing and redaction paths | artifact access/retention/encryption policy |
| provider tool authorization | identity, OAuth/token lifecycle, organization permissions |
| load-target policy | approved load environment and infrastructure limits |
| Appium capability boundary | device/emulator/cloud provisioning and application signing |

Neither side is silently treated as proof of the other.

## Red-team questions the architecture must answer

- Can a failed test become a false-positive product defect?
- Can model interpretation become observed evidence without a tool observation?
- Can a model give a wrong unique locator enough confidence to authorize a repair?
- Can a generated test pass while asserting nothing meaningful?
- Can regression prioritization omit mandatory/security/safety/regulatory coverage?
- Can target `CLAUDE.md`, `.claude/`, `.mcp.json`, source, DOM, logs, or provider content redefine authority?
- Can a mixed MCP name hide a write/delete behind a read-looking prefix?
- Can secrets enter prompts, subprocesses, logs, or artifacts unintentionally?
- Can a path escape trusted evidence or target boundaries?
- Can a symlink redirect mutation or crash recovery?
- Can a stale rollback overwrite newer human work?
- Can same-revision retries hide contradictory validation?
- Can an outage become fabricated provider evidence?
- Can a clean feature branch hide committed risk from a worktree-only scan?
- Can execution exceed a resource budget by shifting work into another dimension?
- Can a production-like load target be disguised by friendly environment metadata?
- Can an integrity hash be misrepresented as a signature or test PASS?

A material weakness should produce a narrower policy, safer tool contract, deterministic regression test, adversarial evaluation, or explicit deployment boundary—not a stronger prompt alone.

## GitHub Actions

`.github/workflows/ci.yml` is operator-dispatched with `workflow_dispatch`. Its jobs define quality/type checks, deterministic pytest, primary evaluation, holdout evaluation, security scanning, a Playwright reference-SUT path, and an optional credentialed model smoke path under explicit operator control.

## Related documentation

- [`README.md`](README.md) — documentation landing page
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — authority, trust, and execution design
- [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) — terminal and validation semantics
- [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) — transaction and recovery mechanics
- [`SECURITY.md`](SECURITY.md) — deterministic security architecture
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — adversarial assumptions and residual boundaries
- [`EVALUATION.md`](EVALUATION.md) — evaluation and holdout governance
- [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) — evidence ownership across trust domains
- [`TECHNICAL_WALKTHROUGH.md`](TECHNICAL_WALKTHROUGH.md) — end-to-end code-path review

## License

The ƳƤ AI QA Automation Framework is licensed under the MIT License.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
