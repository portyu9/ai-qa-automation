# Design Boundaries and Non-Claims

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

A production-quality control system should be explicit about the boundary of every claim. The ƳƤ AI QA Automation Framework therefore documents where its deterministic authority ends and where provider-, target-, domain-, or deployment-specific evidence begins.

These are **architectural boundaries**, not development-progress notes.

## Claude / model boundary

- No prompt or model can guarantee perfect reasoning.
- Model confidence is not observed system truth.
- Repetition or confidence does not convert interpretation into evidence.
- Deterministic policy, ownership, evidence, and validation remain authoritative.
- Model/SDK provenance matters because upgrades can change probabilistic behavior.

## Runtime-result boundary

The runtime semantics in [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) are deliberately conservative.

- `SUCCESS` applies to deterministic closure, not persuasive model output.
- `NOT_VERIFIED` is not equivalent to failure; it preserves unresolved truth.
- same-revision contradictory evidence is surfaced rather than averaged away;
- historical PASS does not automatically certify a newer change revision;
- integrity metadata never overrides a test result.

## External integration boundary

- GitHub and Atlassian access is limited to approved vendor-official integration paths.
- Provider identity does not grant blanket permission to every tool.
- Remote GitHub/Jira/Confluence content remains untrusted evidence.
- Authentication, authorization, provider behavior, rate limits, and availability belong to the connected provider/account context.
- A provider's future tool-surface changes still pass through local action authorization.

## Network-configuration boundary

- The trusted allowlist accepts canonical hostnames/IP literals, not URLs or wildcard policy expressions.
- Host allowlisting controls application-layer destinations; it is not a firewall.
- DNS resolution, routing, proxy policy, TLS trust, and network segmentation remain deployment concerns.
- A host being allowlisted does not imply the endpoint is safe for every operation or dataset.

## Browser boundary

- Playwright observations are scoped to the browser context and target under test.
- Browser navigation/subrequest/WebSocket controls are application-layer safeguards rather than an OS/container network sandbox.
- Service-worker blocking improves routed visibility but is not a replacement for infrastructure egress controls.
- DOM/accessibility evidence can be dynamic or incomplete.
- Locator uniqueness is an observation, not semantic correctness.
- Cross-browser, responsive, accessibility, localization, visual, and device coverage remains target-strategy dependent.

## API boundary

- The built-in API adapter provides bounded HTTP request/evidence/schema behavior.
- Read-only methods are the safe default; mutating methods require explicit enablement.
- Host/method authorization does not establish business authorization for a particular endpoint.
- JSON Schema/OpenAPI validation complements rather than replaces business-semantic validation.
- Target authentication, test data, tenancy, state isolation, and cleanup remain target-specific concerns.

## OpenAPI contract-drift boundary

The contract analyzer is conservative and bounded. It detects supported structural compatibility changes such as removed paths/operations, newly required inputs, successful-response removal, schema/type changes, required-property additions/removals, and enum narrowing.

`NON_BREAKING` means no breaking/risky condition was found under the implemented structural rules. It is not a proof that every client remains compatible.

`NOT_ANALYZED` remains visible uncertainty and must not be interpreted as compatibility.

## CODEOWNERS boundary

The runtime supports a bounded CODEOWNERS grammar with deterministic precedence/last-match behavior. Unsupported patterns are surfaced rather than approximated.

CODEOWNERS data is routing/review context, not runtime authorization.

## Test-impact and regression boundary

- Test-impact mapping is advisory rather than a complete program-dependency proof.
- Static path/component/reference signals can miss runtime/dynamic coupling.
- Low confidence, incomplete dependency information, or truncation broadens regression.
- Mandatory security, safety, regulatory, and smoke coverage is protected independently of impact score.
- The framework does not claim mathematically optimal regression minimization.

## Failure-classification boundary

- Deterministic heuristics classify observed evidence, not every possible real-world root cause.
- `INSUFFICIENT_EVIDENCE` is expected when observations do not discriminate safely.
- Locator-contract classification requires semantic evidence rather than any arbitrary unique candidate.
- Domain-specific application semantics can require additional target evidence beyond generic framework signals.

## Test-generation boundary

- Generated tests require authoritative expected behavior.
- The framework does not invent undocumented product intent merely to produce a test.
- Meaningful-assertion checks reject common weak patterns but do not prove the assertion expresses the most valuable business invariant.
- Supported generation paths prioritize Python, JavaScript, and TypeScript test ecosystems.
- Domain fixtures, data factories, service virtualization, and environment setup remain target-specific unless integrated deliberately.

## Self-healing boundary

- Autonomous healing is intentionally narrow and locator-oriented.
- There is no generic existing-test rewrite capability in the live agent runtime.
- Locator uniqueness is necessary but not sufficient.
- Deterministic semantic matching is intentionally conservative and can reject a legitimate repair for human review rather than over-authorize a risky one.
- Policy-owned stability scores are heuristics for locator durability, not guarantees that a product contract will never change.
- A real product-behavior change must not be disguised as an automation repair.

## Test-execution boundary

- pytest execution cannot make arbitrary third-party dependencies deterministic.
- Contradictory PASS/FAIL evidence at the same revision is surfaced rather than hidden.
- External clocks, queues, networks, datasets, databases, caches, and services can still introduce nondeterminism.
- Target-specific containers, emulators, certificates, credentials, test users, and cleanup remain explicit environment responsibilities.

## Performance boundary

- k6 execution is restricted to bounded, explicitly non-production targets.
- Static script/import controls reduce known escape paths but are not a general JavaScript sandbox.
- Non-local execution requires an explicit infrastructure-egress prerequisite.
- The prerequisite records trusted deployment intent; it does not prove a firewall is correctly configured.
- Business SLOs, workload models, data shape, scaling topology, cloud quotas, and distributed load generation remain environment/domain concerns.

## Mobile boundary

Appium integration is represented through controlled runtime/capability inspection and target-specific mobile execution configuration. Device, emulator, simulator, cloud, application-build, provisioning, certificate, and platform-capability choices belong to the deployment/test environment.

## Security boundary

- Deterministic policy, path ownership, host controls, redaction, transactional mutation, and adversarial tests reduce risk but do not imply absence of unknown vulnerabilities.
- Application-level restrictions do not replace process/container isolation, firewall/proxy policy, identity, secret management, or DLP controls.
- Raw screenshots and other binary artifacts may contain sensitive data and require appropriate storage/access/retention controls.
- Redaction is defense in depth, not permission to place secrets/private production data into an unapproved environment.
- Secret-shaped `.env` paths are protected from runtime reads, while `.env.example` remains reference documentation; other project-specific secret locations still require target governance.

## Evidence-integrity boundary

- SHA-256 artifact hashes and hash-chained journals provide tamper-evidence properties inside the persisted record set.
- They are not actor identity, notarization, trusted timestamps, or digital signatures.
- The unsigned attestation is content-integrity metadata and does not alter a QA result.
- A perfectly intact record can faithfully describe a failed or unresolved run.

## Regulated-mode boundary

`AI_QA_REGULATED_MODE=true` adds engineering traceability and retention labeling. It does not certify HIPAA, PCI DSS, SOC 2, ISO 27001, FDA, SOX, GDPR, or another assurance regime.

Compliance depends on organization-specific policies, legal interpretation, infrastructure, access controls, retention/deletion, validation, and audit evidence.

## Observability boundary

- Structured events, metrics models, correlation/run IDs, artifacts, and OpenTelemetry-compatible code paths are observability surfaces.
- Logs/metrics complement rather than replace underlying evidence and validation lineage.
- Token/cost values are recorded when supplied by the provider rather than estimated as observed fact.
- A telemetry backend/exporter/storage policy is a deployment choice.

## Recovery boundary

- Canonical state/evidence is persisted independently from model conversation history.
- Recovery begins from persisted evidence; it does not reconstruct hidden model reasoning.
- Automatic stale rollback preserves newer human work by refusing ambiguous fingerprints or path ownership.
- Recovery rejects symlink aliases and verifies rollback bytes before restoration.
- If integrity cannot be guaranteed, the correct result is an explicit blocker/infrastructure failure—not best-effort overwrite.

## Container and infrastructure boundary

The included Dockerfile defines a non-root control-plane image shape. Deployment policy determines additional controls such as:

- read-only filesystems;
- seccomp/AppArmor/SELinux;
- Kubernetes security context;
- network policy;
- secret injection;
- persistent artifact storage;
- image signing/provenance;
- resource quotas and runtime monitoring.

## CI/CD boundary

`.github/workflows/ci.yml` is operator-dispatched and separates quality, deterministic evaluation, holdout, security, browser-reference, and optional model jobs.

Workflow logic does not replace repository/organization policy for branch protection, trusted runners, secret exposure, artifact retention, dependency provenance, or untrusted-fork execution.

## Reference-SUT boundary

The reference FastAPI application is deliberately small and deterministic. It exists to make selected evidence/failure paths reproducible. It is not a claim of coverage across every web architecture, authentication pattern, data system, distributed failure, or production traffic shape.

## Context and retrieval boundary

The architecture favors targeted retrieval and bounded summaries over sending entire repositories, logs, or traces to the model.

Additional RAG/vector infrastructure should be introduced only when it has a justified quality/trust benefit; avoiding it by default is a scope and trust decision, not a claim that retrieval platforms are never useful.

## Configuration boundary

- `.env.example` is documentation only; runtime settings do not auto-load repository `.env` files.
- Secret/configuration presence does not imply validity.
- `AI_QA_BASE_REF` is explicit when merge-base analysis is required.
- Raising budgets or enabling write/network authority is a deliberate configuration decision, not evidence that every resulting action is safe.
- Configuration fingerprints capture runtime input identity; they do not prove configuration correctness.

See [`README.md`](README.md), [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md), [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md), [`SETUP.md`](SETUP.md), and [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
