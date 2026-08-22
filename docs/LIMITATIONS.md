# Design Boundaries and Non-Claims

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

The ƳƤ AI QA Automation Framework is deliberately explicit about the boundaries of its authority. These are architectural constraints and deployment responsibilities, not project-progress notes.

## Claude / model boundary

- No prompt or model can guarantee perfect reasoning.
- Model confidence is not observed system truth.
- Deterministic policy, evidence, and validation remain authoritative.
- Model and SDK provenance should be recorded because upgrades can alter behavior.

## External integration boundary

- GitHub and Atlassian access is limited to approved vendor-official integration paths.
- Server identity does not grant blanket permission to every tool.
- Remote GitHub/Jira/Confluence content remains untrusted evidence.
- Authentication, authorization, and provider behavior are properties of the connected environment and account.

## Browser boundary

- Playwright observations are scoped to the browser context and target under test.
- Browser host/subrequest/WebSocket controls are application-layer safeguards rather than an operating-system network sandbox.
- DOM/accessibility evidence can be dynamic or incomplete; locator uniqueness must come from observation, not model assertion.
- Cross-browser, device, responsive, accessibility, and visual coverage is defined by the target test strategy.

## API boundary

- The built-in API adapter provides bounded request, evidence, and schema behavior.
- Read-only methods are the safe default; mutating methods require explicit enablement.
- JSON Schema/OpenAPI validation complements rather than replaces business-semantic validation.
- Target authentication, authorization, data rules, and environment setup remain explicit inputs to the test objective.

## OpenAPI contract-drift boundary

The contract analyzer is conservative and bounded. It detects supported structural compatibility changes such as removed paths/operations, newly required inputs, successful-response removal, schema/type changes, required-property additions, removals, and enum narrowing.

`NON_BREAKING` means the bounded analyzer found no breaking/risky condition under its implemented rules; it is not a mathematical proof of compatibility for every consumer.

`NOT_ANALYZED` remains visible uncertainty and must not be interpreted as compatibility.

## CODEOWNERS boundary

The runtime supports a bounded CODEOWNERS grammar with deterministic precedence and last-match behavior. Unsupported patterns are surfaced rather than guessed.

CODEOWNERS information is review/routing context, not runtime authorization.

## Test-impact and regression boundary

- Test-impact mapping is advisory rather than a complete dependency proof.
- Static signals can miss dynamic dependencies.
- Low confidence, incomplete dependency information, or truncated scans broaden regression.
- Mandatory security, safety, regulatory, and smoke coverage is protected independently of impact score.

## Test-generation boundary

- Generated tests require authoritative expected behavior.
- The framework does not invent undocumented product intent merely to produce a test.
- Meaningful-assertion checks reject common weak patterns but do not replace domain review.
- The supported generation paths prioritize Python, JavaScript, and TypeScript test ecosystems.

## Self-healing boundary

- Autonomous healing is intentionally narrow and locator-oriented.
- There is no generic existing-test rewrite capability in the live agent runtime.
- Locator uniqueness is necessary but not sufficient; semantic correctness and test-intent preservation remain required.
- Ambiguous repair is refused rather than optimized for heal-rate metrics.

## Test-execution boundary

- pytest execution cannot make arbitrary third-party dependencies deterministic.
- Contradictory PASS/FAIL evidence at the same revision is surfaced rather than hidden.
- Target-specific databases, containers, service emulators, certificates, credentials, and fixtures remain explicit test-environment concerns.

## Performance boundary

- k6 execution is restricted to bounded, explicitly non-production targets.
- Non-local execution requires an explicit infrastructure-egress prerequisite.
- Static script controls reduce known escape paths but are not a general JavaScript sandbox.
- Business SLOs and load profiles must be defined before interpreting measurements.

## Mobile boundary

Appium integration is represented through controlled runtime/capability inspection and target-specific mobile execution configuration. Device, emulator, cloud, application-build, provisioning, and platform capability choices belong to the deployment/test environment.

## Security boundary

- Deterministic policy, protected paths, network restrictions, secret redaction, transactional mutation, and adversarial tests reduce risk but do not imply the absence of unknown vulnerabilities.
- Application-level restrictions do not replace process/container isolation, firewall/proxy policy, identity, secret management, or data-loss-prevention controls.
- Raw binary artifacts such as screenshots may contain sensitive data and require appropriate storage/access/retention handling.
- Redaction is defense in depth, not permission to place secrets or private production data into an unapproved environment.

## Evidence-integrity boundary

- SHA-256 artifact hashes and hash-chained journals provide tamper-evidence properties.
- They are not actor identity, notarization, trusted timestamps, or digital signatures.
- The unsigned attestation is content-integrity metadata and does not alter a test result.

## Regulated-mode boundary

`AI_QA_REGULATED_MODE=true` adds engineering traceability and retention labeling. Compliance with HIPAA, PCI DSS, SOC 2, ISO 27001, FDA, SOX, GDPR, or other regimes depends on organization-specific controls, policies, legal interpretation, infrastructure, evidence, and audits.

## Observability boundary

- Structured events, metrics models, correlation IDs, run IDs, artifacts, and OpenTelemetry-compatible code paths are observability surfaces.
- Logs and metrics complement rather than replace underlying evidence artifacts and validation gates.
- Token/cost values are recorded when supplied by the model/provider rather than estimated as observed fact.

## Recovery boundary

- Canonical state and evidence are persisted independently from model conversation history.
- Recovery starts from persisted evidence; it does not reconstruct hidden model reasoning.
- Automatic stale rollback preserves newer human/out-of-band changes by refusing ambiguous ownership.
- Autonomous mutation paths reject symlink components rather than treating aliases as equivalent ownership.

## Container and infrastructure boundary

The included Dockerfile defines a non-root control-plane image shape. Deployment policy determines additional controls such as read-only filesystems, seccomp/AppArmor/SELinux, Kubernetes security context, network policy, secret injection, persistent artifact storage, signing, and provenance.

## CI/CD boundary

`.github/workflows/ci.yml` is operator-dispatched and separates quality, deterministic evaluation, holdout, security, browser-reference, and optional model jobs. Production credentials must never be exposed to untrusted pull-request execution.

## Reference-SUT boundary

The reference application is deliberately small and deterministic. It exists to make selected evidence and failure paths reproducible; target-specific validation defines the behavior of any real application under test.

## Context and retrieval boundary

The architecture prefers targeted retrieval and bounded summaries over sending entire repositories, logs, or traces to the model. Additional retrieval infrastructure should be introduced only when it has a justified quality and trust benefit.

## Configuration boundary

- `.env.example` is documentation only; runtime settings do not auto-load repository `.env` files.
- Secret/configuration presence does not imply validity.
- `AI_QA_BASE_REF` is explicit when merge-base analysis is required.
- Raising budgets or enabling write/network authority is a deliberate configuration decision, not a substitute for evidence.

See [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md), [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md), [`SETUP.md`](SETUP.md), and [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
