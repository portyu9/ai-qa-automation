# Limitations and Non-Claims

This document is intentionally explicit about what the project **does not prove**. The platform's evidence-first design applies to its own documentation: implemented code, configuration, tests, and workflows are not represented as successful execution unless matching evidence exists.

## Current project boundary

AI QA Automation is a production-shaped engineering portfolio/reference implementation. The current repository head is **not production-release verified** until the applicable deterministic, security, browser, model, integration, and environment gates are actually executed and inspected.

Historical successful checks are useful prior evidence, not a release certificate for later commits.

## Claude / model limitations

- Live Claude Agent SDK orchestration is implemented, but real provider behavior requires a valid `ANTHROPIC_API_KEY` and an intentionally executed session.
- No prompt, model version, or evaluation corpus can guarantee that a probabilistic model will never make a reasoning mistake.
- The architecture therefore limits what a model mistake can authorize and requires deterministic evidence for verified outcomes.
- Model confidence is not observed system truth.
- The project does not claim that all possible prompts, repositories, applications, or adversarial inputs have been evaluated.
- Model upgrades can alter behavior; version/provenance should be recorded and applicable evaluations rerun before promoting a new model state.

## External MCP limitations

- GitHub and Atlassian integrations are configured only through approved vendor-official paths and remain disabled by default.
- Configuration does not prove authentication, authorization, provider availability, or tool behavior in a specific account.
- Authenticated GitHub/Atlassian MCP behavior is environment-required until exercised.
- The repository intentionally does not inherit arbitrary target/user/community MCP configuration into the live runtime.
- A vendor-official server can evolve its tool surface; server identity is not blanket permission for every current or future tool.
- Remote GitHub/Jira/Confluence content remains untrusted evidence and can still contain malicious prompt-injection-shaped text.

### TestRail and other systems

TestRail is currently `NOT_CONFIGURED` as an external integration in this repository. The project does not install a community MCP server merely to claim TestRail support. A future integration should use an organization-approved first-party/vendor-official MCP if one satisfies the trust requirements, or a narrow adapter to an approved official API with equivalent authorization/evidence controls.

The same rule applies to other services without an approved integration path.

## Browser limitations

- Browser policy and Playwright-backed reference behavior exist, but a reference SUT is not proof that an arbitrary external application works.
- A locally installed `playwright` package is not evidence that the required browser executable is installed; the runtime reports these separately.
- Browser host/subrequest/WebSocket controls are application-layer safeguards, not a complete OS/container network sandbox.
- DOM/accessibility evidence can be incomplete, dynamic, or misleading; the model must not infer locator uniqueness that Playwright did not observe.
- Visual correctness across all browsers, devices, responsive breakpoints, assistive technologies, and production data is outside the default reference suite.

## API limitations

- The built-in API adapter provides bounded request/evidence/schema behavior; it is not a complete API testing product for every protocol/authentication scheme.
- External target authentication, authorization, data safety, and environment availability require target-specific configuration/evidence.
- Read-only methods are the safe default. Enabling mutating methods does not itself establish that a particular endpoint is safe to modify.
- JSON Schema/OpenAPI evidence is useful but does not replace business-semantic validation.

## OpenAPI contract-drift limitations

The contract analyzer is deliberately conservative and bounded. It detects supported structural compatibility changes such as removed paths/operations, newly required inputs, successful-response removal, schema/type changes, required-property additions, removals, and enum narrowing.

`NON_BREAKING` means no breaking/risky condition was identified under the implemented structural rules. It is **not** a formal proof that every downstream consumer remains compatible.

`NOT_ANALYZED` remains visible uncertainty and must not be interpreted as compatibility.

## CODEOWNERS limitations

The runtime supports a bounded subset of CODEOWNERS grammar and explicit precedence/last-match behavior needed for deterministic routing. Unsupported patterns are reported rather than guessed.

CODEOWNERS information is review context, not runtime authorization. Repository CODEOWNERS enforcement also depends on GitHub branch-protection/repository settings outside this codebase.

## Test-impact and regression-prioritization limitations

- Test-impact mapping is advisory and explainable, not a complete program dependency proof.
- Static path/component/reference signals can miss runtime/dynamic dependencies.
- Truncated scans, low confidence, incomplete dependency information, or unsupported ecosystems must broaden regression rather than justify aggressive omission.
- Mandatory security/safety/regulatory/smoke coverage is protected independently of impact score.
- The project does not claim optimal runtime reduction for every repository.

## Test-generation limitations

- The platform can detect and plan around bounded observed repository coverage; it cannot know undocumented product intent automatically.
- Generated tests require an authoritative expected behavior. Unknown requirements should remain blocked/uncertain rather than be invented.
- Meaningful-assertion checks prevent common weak tests but cannot mathematically prove that every assertion captures the most valuable business risk.
- The repository prioritizes supported Python/JavaScript/TypeScript test-generation paths rather than claiming universal language/framework generation.

## Self-healing limitations

- Autonomous healing is intentionally narrow and primarily locator-oriented.
- There is no generic existing-test rewrite capability in the live agent runtime.
- A unique locator can still be semantically wrong, which is why observed uniqueness is necessary but not sufficient; semantic evidence and intent preservation remain required.
- The platform refuses ambiguous repair rather than maximizing heal rate.
- A product behavior change that invalidates the old test intent should not be disguised as an automation heal.

## pytest / test-execution limitations

- pytest support is concrete but cannot make arbitrary third-party suites deterministic.
- Flaky dependencies, external services, clocks, data, or test isolation can still produce unstable results.
- Same-revision contradictory PASS/FAIL evidence is deliberately exposed as `NOT_VERIFIED`; the platform does not claim to automatically solve every source of flakiness.
- Target-specific setup such as databases, containers, service emulators, certificates, or credentials remains the target project's responsibility unless explicitly integrated.

## Performance / k6 limitations

- k6 execution is restricted to bounded, explicitly non-production use.
- A non-local run requires a trusted assertion that infrastructure-level egress controls exist; the repository itself does not create or certify that firewall/network boundary.
- Static script checks reduce known escape paths but do not constitute a general JavaScript security sandbox.
- Real load capacity, scaling limits, cloud quotas, production-like data shape, and distributed load-generator behavior require environment-specific testing.
- Thresholds must be defined before observing results; the repository cannot determine business SLOs automatically.

## Mobile / Appium limitations

The current mobile capability is primarily runtime/capability inspection. It does **not** constitute a complete verified Appium end-to-end mobile automation implementation against a real application/device fleet.

Real mobile validation requires, as applicable:

- Appium server/drivers;
- application build;
- emulator/simulator/device/device-cloud access;
- platform certificates/provisioning;
- target-specific capabilities and test flows.

Those remain `ENVIRONMENT_REQUIRED` until actually exercised.

## Security limitations

- Deterministic policy, protected paths, network restrictions, secret redaction, transactional mutation, and adversarial tests reduce risk; they do not prove the system has no unknown vulnerabilities.
- Application-level host/path/tool restrictions are not substitutes for deployment-level process/container isolation, non-root enforcement, firewall/proxy policy, identity, secret management, or data-loss-prevention controls.
- Static analyzers and dependency scanners can have false positives/false negatives and require actual execution to produce current-head evidence.
- Raw binary artifacts such as screenshots are hashed but not magically sanitized. They may contain sensitive UI/data and require appropriate storage/access/retention controls.
- Redaction is defense in depth, not permission to feed secrets/private production data into an unapproved environment.

## Evidence-integrity limitations

- SHA-256 artifact hashes and hash-chained journals make persisted content modification/order changes detectable under the implemented verification model.
- They are not a cryptographic identity signature, trusted timestamp, notarization, or proof of who created the data.
- The unsigned attestation is content-addressed integrity metadata only.
- Integrity of a failed/incorrect run does not turn it into PASS.
- An organization requiring non-repudiation or external trust anchors must add an approved signing/timestamping system outside this repository.

## Regulated-mode limitations

`AI_QA_REGULATED_MODE=true` enables additional engineering traceability/retention labeling behavior. It does **not** certify compliance with HIPAA, PCI DSS, SOC 2, ISO 27001, FDA, SOX, GDPR, or any other regulatory/assurance regime.

Compliance requires organization-specific policies, controls, legal interpretation, infrastructure, access management, retention/deletion rules, evidence, and audits.

## Observability limitations

- Structured events, metrics models, correlation IDs/run IDs, artifacts, and OpenTelemetry-compatible code paths exist.
- A real telemetry backend/export pipeline is environment-dependent.
- Token/cost values are recorded only when the live model/provider supplies them; missing live usage is not estimated and presented as observed fact.
- Logs/metrics do not replace underlying evidence artifacts or validation gates.

## Recovery limitations

- The runtime persists canonical state/evidence independently from the model conversation and can inspect safe recovery conditions.
- It does **not** replay or reconstruct hidden Claude conversational state after a crash/context loss.
- Recovery begins a new model session from persisted evidence when safe.
- Automatic stale mutation rollback intentionally stops when newer human/out-of-band workspace changes make ownership ambiguous.

## Docker/container limitations

The included Dockerfile provides a non-root CLI/control-plane image shape and trusted project markers. Its presence does not prove:

- the image currently builds on every platform;
- CVE-free base/dependencies;
- production container hardening;
- read-only root filesystem;
- seccomp/AppArmor/SELinux policy;
- Kubernetes security context;
- network policy;
- secret injection;
- persistent artifact storage;
- enterprise image signing/provenance.

Those require actual build/scanning/deployment evidence.

## CI/CD limitations

- `.github/workflows/ci.yml` is intentionally manual-only during the current bootstrap stage.
- A workflow file in Git is not a passing workflow run.
- Current-head quality, tests, primary evaluation, holdout, security, browser, and model gates remain `NOT_VERIFIED` until intentionally executed.
- The live-model gate requires a repository secret only when opted in.
- The current workflow does not verify authenticated GitHub/Atlassian MCP sessions.
- Production credentials must not be exposed to untrusted pull-request execution.

## Reference-SUT limitations

The reference application is deliberately small. It exists to make selected failure/evidence paths reproducible and understandable. It is not a benchmark claiming coverage of all web architectures, microservices, data stores, UI frameworks, authentication systems, distributed failures, or production traffic patterns.

A control proven against the reference SUT still needs target-specific validation before being claimed for a real application.

## Context / retrieval limitations

The architecture prefers targeted retrieval and bounded summaries over sending entire repositories/logs/traces to the model. It does not include a vector database/RAG platform by default because that additional trust/operations layer is not justified until normal targeted retrieval demonstrates a real insufficiency.

That is a deliberate scope decision, not a claim that vector retrieval is never useful.

## Configuration limitations

- `.env.example` is documentation only; runtime settings deliberately do not auto-load repository `.env` files.
- Secret/configuration presence is not validity.
- `AI_QA_BASE_REF` must be explicit when merge-base analysis is required; the runtime does not invent a favorable baseline.
- Raising a budget or enabling a write/network capability is a configuration decision, not evidence that the resulting action is safe for every objective.

## What remains before a production claim

At minimum, a real production deployment must provide current evidence for all applicable gates in [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md), including environment-specific model/integration/browser/device/load/infrastructure requirements.

Anything excluded from that deployment should remain visibly `NOT_VERIFIED`, `NOT_CONFIGURED`, or `ENVIRONMENT_REQUIRED` rather than being implied by adjacent green checks.

See [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md), [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md), [`SETUP.md`](SETUP.md), and [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).
