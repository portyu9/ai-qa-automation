# Design Boundaries and Non-Claims

> [!IMPORTANT]
> A strong control system should be explicit about the boundary of every claim. These are **architectural boundaries**, not project-progress notes.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md) · [Production readiness](PRODUCTION_READINESS.md) · [Security](SECURITY.md)

---

## Boundary philosophy

The framework deliberately distinguishes:

```text
implemented control
≠ observed runtime behavior
≠ provider behavior
≠ target behavior
≠ deployment assurance
≠ compliance certification
```

The sections below describe what each control **does not claim** beyond its owned evidence boundary.

---

## Model and runtime truth

### Claude / model

- No prompt or model guarantees perfect reasoning.
- Model confidence is not observed system truth.
- Repetition does not convert interpretation into evidence.
- Model/SDK provenance matters because upgrades can alter probabilistic behavior.
- Deterministic policy, ownership, evidence, and validation remain authoritative.

### Runtime result

[`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) is deliberately conservative:

- `SUCCESS` means deterministic closure, not persuasive output;
- `NOT_VERIFIED` preserves unresolved truth rather than pretending failure or success;
- same-revision contradiction is surfaced;
- historical PASS cannot certify newer bytes;
- targeted mutation validation must refer to the exact changed path;
- integrity metadata never overrides validation.

---

## External providers

- GitHub/Atlassian access uses approved vendor-official paths only.
- Provider identity does not grant blanket tool permission.
- Provider content remains untrusted evidence.
- Authentication, authorization, rate limits, availability, and organization permissions belong to the provider/account context.
- Future provider tool-surface changes still pass local deterministic authorization.

---

## Network and browser

### Network configuration

- The trusted allowlist accepts canonical hostnames/IP literals, not wildcard policies or URLs.
- Host allowlisting is an application-layer control, not a firewall.
- DNS, routing, TLS trust, proxies, segmentation, and egress policy remain deployment concerns.
- An allowlisted host is not automatically safe for every action or dataset.

### Browser / Playwright

- Observations are scoped to the configured browser context and target.
- Routed HTTP(S)/WebSocket controls are not an OS/container network sandbox.
- Service-worker blocking improves visibility but does not replace infrastructure egress controls.
- DOM/accessibility state can be dynamic or incomplete.
- Locator uniqueness is not semantic correctness.
- Cross-browser, responsive, accessibility, localization, visual, and device strategy remain target-specific.

---

## API and contracts

### API

- The adapter provides bounded HTTP/evidence/schema mechanics, not business authorization.
- Read-only methods are default; mutating methods require explicit enablement.
- Host/method permission does not establish that a user/test identity is authorized for an endpoint.
- JSON Schema/OpenAPI validation complements—not replaces—business-semantic validation.
- Target auth, tenancy, data setup/isolation, and cleanup remain target responsibilities.

### OpenAPI drift

The analyzer is structural and conservative.

- `NON_BREAKING` means no supported breaking/risky rule fired; it is not proof every client remains compatible.
- `NOT_ANALYZED` is visible uncertainty, not compatibility.
- Consumer-specific semantics may require additional contract/application testing.

### CODEOWNERS

- Supported grammar is intentionally bounded.
- Unsupported syntax is surfaced rather than guessed.
- Ownership is review/routing context, not runtime authorization.

### Repository baseline refs

- Named change-intelligence baselines are resolved only while the supported loose-ref and `packed-refs` authority paths remain metadata-stable; observed concurrent ref mutation fails closed rather than certifying an alternate merge base.
- Current `HEAD` resolution separately brackets the direct `.git/HEAD` bytes/metadata and, for symbolic HEAD, the single direct `refs/...` target plus `packed-refs`; stable detached full-object HEAD and stable unborn direct branches remain supported, while nested symbolic ref authority is rejected.
- A failed current `HEAD` resolution is treated as unborn only when the confined `HEAD` is symbolic and its direct target is provably absent from loose refs and bounded, structurally valid `packed-refs`. Unresolved detached HEAD, malformed existing symbolic targets, and malformed packed-ref authority fail closed instead of becoming a clean unborn snapshot.
- Baseline revision expressions, bare abbreviated object IDs, and symbolic loose baseline refs are intentionally rejected instead of introducing mutable/ambiguous revision semantics or an unbound second ref hop. Bare full object IDs must resolve to exactly the supplied object ID; hexadecimal ref names remain available through an explicit `refs/...` name.
- Git's reftable ref backend is not yet descriptor-bound by `RepositoryInspector`; repositories exposing `.git/reftable` are therefore rejected rather than treated as verified baseline authority.
- These controls detect ordinary filesystem-visible mutation through identity/size/time metadata and directory changes; they do not claim protection from privileged filesystem snapshot rollback that can restore metadata outside the process authority boundary.

### Repository worktree and Git metadata authority

- Every allowlisted Git text/binary read is bracketed by a bounded descriptor-confined metadata observation of the direct `.git` tree. Ordinary filesystem-visible changes to repository-local refs, config, ignore metadata, packs/objects, indexes, or their parent directories therefore invalidate the read rather than being silently accepted as stable authority.
- Untracked-file enumeration is additionally bracketed by a bounded metadata observation of the worktree namespace. Only the authorized workspace's direct `.git` directory is excluded; nested `.git` directories remain observation subjects, so nested-repository state cannot disappear behind a recursive name ignore.
- A nested repository whose `.git` metadata remains local can be observed as part of that namespace. Nested `.git` gitfiles, filesystem aliases, `commondir`, and object-alternate indirections are rejected because they would expand observation authority outside the bounded workspace tree.
- Worktree and Git-metadata scans are entry/depth bounded. Resource exhaustion, unreadable authority-bearing paths, or incomplete Git-metadata traversal fail closed rather than certifying an incomplete namespace. The worktree namespace token records metadata rather than file-content hashes; ordinary in-place content rewrites are detected through filesystem time/size metadata, not through a claim of privileged-snapshot resistance.

### Repository index storage

- An active Git split index is not treated as repository observation authority. `RepositoryInspector` reads the already confined main-index bytes, validates the index checksum and supported version/framing, and rejects the mandatory lowercase `link` extension before executing any allowlisted `ls-files` command.
- Split-index detection supports Git index versions 2 through 4 and both SHA-1 and SHA-256 index checksums. Malformed headers, entries, path compression, checksums, or extension framing cannot become affirmative clean-state evidence.
- Split-index detection deliberately does **not** execute `git rev-parse --shared-index-path`: Git may update active `sharedindex.*` modification metadata while reading split-index state, so using that command as an observation probe would mutate the very metadata being bracketed.
- A stale, unreferenced `sharedindex.*` regular file is not active index authority and does not by itself block inspection when the confined main index has no `link` extension.

---

## Test impact, generation, and classification

### Test impact / regression

- Mapping is advisory, not a complete program-dependency proof.
- Static path/reference signals can miss runtime coupling.
- Low confidence, incomplete dependency information, or truncation broadens regression.
- Mandatory security/safety/regulatory/smoke coverage is protected independently.
- The framework does not claim mathematically optimal test minimization.

### Failure classification

- Deterministic heuristics cover observed signals, not every possible real-world root cause.
- `INSUFFICIENT_EVIDENCE` is expected when observations cannot discriminate safely.
- Locator classification requires semantic relationship, not an arbitrary unique element.
- Domain-specific behavior can require additional target evidence.

### Test generation

- Generated tests require authoritative expected behavior.
- Undocumented product intent is not invented to create a test.
- Meaningful-assertion checks reject common weak patterns but do not prove the assertion captures the best business invariant.
- Deterministic candidate gaps cannot be suppressed solely by unsupported model “already covered” labels.
- Reusable generation/patch components understand Python/JavaScript/TypeScript, but live autonomous commit authority is narrower where controlled proof is pytest-backed.
- Fixtures, factories, service virtualization, and environment setup remain target-specific unless deliberately integrated.

---

## Self-healing and mutation

### Self-healing

- Autonomous healing is intentionally locator-oriented.
- There is no generic existing-test rewrite capability in the live runtime.
- Uniqueness is necessary but not sufficient.
- Conservative semantic matching can reject a legitimate repair for review rather than over-authorize a risky one.
- Policy stability scores are heuristics, not guarantees of permanent product contracts.
- Real product behavior changes must not be disguised as automation repair.

### Live autonomous mutation

- Write enablement does not authorize arbitrary files.
- Live autonomous commit is restricted to approved Python test paths because deterministic closure is pytest-backed.
- A targeted PASS for another file or a `-k`-only run cannot certify the pending path.
- OS-backed lease/fingerprint/path checks reduce concurrency risk but do not replace surrounding process/filesystem isolation.

### Recovery

- Canonical state/evidence persists independently from model conversation history.
- Recovery does not reconstruct hidden model reasoning.
- Automatic stale rollback refuses ambiguous fingerprints/path ownership.
- Symlink aliases and tampered rollback state block automatic restoration.
- If integrity cannot be guaranteed, the correct response is explicit blocking/infrastructure failure—not best-effort overwrite.

---

## Test execution and performance

### pytest / target execution

- Controlled pytest cannot make arbitrary third-party dependencies deterministic.
- External clocks, queues, networks, databases, caches, datasets, and services can still introduce nondeterminism.
- Target containers, certificates, test users, credentials, and cleanup remain environment responsibilities.
- Contradictory same-revision evidence remains visible rather than averaged away.

### k6

- k6 is restricted to explicitly non-production authorized targets.
- Static script/import analysis reduces known escape paths but is **not** a JavaScript sandbox.
- Deployment-level egress containment is required for **every** k6 run, including localhost-declared targets.
- `AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true` asserts the prerequisite; it does not prove a firewall is configured correctly.
- Business SLOs, workload models, data shape, topology, quotas, and distributed load infrastructure remain domain/deployment concerns.

### Mobile / Appium

The framework exposes controlled runtime/capability inspection boundaries. Devices, emulators, simulators, cloud sessions, builds, provisioning, certificates, and platform capabilities belong to the mobile test environment.

---

## Security and secrets

- Deterministic policy, path ownership, host controls, redaction, transactions, and adversarial tests reduce risk; they do not prove absence of unknown vulnerabilities.
- Application-layer controls do not replace process/container isolation, firewall/proxy policy, identity, secret management, or DLP.
- Raw screenshots/binary artifacts may contain sensitive data and require deployment storage/access/retention controls.
- Redaction is defense in depth, not permission to introduce secrets/private production data into an unapproved environment.
- Secret-shaped `.env` paths are protected while `.env.example` remains reference documentation; target-specific secret locations still require governance.

---

## Evidence integrity and attestation

- SHA-256 hashes and hash-chained journals provide internal tamper-evidence properties.
- Symlink-resistant ownership checks distinguish “matching bytes” from “owned persisted object.”
- The unsigned attestation can verify core subject ownership, journal validity, no pending mutation, and registered artifact hashes.
- It is not actor identity, notarization, a trusted timestamp, digital signature, compliance proof, or test PASS.
- A perfectly intact record can faithfully describe a failed or unresolved run.

---

## Regulated mode and observability

### Regulated mode

`AI_QA_REGULATED_MODE=true` adds engineering traceability/retention labeling. It does not certify HIPAA, PCI DSS, SOC 2, ISO 27001, FDA, SOX, GDPR, or another assurance regime.

Compliance depends on organization-specific policy, infrastructure, legal interpretation, controls, and evidence.

### Observability

- Structured events, metrics models, run IDs, artifacts, and OpenTelemetry-compatible paths are observability surfaces.
- Telemetry complements but does not replace source evidence and validation lineage.
- Token/cost values are recorded when supplied by the provider rather than invented as observation.
- Backend/exporter/storage choices belong to deployment.

---

## Container, CI/CD, and reference SUT

### Container / infrastructure

The included Dockerfile defines a non-root control-plane image shape. Deployment decides additional controls such as read-only filesystems, seccomp/AppArmor/SELinux, Kubernetes policy, network policy, secret injection, image signing, quotas, persistent storage, and runtime monitoring.

### CI/CD

The activated protected path uses owner-authorized trusted `repository_dispatch` to run read-only, secret-free, revision-bound quality/evaluation/security/supply-chain/reference-browser validation. `Required PR Gate` is internal aggregate evidence; protected merge authority is `Trusted PR Gate` after live PR/merge-ref revalidation. Ordinary PR/push/merge-group execution is externally denied under the observed policy, while H-series readiness and credentialed model smoke require a separately trusted manual execution mechanism. Repository workflow logic and a green status still do not prove hosted-runner immutability, future platform configuration, credential availability, or release/deployment execution.

See [CI/CD and Repository Governance](CI_CD.md).

### Reference SUT

The FastAPI reference application is intentionally small and deterministic. It makes selected evidence/failure paths reproducible; it is not coverage of every web architecture, auth pattern, data system, distributed failure, or traffic shape.

---

## Context / retrieval / configuration

### Context and retrieval

The architecture prefers targeted retrieval and bounded summaries over sending entire repositories/logs/traces to the model. Additional RAG/vector infrastructure should be introduced when justified by a concrete quality/trust benefit; omitting it by default is a scope/trust choice, not a claim such systems are never useful.

### Configuration

- `.env.example` is documentation only; repository `.env` is not auto-loaded.
- Presence does not imply validity.
- `AI_QA_BASE_REF` is explicit for merge-base analysis.
- Enabling write/network authority is a deliberate policy change, not evidence every subsequent action is safe.
- Configuration fingerprints capture identity of inputs, not correctness of configuration.

---

## The non-claim rule

> **Do not turn a strong implementation into a stronger claim than the evidence supports.**

That discipline is part of the framework's quality model, not an apology for it.

---

## Related documentation

- [CI/CD and repository governance](CI_CD.md)
- [Verification boundaries](VERIFICATION_BOUNDARIES.md)
- [Production readiness](PRODUCTION_READINESS.md)
- [Security architecture](SECURITY.md)
- [Setup](SETUP.md)
- [Troubleshooting](TROUBLESHOOTING.md)

---

[← Verification boundaries](VERIFICATION_BOUNDARIES.md) · [Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
