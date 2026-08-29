# Verification Boundaries

> [!IMPORTANT]
> Verification is meaningful only when the **evidence source** and **trust owner** are explicit. Implementation presence, configuration presence, and neighboring green signals are not substitutes for evidence that belongs to another trust domain.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Production readiness](PRODUCTION_READINESS.md) · [Result contract](RESULT_CONTRACT.md) · [Traceability](TRACEABILITY.md)

---

## The evidence ownership model

The framework separates five evidence domains:

```mermaid
flowchart LR
    accTitle: Evidence ownership domains and independent deployment constraints
    accDescr: Repository-contained controls can produce local runtime observations. Local runtime observations can support credentialed provider and target-environment evidence. Deployment infrastructure independently constrains local execution and target interaction; one evidence domain cannot substitute for another.

    R[Repository-contained controls] -->|execute| L[Local runtime observations]
    L -->|authorized interaction| P[Credentialed provider evidence]
    L -->|target observation| T[Target-environment evidence]
    D[Deployment infrastructure evidence] -. independently constrains .-> L
    D -. independently constrains .-> T

    classDef repository fill:#ddf4ff,stroke:#0969da,color:#24292f,stroke-width:2px
    classDef runtime fill:#dafbe1,stroke:#1a7f37,color:#24292f,stroke-width:2px
    classDef external fill:#fff8c5,stroke:#9a6700,color:#24292f,stroke-width:2px
    classDef deployment fill:#fbefff,stroke:#8250df,color:#24292f,stroke-width:2px,stroke-dasharray:5 3

    class R repository
    class L runtime
    class P,T external
    class D deployment
    linkStyle default stroke:#57606a,stroke-width:1.5px
```

**Evidence key:** blue = repository-owned contract · green = observed local execution · amber = provider/target-owned observation · purple dashed = independent deployment enforcement. Ownership labels remain explicit so color is supplementary.

| Evidence class | Primary owner | Examples |
|---|---|---|
| **Repository-contained** | deterministic framework code/config/tests/evaluators | policy, result logic, state/evidence contracts, change intelligence |
| **Local runtime** | executable/runtime environment | Python, Chromium, Docker, k6, Appium/runtime visibility, filesystem identity observations |
| **Credentialed provider** | authorized provider session | Claude, GitHub MCP, Atlassian MCP interactions |
| **Target environment** | selected SUT/test environment | browser/API behavior, load metrics, app/device behavior |
| **Deployment infrastructure** | organization/platform | process/container isolation, egress, identity, secrets, trusted artifact storage, retention |

A capability may span several classes. The framework keeps those contributions separate rather than declaring the whole capability “verified” from one layer alone.

---

## Repository-contained controls

The codebase defines deterministic contracts for areas including:

- typed state, evidence, validation, provider, policy, and terminal outcomes;
- terminal truth with gate identity + revision supersession;
- exact-path binding between mutation, patch-safety, and targeted pytest evidence;
- failure classification and insufficient-evidence handling;
- deterministic locator parsing/semantic scoring;
- same-DOM Playwright locator verification;
- guarded self-healing authorization;
- coverage search, conservative generation planning, and test-quality review;
- regression prioritization with uncertainty broadening;
- canonical hostname/IP validation;
- path/tool/MCP/API/performance authorization;
- recursive redaction and credential-minimal subprocess environments;
- evidence/artifact confinement and immutability;
- strict authority-JSON parsing and typed persisted-record validation;
- hash-chained journals and regulated audit records;
- workspace lease, target-root identity, fingerprint, transaction, rollback, and stale recovery logic;
- symlink-resistant/descriptor-relative ownership for mutation, rollback, evidence, journal, lease, recovery, and attestation subjects where supported;
- exact runtime journal head/count binding for recovery and attestation;
- merge-base change intelligence, CODEOWNERS, test impact, and OpenAPI drift;
- unsigned run-attestation logic with artifact-byte and workspace-root verification;
- run-bound typed lineage graph construction;
- fixed primary and repository-visible sequestered H-series readiness evaluators;
- deterministic reference-SUT behavior.

These are **framework contracts**. Their existence does not by itself prove a particular runtime/provider/target execution occurred.

---

## Local runtime evidence

Some execution surfaces require locally observable components even when no remote account is involved:

- Python/package environment;
- Playwright browser executable;
- Docker for the configured GitHub MCP container path;
- k6 executable;
- Appium/device tooling;
- Git repository/worktree support;
- operating-system filesystem primitives needed for descriptor-relative root identity and inode locking.

`ai-qa doctor` reports what the current environment can actually observe. Package/executable presence does not become provider authentication evidence.

Where descriptor-relative/no-follow filesystem authority is unavailable, repository code must not silently relabel path equality as equivalent root-identity proof. Environment-dependent identity guarantees remain explicit.

---

## Credentialed provider evidence

Credentialed evidence belongs to an authorized interaction:

- Claude Agent SDK behavior with model credentials;
- GitHub MCP behavior with an authorized GitHub identity/token and provider call;
- Atlassian Rovo MCP behavior with an authorized site/session and provider call.

The framework records provider `AVAILABLE` only after an observed successful interaction. Local configuration does not manufacture availability, and a provider outcome does not become the QA terminal outcome.

---

## Target-environment evidence

Target-specific evidence includes:

- Playwright behavior against the selected application;
- API authentication/data/business behavior;
- k6 metrics against the approved workload;
- Appium behavior against a selected app/device environment;
- database/cache/queue/external-dependency behavior;
- application authorization and data-classification rules.

Reference fixtures prove framework mechanics for the fixture behavior they exercise. They do not define arbitrary external systems.

---

## Deployment-infrastructure evidence

Repository code can demand prerequisites and refuse unsafe operations, but it does not pretend to own infrastructure outside its process boundary.

Deployment evidence includes:

- process/container/VM isolation;
- non-root/security context;
- firewall/proxy/egress enforcement;
- identity and secret lifecycle;
- provider-side authentication/authorization;
- trusted artifact-root ownership/protection from arbitrary same-account writers;
- artifact encryption/access/retention;
- trusted runner/CI infrastructure;
- device/cloud security posture;
- legal/compliance controls;
- incident-response and availability controls.

> [!CAUTION]
> `AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true` is a prerequisite assertion, not a firewall. The deployment must actually provide egress containment for every k6 execution. K6 process spawn additionally requires trusted **process/filesystem isolation** and **executable module-loading isolation**. Static JavaScript inspection is not treated as a process, filesystem, network, or module-loader sandbox. The current live MCP configuration exposes only the egress assertion, so live k6 remains intentionally fail-closed until both additional containment prerequisites are plumbed through trusted runtime configuration.

Every k6 validation outcome is bound to the same normalized six-field subject: script, target URL, environment, maximum p95, maximum error rate, and minimum request rate. Thresholds are validated before any target or k6 process action. The exact normalized subject participates in gate hashing; durable blocked-gate details retain only the framework-redacted target URL and numeric thresholds. Raw script/environment strings, URL credentials, query strings, non-root URL paths, and separate per-field correlation hashes are not persisted in those details. Durable live blocked details explicitly record `process_isolation_enforced=false` and `module_isolation_enforced=false` because neither authority is currently exposed by the live path.

Before collecting executable module bytes, `K6Runner` records the workspace root identity. Each root/local-import module is then opened through descriptor-relative no-follow confinement and revalidated against that expected root identity while the bounded read is in progress. A symlinked parent/final component, whole-root replacement, identity change during ingestion, unsupported descriptor-relative authority, or out-of-root lexical path fails closed before snapshot materialization.

Static module inspection is defense-in-depth rather than module-loader authority. The controlled runner rejects CommonJS `require`, dynamic `import()`, remote static imports, unapproved extension/builtin imports, and disables automatic k6 extension resolution with `K6_AUTO_EXTENSION_RESOLUTION=false`. The separate deployment module-loading-isolation prerequisite still must prove that executable runtime code cannot escape the validated snapshot plus approved built-ins; the process/filesystem-isolation prerequisite independently constrains the spawned workload. Neither prerequisite is inferred from static source checks.

---

## Capability/evidence matrix

| Capability | Framework-owned contract | Environment/provider-owned evidence |
|---|---|---|
| Claude reasoning loop | Agent SDK orchestration, policy, result semantics | credentialed provider interaction |
| Terminal truth | gate/revision/path lineage and deterministic derivation | actual validation observations for the run |
| Autonomous mutation | Python-path authority, target-root identity, lease/fingerprint, descriptor-pinned transaction/rollback, exact-path pytest closure | filesystem/process isolation around runtime |
| Stale recovery | prior-run journal binding, persisted workspace-root identity, exact fingerprint, target/backup confinement | current filesystem identity primitives + trusted artifact storage |
| GitHub MCP | official config, action policy, failure normalization | auth, permissions, provider responses |
| Atlassian MCP | official endpoint config, action policy, failure normalization | auth/session, site permissions, provider responses |
| Network policy | canonical host validation + adapter authorization | DNS/routing/firewall/proxy enforcement |
| Playwright | navigation/subresource/WebSocket policy + locator evidence contract | browser runtime + target app behavior |
| API | host/method policy + bounded evidence capture | target auth/data/service behavior |
| k6 | non-production/host/script/threshold policy + root-identity-bound descriptor-confined module ingestion + bounded validated snapshot + static loader denials + egress/process/module-isolation prerequisites | executable, approved target, actual infrastructure egress + process/filesystem isolation + executable module-loading isolation |
| Appium | runtime/capability inspection boundary | app/device/emulator/cloud session |
| Secret safety | protected paths, redaction, minimal subprocess env | organization secret manager, rotation, access policy |
| Traceability | strict run-bound manifests, hashes, journal/runtime binding, typed lineage, artifact/root-verifying unsigned attestation | external signing/identity/timestamping when required |
| Evaluation | fixed primary definitions plus repository-visible sequestered H-series readiness definitions and hard-safety scoring | execution results for a specific revision/environment |

---

## Artifact and attestation boundary

Text evidence is sanitized/redacted on supported model-facing/text persistence paths. Binary screenshots and similar artifacts remain explicitly `RAW` and require deployment-level storage/access/retention controls.

Hashing and hash chaining establish internal integrity properties. The unsigned attestation can additionally verify owned persisted subjects, exact journal/runtime linkage, pending-mutation state, typed/run-bound manifest structure, registered artifact bytes, and current workspace-root identity where the platform exposes the required filesystem authority.

Those properties still do **not** create:

- a trusted external signer;
- an external timestamp authority;
- actor identity attribution;
- test correctness;
- provider authentication;
- deployment isolation assurance;
- compliance certification.

---

## Claim discipline

Use the narrowest statement that matches the evidence owner.

| Claim | Required evidence owner |
|---|---|
| “The control exists.” | repository source/configuration |
| “The deterministic behavior occurred.” | execution/evaluation for the exercised path |
| “The provider was available.” | authorized provider interaction |
| “The target behaved this way.” | target-specific observation |
| “The deployment enforces this boundary.” | infrastructure/organization evidence |
| “These persisted subjects are internally consistent.” | owned subject + strict schema + hash/journal/artifact/root verification applicable to that platform |
| “This run succeeded.” | current deterministic validation closure under [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) |

> [!TIP]
> Strong architecture should make it easier to say **exactly what is known**, not easier to overclaim.

---

## Reviewer checklist

When reviewing a claim, ask:

1. **What object is being claimed about?**
2. **Which trust domain owns the evidence?**
3. **Was the evidence observed for this revision/environment/provider?**
4. **Can a neighboring green signal be mistaken for this evidence?**
5. **Does integrity prove only bytes/subject binding, or is someone accidentally treating it as correctness/identity?**
6. **Does configuration state merely permit an action, or prove it occurred?**
7. **If deployment enforcement is required, is it actually external to the application flag?**
8. **If a filesystem pathname was reused, was subject identity verified rather than inferred from path equality?**

---

## Related documentation

- [Production readiness](PRODUCTION_READINESS.md)
- [Runtime result contract](RESULT_CONTRACT.md)
- [Traceability](TRACEABILITY.md)
- [Security architecture](SECURITY.md)
- [Setup](SETUP.md)
- [Operations](OPERATIONS.md)

---

[← Production readiness](PRODUCTION_READINESS.md) · [Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
