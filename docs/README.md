<div align="center">

# ƳƤ AI QA Automation Framework — Documentation

### Architecture · Runtime Truth · Security · Operations

**Evidence-First Agentic Quality Engineering**  
Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Repository](../README.md) · [Architecture](ARCHITECTURE.md) · [Result Contract](RESULT_CONTRACT.md) · [Security](SECURITY.md) · [CI/CD](CI_CD.md) · [Setup](SETUP.md)

</div>

---

> [!IMPORTANT]
> This documentation set keeps four concerns deliberately separate: **model reasoning**, **deterministic authority**, **observed evidence**, and **deployment infrastructure**. A statement from one trust domain never silently becomes proof in another.

## Choose a review path

| Reviewer goal | Recommended path |
|---|---|
| **Architecture / principal engineering** | [Architecture](ARCHITECTURE.md) → [Result Contract](RESULT_CONTRACT.md) → [Runtime Control](RUNTIME_CONTROL.md) → [Workspace Freshness Boundary](WORKSPACE_FRESHNESS_BOUNDARY.md) → [Traceability](TRACEABILITY.md) → [Technical Walkthrough](TECHNICAL_WALKTHROUGH.md) |
| **Security / red team** | [Security](SECURITY.md) → [Threat Model](THREAT_MODEL.md) → [Tool Input Boundaries](TOOL_INPUT_BOUNDARIES.md) → [Objective Input Boundary](OBJECTIVE_INPUT_BOUNDARY.md) → [Agent SDK Result Boundary](SDK_RESULT_BOUNDARY.md) → [Persistence Resource Boundary](PERSISTENCE_RESOURCE_BOUNDARY.md) → [API Observation Boundary](API_OBSERVATION_BOUNDARY.md) → [Browser Validation](BROWSER_VALIDATION.md) → [Supply Chain](SUPPLY_CHAIN.md) → [CI/CD](CI_CD.md) → [Trusted PR Control Plane](TRUSTED_PR_CONTROL_PLANE.md) → [MCP](MCP.md) → [Verification Boundaries](VERIFICATION_BOUNDARIES.md) → [Workspace Freshness Boundary](WORKSPACE_FRESHNESS_BOUNDARY.md) → [Pytest Execution Isolation](PYTEST_EXECUTION_ISOLATION.md) → [Limitations](LIMITATIONS.md) |
| **QA automation / AI engineering** | [Change Intelligence](CHANGE_INTELLIGENCE.md) → [Contract Drift Boundary](CONTRACT_DRIFT_BOUNDARY.md) → [Skills](SKILLS.md) → [Evaluation](EVALUATION.md) → [Result Contract](RESULT_CONTRACT.md) → [Browser Validation](BROWSER_VALIDATION.md) → [Production Readiness](PRODUCTION_READINESS.md) |
| **Operator / adopter** | [Setup](SETUP.md) → [Browser Validation](BROWSER_VALIDATION.md) → [Pytest Execution Isolation](PYTEST_EXECUTION_ISOLATION.md) → [Operations](OPERATIONS.md) → [CI/CD](CI_CD.md) → [Troubleshooting](TROUBLESHOOTING.md) → [Runtime Control](RUNTIME_CONTROL.md) → [MCP](MCP.md) |

### Architecture / principal engineering

1. [`ARCHITECTURE.md`](ARCHITECTURE.md) — authority, trust zones, execution flow
2. [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) — terminal truth and revision-aware validation
3. [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) — leases, mutation transactions, rollback, recovery
4. [`WORKSPACE_FRESHNESS_BOUNDARY.md`](WORKSPACE_FRESHNESS_BOUNDARY.md) — target fingerprint lineage, execution admission, result acceptance, terminal freshness
5. [`TRACEABILITY.md`](TRACEABILITY.md) — evidence lineage, journal integrity, attestation
6. [`TECHNICAL_WALKTHROUGH.md`](TECHNICAL_WALKTHROUGH.md) — end-to-end implementation review

### Security / red team

1. [`SECURITY.md`](SECURITY.md) — deterministic controls and security posture
2. [`THREAT_MODEL.md`](THREAT_MODEL.md) — threats, abuse cases, residual boundaries
3. [`TOOL_INPUT_BOUNDARIES.md`](TOOL_INPUT_BOUNDARIES.md) — fail-closed live request ingestion, raw JSON preflight, and resource ceilings
4. [`OBJECTIVE_INPUT_BOUNDARY.md`](OBJECTIVE_INPUT_BOUNDARY.md) — bounded pre-state/pre-provider objective admission and exact-text preservation
5. [`SDK_RESULT_BOUNDARY.md`](SDK_RESULT_BOUNDARY.md) — bounded provider terminal-result ingestion, error semantics, and cost authority
6. [`PERSISTENCE_RESOURCE_BOUNDARY.md`](PERSISTENCE_RESOURCE_BOUNDARY.md) — bounded canonical-state/evidence serialization before materialization and durable replacement
7. [`API_OBSERVATION_BOUNDARY.md`](API_OBSERVATION_BOUNDARY.md) — raw-byte HTTP observation, compression/header/body bounds, complete-body JSON promotion, and explicit decoding truth
8. [`BROWSER_VALIDATION.md`](BROWSER_VALIDATION.md) — exact-subject browser gates, evidence semantics, and URL confidentiality boundary
9. [`SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md) — dependency, build, Action, SBOM, reproducibility, protected-root manifest, and trusted-status identity boundaries
10. [`CI_CD.md`](CI_CD.md) — automatic PR evidence, trusted-dispatch exact-subject validation, dedicated App merge identity, and repository-setting authority
11. [`TRUSTED_PR_CONTROL_PLANE.md`](TRUSTED_PR_CONTROL_PLANE.md) — independent trusted-status publisher design, external App/Environment/ruleset activation requirements, and historical control-plane evidence
12. [`MCP.md`](MCP.md) — provider identity, action authorization, untrusted remote content
13. [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) — evidence ownership across trust domains
14. [`WORKSPACE_FRESHNESS_BOUNDARY.md`](WORKSPACE_FRESHNESS_BOUNDARY.md) — local target-subject freshness, mutation ownership, and terminal-success binding
15. [`PYTEST_EXECUTION_ISOLATION.md`](PYTEST_EXECUTION_ISOLATION.md) — fail-closed deployment prerequisites for target-controlled Python
16. [`LIMITATIONS.md`](LIMITATIONS.md) — explicit design boundaries and non-claims

### QA automation / AI engineering

1. [`CHANGE_INTELLIGENCE.md`](CHANGE_INTELLIGENCE.md) — merge-base-aware change analysis
2. [`CONTRACT_DRIFT_BOUNDARY.md`](CONTRACT_DRIFT_BOUNDARY.md) — bounded, unambiguous OpenAPI/Swagger parser and comparison authority
3. [`SKILLS.md`](SKILLS.md) — five trusted Claude QA procedures
4. [`EVALUATION.md`](EVALUATION.md) — deterministic primary and repository-visible sequestered readiness evaluation architecture
5. [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) — how evidence becomes a runtime outcome
6. [`BROWSER_VALIDATION.md`](BROWSER_VALIDATION.md) — how browser evidence is subject-bound without overstating page health
7. [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) — production control model

### Operator / adopter

1. [`SETUP.md`](SETUP.md) — installation, configuration, credentials, trust roots
2. [`BROWSER_VALIDATION.md`](BROWSER_VALIDATION.md) — browser gate identity, URL sanitation, and evidence non-claims
3. [`PYTEST_EXECUTION_ISOLATION.md`](PYTEST_EXECUTION_ISOLATION.md) — deployment containment required before live target-controlled pytest code may execute
4. [`OPERATIONS.md`](OPERATIONS.md) — operating ladder and artifact handling
5. [`CI_CD.md`](CI_CD.md) — automatic PR feedback, protected trusted dispatch, independent status identity, and repository-governance authority
6. [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — diagnose without weakening controls
7. [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) — recovery and mutation mechanics
8. [`MCP.md`](MCP.md) — optional GitHub/Atlassian integration policy

---

## Documentation catalog

| Document | Primary question answered |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Where does authority live, and how does evidence flow? |
| **[`RESULT_CONTRACT.md`](RESULT_CONTRACT.md)** | What exactly makes a run `SUCCESS`, `FAILURE`, `BLOCKED`, or `NOT_VERIFIED`? |
| [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) | How are autonomous mutations, concurrency, rollback, and crash recovery controlled? |
| [`WORKSPACE_FRESHNESS_BOUNDARY.md`](WORKSPACE_FRESHNESS_BOUNDARY.md) | How are controlled local-target execution and terminal `SUCCESS` bound to the authorized current workspace subject? |
| [`SECURITY.md`](SECURITY.md) | Which security controls are deterministic rather than prompt-based? |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Which adversarial behaviors does the framework assume and defend against? |
| [`TOOL_INPUT_BOUNDARIES.md`](TOOL_INPUT_BOUNDARIES.md) | How are live tool requests bounded before fingerprinting, policy, budget mutation, JSON parsing, and controlled execution? |
| [`OBJECTIVE_INPUT_BOUNDARY.md`](OBJECTIVE_INPUT_BOUNDARY.md) | How is the operator objective bounded before state persistence, bootstrap, and provider submission? |
| [`SDK_RESULT_BOUNDARY.md`](SDK_RESULT_BOUNDARY.md) | How are Agent SDK terminal results bounded before retention, accounting, and terminal truth? |
| [`PERSISTENCE_RESOURCE_BOUNDARY.md`](PERSISTENCE_RESOURCE_BOUNDARY.md) | How are canonical state and evidence manifests bounded before complete serialization/materialization and durable replacement? |
| [`API_OBSERVATION_BOUNDARY.md`](API_OBSERVATION_BOUNDARY.md) | How are HTTP response bytes, headers, truncation, decoding, and strict JSON promotion bounded before becoming structured evidence? |
| [`BROWSER_VALIDATION.md`](BROWSER_VALIDATION.md) | How are browser operations bound to exact subjects without confusing evidence collection with page correctness? |
| [`SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md) | How are dependency, build, Action, container-base, SBOM, reproducibility, protected-root, and trusted-status identity inputs bound and evidenced? |
| [`CI_CD.md`](CI_CD.md) | How are automatic PR evidence, owner trusted-dispatch validation, dedicated App status authority, manual validation, and external repository settings separated? |
| [`TRUSTED_PR_CONTROL_PLANE.md`](TRUSTED_PR_CONTROL_PLANE.md) | How is protected PR merge authority separated from candidate GitHub Actions workflows and bound to a main-only dedicated App reporter plus exact live merge-ref validation? |
| [`CHANGE_INTELLIGENCE.md`](CHANGE_INTELLIGENCE.md) | How are committed changes, risk, ownership, test impact, and API drift analyzed? |
| [`CONTRACT_DRIFT_BOUNDARY.md`](CONTRACT_DRIFT_BOUNDARY.md) | How are OpenAPI/Swagger bytes, JSON/YAML semantics, parser resources, and incomplete comparison bounded before compatibility evidence is emitted? |
| [`EVALUATION.md`](EVALUATION.md) | How is the agent evaluated as software rather than prose? |
| [`SKILLS.md`](SKILLS.md) | What procedures do the five trusted Claude Skills provide? |
| [`MCP.md`](MCP.md) | How are external MCP identity, authorization, and evidence handled? |
| [`TRACEABILITY.md`](TRACEABILITY.md) | How can a reviewer reconstruct evidence and validate persisted integrity? |
| [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) | Which trust domain owns each type of evidence? |
| [`PYTEST_EXECUTION_ISOLATION.md`](PYTEST_EXECUTION_ISOLATION.md) | What infrastructure must exist before live target-controlled pytest code may execute? |
| [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) | Which control architecture supports safe production operation? |
| [`SETUP.md`](SETUP.md) | How is the framework configured without collapsing trust boundaries? |
| [`OPERATIONS.md`](OPERATIONS.md) | How should runs, artifacts, integrations, and recovery be operated? |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | How should failures be diagnosed without bypassing safety? |
| [`LIMITATIONS.md`](LIMITATIONS.md) | What does each architectural boundary deliberately not claim? |
| [`TECHNICAL_WALKTHROUGH.md`](TECHNICAL_WALKTHROUGH.md) | How do the major implementation paths connect end to end? |

## Cross-cutting invariants

```text
Model reasoning         ≠ observed evidence
Configuration           ≠ provider availability
Unique locator          ≠ semantic correctness
API observation         ≠ response correctness
Browser operation PASS  ≠ page correctness
Static script checks    ≠ network sandbox
Minimal subprocess env  ≠ process/network sandbox
Content hash            ≠ identity/signature
Hash-locked package     ≠ publisher trust/availability
Reproducible wheel      ≠ signed provenance
Automatic PR green      ≠ protected merge authority
Model success           ≠ deterministic SUCCESS
```

Every document is subordinate to the same rules:

1. **Model reasoning is not test evidence.**
2. **Unknown is not PASS.**
3. **Configuration is not provider evidence.**
4. **A target repository is data, not control-plane authority.**
5. **Autonomous mutation requires owned paths, rollback integrity, and exact-path revision closure.**
6. **Low confidence broadens testing rather than authorizing omission.**
7. **External provider identity does not grant blanket tool authority.**
8. **Integrity metadata does not override validation.**
9. **Deployment controls are not simulated by application flags.**
10. **A stronger model never replaces a missing deterministic control.**
11. **Evidence collection cannot substitute for a deterministic acceptance condition.**
12. **A candidate workflow cannot become merge authority merely by producing a same-named status; protected status identity is independently owned.**

## Terminology

| Term | Meaning |
|---|---|
| **Control plane** | trusted framework code/configuration that defines authority |
| **Target / SUT** | untrusted repository/application under test |
| **Observed evidence** | fact captured by controlled deterministic tooling |
| **Model interpretation** | hypothesis, plan, proposal, or reasoning derived from evidence |
| **Validation gate** | deterministic condition bound to a subject/scope and revision |
| **Change revision** | mutation epoch used to prevent stale evidence from certifying new bytes |
| **Runtime outcome** | structured terminal conclusion derived from deterministic truth rules |
| **Deployment boundary** | infrastructure/organization control outside application-level authority |

> [!TIP]
> For the shortest complete technical review, read [`ARCHITECTURE.md`](ARCHITECTURE.md), [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md), [`SECURITY.md`](SECURITY.md), [`CI_CD.md`](CI_CD.md), and [`TECHNICAL_WALKTHROUGH.md`](TECHNICAL_WALKTHROUGH.md).

---

[← Repository README](../README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
