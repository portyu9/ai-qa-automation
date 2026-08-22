<div align="center">

# ƳƤ AI QA Automation Framework — Documentation

### Architecture · Runtime Truth · Security · Operations

**Evidence-First Agentic Quality Engineering**  
Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Repository](../README.md) · [Architecture](ARCHITECTURE.md) · [Result Contract](RESULT_CONTRACT.md) · [Security](SECURITY.md) · [Setup](SETUP.md)

</div>

---

> [!IMPORTANT]
> This documentation set keeps four concerns deliberately separate: **model reasoning**, **deterministic authority**, **observed evidence**, and **deployment infrastructure**. A statement from one trust domain never silently becomes proof in another.

## Choose a review path

| Reviewer goal | Recommended path |
|---|---|
| **Architecture / principal engineering** | [Architecture](ARCHITECTURE.md) → [Result Contract](RESULT_CONTRACT.md) → [Runtime Control](RUNTIME_CONTROL.md) → [Traceability](TRACEABILITY.md) → [Technical Walkthrough](TECHNICAL_WALKTHROUGH.md) |
| **Security / red team** | [Security](SECURITY.md) → [Threat Model](THREAT_MODEL.md) → [MCP](MCP.md) → [Verification Boundaries](VERIFICATION_BOUNDARIES.md) → [Limitations](LIMITATIONS.md) |
| **QA automation / AI engineering** | [Change Intelligence](CHANGE_INTELLIGENCE.md) → [Skills](SKILLS.md) → [Evaluation](EVALUATION.md) → [Result Contract](RESULT_CONTRACT.md) → [Production Readiness](PRODUCTION_READINESS.md) |
| **Operator / adopter** | [Setup](SETUP.md) → [Operations](OPERATIONS.md) → [Troubleshooting](TROUBLESHOOTING.md) → [Runtime Control](RUNTIME_CONTROL.md) → [MCP](MCP.md) |

### Architecture / principal engineering

1. [`ARCHITECTURE.md`](ARCHITECTURE.md) — authority, trust zones, execution flow
2. [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) — terminal truth and revision-aware validation
3. [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) — leases, mutation transactions, rollback, recovery
4. [`TRACEABILITY.md`](TRACEABILITY.md) — evidence lineage, journal integrity, attestation
5. [`TECHNICAL_WALKTHROUGH.md`](TECHNICAL_WALKTHROUGH.md) — end-to-end implementation review

### Security / red team

1. [`SECURITY.md`](SECURITY.md) — deterministic controls and security posture
2. [`THREAT_MODEL.md`](THREAT_MODEL.md) — threats, abuse cases, residual boundaries
3. [`MCP.md`](MCP.md) — provider identity, action authorization, untrusted remote content
4. [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) — evidence ownership across trust domains
5. [`LIMITATIONS.md`](LIMITATIONS.md) — explicit design boundaries and non-claims

### QA automation / AI engineering

1. [`CHANGE_INTELLIGENCE.md`](CHANGE_INTELLIGENCE.md) — merge-base-aware change analysis
2. [`SKILLS.md`](SKILLS.md) — five trusted Claude QA procedures
3. [`EVALUATION.md`](EVALUATION.md) — deterministic, adversarial, and holdout evaluation architecture
4. [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) — how evidence becomes a runtime outcome
5. [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) — production control model

### Operator / adopter

1. [`SETUP.md`](SETUP.md) — installation, configuration, credentials, trust roots
2. [`OPERATIONS.md`](OPERATIONS.md) — operating ladder and artifact handling
3. [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — diagnose without weakening controls
4. [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) — recovery and mutation mechanics
5. [`MCP.md`](MCP.md) — optional GitHub/Atlassian integration policy

---

## Documentation catalog

| Document | Primary question answered |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Where does authority live, and how does evidence flow? |
| **[`RESULT_CONTRACT.md`](RESULT_CONTRACT.md)** | What exactly makes a run `SUCCESS`, `FAILURE`, `BLOCKED`, or `NOT_VERIFIED`? |
| [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) | How are autonomous mutations, concurrency, rollback, and crash recovery controlled? |
| [`SECURITY.md`](SECURITY.md) | Which security controls are deterministic rather than prompt-based? |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Which adversarial behaviors does the framework assume and defend against? |
| [`CHANGE_INTELLIGENCE.md`](CHANGE_INTELLIGENCE.md) | How are committed changes, risk, ownership, test impact, and API drift analyzed? |
| [`EVALUATION.md`](EVALUATION.md) | How is the agent evaluated as software rather than prose? |
| [`SKILLS.md`](SKILLS.md) | What procedures do the five trusted Claude Skills provide? |
| [`MCP.md`](MCP.md) | How are external MCP identity, authorization, and evidence handled? |
| [`TRACEABILITY.md`](TRACEABILITY.md) | How can a reviewer reconstruct evidence and validate persisted integrity? |
| [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) | Which trust domain owns each type of evidence? |
| [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) | Which control architecture supports safe production operation? |
| [`SETUP.md`](SETUP.md) | How is the framework configured without collapsing trust boundaries? |
| [`OPERATIONS.md`](OPERATIONS.md) | How should runs, artifacts, integrations, and recovery be operated? |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | How should failures be diagnosed without bypassing safety? |
| [`LIMITATIONS.md`](LIMITATIONS.md) | What does each architectural boundary deliberately not claim? |
| [`TECHNICAL_WALKTHROUGH.md`](TECHNICAL_WALKTHROUGH.md) | How do the major implementation paths connect end to end? |

## Cross-cutting invariants

```text
Model reasoning      ≠ observed evidence
Configuration        ≠ provider availability
Unique locator       ≠ semantic correctness
Static script checks ≠ network sandbox
Content hash         ≠ identity/signature
Model success        ≠ deterministic SUCCESS
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
> For the shortest complete technical review, read [`ARCHITECTURE.md`](ARCHITECTURE.md), [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md), [`SECURITY.md`](SECURITY.md), and [`TECHNICAL_WALKTHROUGH.md`](TECHNICAL_WALKTHROUGH.md).

---

[← Repository README](../README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
