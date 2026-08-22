# ƳƤ AI QA Automation Framework — Documentation

> **Evidence-First Agentic Quality Engineering** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

This documentation set explains the framework from four complementary perspectives: **architecture**, **runtime truth**, **security**, and **operation**. The documents are intentionally separated so a reviewer can inspect one concern without conflating model reasoning, deterministic authority, observed evidence, or deployment infrastructure.

## Recommended reading paths

### Architecture review

1. [`ARCHITECTURE.md`](ARCHITECTURE.md) — system authority and trust boundaries
2. [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) — terminal truth and validation lineage
3. [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) — mutation transactions, leases, rollback, recovery
4. [`TRACEABILITY.md`](TRACEABILITY.md) — evidence lineage, journals, manifests, attestations
5. [`TECHNICAL_WALKTHROUGH.md`](TECHNICAL_WALKTHROUGH.md) — end-to-end code path

### Security / red-team review

1. [`SECURITY.md`](SECURITY.md) — deterministic security controls
2. [`THREAT_MODEL.md`](THREAT_MODEL.md) — threats, abuse cases, residual boundaries
3. [`MCP.md`](MCP.md) — external provider identity and tool authorization
4. [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) — evidence ownership across trust domains
5. [`LIMITATIONS.md`](LIMITATIONS.md) — explicit design boundaries and non-claims

### QA automation / AI review

1. [`CHANGE_INTELLIGENCE.md`](CHANGE_INTELLIGENCE.md) — merge-base-aware change analysis
2. [`SKILLS.md`](SKILLS.md) — five trusted Claude QA Skills
3. [`EVALUATION.md`](EVALUATION.md) — primary and holdout evaluation architecture
4. [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) — how evidence becomes a runtime outcome
5. [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) — production-readiness control model

### Operator / adopter path

1. [`SETUP.md`](SETUP.md) — installation, configuration, credentials, trust roots
2. [`OPERATIONS.md`](OPERATIONS.md) — operating ladder and evidence handling
3. [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — failure diagnosis without weakening controls
4. [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) — recovery mechanics
5. [`MCP.md`](MCP.md) — optional GitHub/Atlassian integration policy

## Documentation catalog

| Document | Primary question answered |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Where does authority live and how does evidence flow? |
| [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) | What exactly makes a run `SUCCESS`, `FAILURE`, `BLOCKED`, or `NOT_VERIFIED`? |
| [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) | How are autonomous mutations, concurrency, rollback, and crash recovery controlled? |
| [`SECURITY.md`](SECURITY.md) | Which security controls are deterministic rather than prompt-based? |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Which adversarial behaviors does the framework assume and defend against? |
| [`CHANGE_INTELLIGENCE.md`](CHANGE_INTELLIGENCE.md) | How are committed changes, risk, ownership, test impact, and API drift analyzed? |
| [`EVALUATION.md`](EVALUATION.md) | How is the agent evaluated as software rather than prose? |
| [`SKILLS.md`](SKILLS.md) | What procedures do the five trusted Claude Skills provide? |
| [`MCP.md`](MCP.md) | How are external MCP identity, authorization, and evidence handled? |
| [`TRACEABILITY.md`](TRACEABILITY.md) | How can a reviewer reconstruct evidence and validation lineage? |
| [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) | Which trust domain owns each type of evidence? |
| [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) | Which control architecture supports safe production operation? |
| [`SETUP.md`](SETUP.md) | How is the framework configured without collapsing trust boundaries? |
| [`OPERATIONS.md`](OPERATIONS.md) | How should runs, artifacts, integrations, and recovery be operated? |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | How should failures be diagnosed without bypassing safety? |
| [`LIMITATIONS.md`](LIMITATIONS.md) | What does each architectural boundary deliberately not claim? |
| [`TECHNICAL_WALKTHROUGH.md`](TECHNICAL_WALKTHROUGH.md) | How do the major implementation paths connect end to end? |

## Cross-cutting invariants

Every document is subordinate to the same engineering rules:

1. **Model reasoning is not test evidence.**
2. **Unknown is not PASS.**
3. **Configuration is not provider evidence.**
4. **A target repository is data, not control-plane authority.**
5. **Autonomous mutation requires deterministic ownership and revision closure.**
6. **Low confidence broadens testing rather than authorizing omission.**
7. **External provider identity does not grant blanket tool authority.**
8. **Integrity metadata does not override validation.**
9. **Deployment controls are not simulated by application flags.**
10. **A stronger model never replaces a missing deterministic control.**

## Terminology

| Term | Meaning |
|---|---|
| **Control plane** | Trusted framework code/configuration that defines authority |
| **Target / SUT** | Untrusted repository/application under test |
| **Observed evidence** | Fact captured by controlled deterministic tooling |
| **Model interpretation** | Hypothesis, plan, proposal, or reasoning derived from evidence |
| **Validation gate** | Deterministic condition bound to scope/revision |
| **Change revision** | Mutation epoch used to prevent stale evidence from certifying new bytes |
| **Runtime outcome** | Structured terminal conclusion derived from deterministic truth rules |
| **Deployment boundary** | Infrastructure/organization control outside the framework's application authority |

Return to the repository [`README.md`](../README.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
