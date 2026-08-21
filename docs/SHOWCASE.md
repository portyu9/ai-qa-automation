# Portfolio and Technical Interview Walkthrough

This repository is easiest to understand as a **quality-engineering control system around an AI reasoner**, not as a chatbot that happens to run tests.

The strongest demonstration is therefore not “Claude generated a green test.” It is showing how the system prevents a probabilistic model from converting weak evidence into a false PASS.

## Five-minute walkthrough

### 1. State the governing invariant

Start with:

> **Model reasoning is not test evidence. Claude can interpret and propose; deterministic tools, evidence, policy, and validation decide what is verified.**

Point to the architecture diagram in the README and the trust boundaries in [`ARCHITECTURE.md`](ARCHITECTURE.md).

### 2. Show the deterministic, credential-free scenario

```bash
ai-qa demo
```

The reference scenario demonstrates a deliberately important failure mode: a missing UI element plus an HTTP 500 is not automatically classified as a locator defect. The system requires observed evidence before selecting a repair path.

Do not describe this command as a live Claude demonstration. It is intentionally deterministic.

### 3. Show the narrow runtime authority

Open:

- `src/ai_qa_automation/agent.py`
- `src/ai_qa_automation/policy.py`
- `src/ai_qa_automation/runtime/runtime_hooks.py`

Highlight:

- no generic runtime Bash/Edit/Write/Web surface;
- explicit project Skills and QA tools;
- fail-closed tool authorization;
- control-plane/SUT isolation;
- independent turn/tool/network/mutation/time/cost limits;
- external MCP disabled unless explicitly approved and configured.

### 4. Show why self-healing is not “find a selector that passes”

Open [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) and the self-healing sections of the README.

Explain that a mutation is transactional and remains untrusted until the new revision closes patch-safety, targeted pytest, and full-regression validation. A failed or unverified run rolls back; a post-crash human edit blocks automatic rollback rather than being overwritten.

### 5. End with truthfulness and traceability

Open:

- [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md)
- [`TRACEABILITY.md`](TRACEABILITY.md)
- [`EVALUATION.md`](EVALUATION.md)

The differentiator is not merely that the repository has many checks. It is that **unexecuted checks remain `NOT_VERIFIED`**, historical evidence is not silently promoted to current-head evidence, and persisted lineage can connect observations to validations and artifacts.

## Fifteen-minute engineering walkthrough

A deeper walkthrough can follow this order:

1. **Architecture** — probabilistic reasoning separated from deterministic authority.
2. **Trust model** — trusted control root, untrusted SUT, explicitly approved integration plane.
3. **Bootstrap intelligence** — repository fingerprint, merge base, change risk, CODEOWNERS, test-impact candidates, dependency inventory, OpenAPI drift.
4. **Evidence model** — observed facts separated from model interpretations; sanitized/hash-addressed artifacts.
5. **Failure intelligence** — evidence-driven taxonomy instead of default product-defect classification.
6. **Guarded mutation** — locator-only healing and plan-bound test creation; no generic existing-test rewrite path.
7. **Runtime safety** — lease, drift detection, independent budgets, tool circuits, transactional rollback, stale recovery.
8. **Regression safety** — mandatory coverage preservation and uncertainty broadening.
9. **Evaluation** — normal tests, fixed primary adversarial corpus, separate holdout corpus, live-model tests isolated behind credentials.
10. **Traceability** — journal, state, lineage, and unsigned content-addressed attestation.
11. **External systems** — vendor-official MCP only; configuration is not proof of availability.
12. **Readiness truth model** — implemented versus actually verified versus environment-required.

## Three interview questions this project is designed to answer

### “How do you stop an AI agent from making the tests green by weakening them?”

The system does not rely on a prompt asking the model to behave. It constrains the mutation surface, protects governance paths, detects skip/xfail/sleep/timeout/assertion-weakening patterns, validates test quality deterministically, binds repairs to observed evidence and expected hashes, and requires post-change validation at a new revision.

### “How do you know the AI found the real defect?”

It may not. The architecture preserves uncertainty. Failure classification consumes observed evidence and can return `INSUFFICIENT_EVIDENCE`; model interpretation alone cannot prove a defect category. Conflicting validation at the same revision becomes `NOT_VERIFIED` rather than being hidden by a retry.

### “What happens if the agent crashes while editing a test?”

The write is a transaction. The prior bytes are snapshotted outside the SUT, the pending mutation is persisted, and a later process may restore it only if the persisted workspace fingerprint proves that no newer operator/out-of-band edit would be overwritten. Otherwise recovery blocks for manual review.

## What not to claim in a portfolio or interview

Do not claim any of the following without matching execution evidence:

- “production certified” or “production ready” because the code exists;
- current-head tests are green before they are actually run;
- Claude integration is verified without a live credentialed run;
- MCP is available merely because a server is configured;
- a hash digest is a trusted digital signature;
- application-level host checks are equivalent to an infrastructure sandbox/firewall;
- an Appium capability inspector is the same as a real device test;
- a reference-SUT browser test proves behavior against an external production system.

That restraint is part of the engineering story: the platform is designed to distinguish **implemented capability** from **observed evidence**.

## Suggested repository tour

For an interviewer or reviewer who wants to go directly to the strongest material:

| Topic | Start here |
|---|---|
| Overall design | `README.md`, `docs/ARCHITECTURE.md` |
| Live runtime | `src/ai_qa_automation/agent.py` |
| Deterministic authorization | `src/ai_qa_automation/policy.py` |
| Runtime safeguards | `src/ai_qa_automation/runtime/`, `docs/RUNTIME_CONTROL.md` |
| Evidence/state | `src/ai_qa_automation/evidence.py`, `src/ai_qa_automation/models.py` |
| Change intelligence | `docs/CHANGE_INTELLIGENCE.md`, `src/ai_qa_automation/intelligence/` |
| Evaluation strategy | `docs/EVALUATION.md`, `evals/`, `tests/` |
| Security model | `docs/SECURITY.md`, `docs/THREAT_MODEL.md` |
| Operational setup | `docs/SETUP.md`, `docs/OPERATIONS.md` |
| Production truth model | `docs/PRODUCTION_READINESS.md` |
| Traceability | `docs/TRACEABILITY.md` |

## Live demo extension, when credentials are intentionally configured

Only after the environment is ready, the same walkthrough can add one bounded live Claude session. The value of that demonstration is not the prose Claude returns; it is watching the same policy, evidence, state, budget, and deterministic-validation architecture remain authoritative around the model.

See [`SETUP.md`](SETUP.md) before enabling any credentialed integration.
