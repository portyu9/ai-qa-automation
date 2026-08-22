# Technical Walkthrough

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

This walkthrough follows the ƳƤ AI QA Automation Framework from **authorized objective → observed evidence → bounded reasoning/action → deterministic validation → persisted result**. It is written for a technical reviewer who wants to understand where authority lives, not only what features exist.

## 1. Start with the result contract

The most important rule is implemented in `src/ai_qa_automation/agent.py`: a successful model result does not produce verified success by itself.

Deterministic gates have revision-aware lineage. Same-revision PASS/FAIL conflicts remain `NOT_VERIFIED`; only an approved change that advances the revision can establish a newer gate result without deleting history. A changed test must close its current revision with:

1. patch-safety PASS;
2. targeted pytest PASS; and
3. full-regression pytest PASS.

Related files:

- `src/ai_qa_automation/models.py`
- `src/ai_qa_automation/agent.py`
- `src/ai_qa_automation/reporting.py`

This is the first place to look when evaluating whether the architecture can fabricate a false PASS.

## 2. Follow trust before functionality

Read [`ARCHITECTURE.md`](ARCHITECTURE.md) before tracing individual tools.

The control repository contains trusted runtime policy, Skills, hooks, tool definitions, and thresholds. The target worktree is untrusted data even if it contains its own `CLAUDE.md`, `.claude/`, `.mcp.json`, source comments, or tests that appear to contain instructions.

`validate_runtime_roots()` rejects overlapping control/artifact/target roots for live execution.

## 3. Follow deterministic bootstrap into evidence

Before Claude sees the objective, `runtime/bootstrap.py` records a bounded target snapshot:

- Git SHA and worktree fingerprint;
- optional trusted base-ref and merge-base change set;
- change-risk domains;
- repository/test topology;
- dependency-manifest inventory;
- CODEOWNERS;
- test-impact candidates;
- OpenAPI/Swagger compatibility drift.

These facts are persisted as evidence first; only a bounded serialized summary is then labeled as observed context for the model.

This is an important architectural inversion: the model is not asked to be the source of truth about basic repository facts the runtime can measure deterministically.

## 4. Follow evidence into canonical state

`EvidenceStore` sanitizes structured text evidence, hashes artifacts, maintains the run manifest, and optionally emits a hash-chained audit log. It also confines run directories/artifacts beneath the trusted artifact root and rejects duplicate evidence/artifact identifiers rather than silently replacing prior evidence. `StateStore` persists canonical QA decision state independently from conversation history using atomic replacement.

```bash
ai-qa demo
```

The deterministic demo illustrates why a missing UI control plus HTTP 500 should not be repaired as a locator defect. It is intentionally credential-free and should not be described as a live Claude run.

Related files:

- `src/ai_qa_automation/evidence.py`
- `src/ai_qa_automation/state.py`
- `src/ai_qa_automation/models.py`
- `src/ai_qa_automation/demo.py`

## 5. Inspect the controlled tool surface

`runtime/internal_tools.py` defines the 18 narrow Agent SDK QA tools. `policy.py` and `runtime/runtime_hooks.py` enforce authorization and process safeguards before/after tool execution.

Key properties include:

- explicit internal tool inventory;
- unknown tools fail closed;
- general Bash/Edit/Write/Web runtime tools are not exposed;
- independent total-tool, network, mutation, repetition, time, and model-cost limits;
- API mutation control;
- browser host/subrequest/WebSocket allowlisting;
- restricted test writes;
- production-load denial including contradictory production-like target hostnames;
- external MCP read/write/destructive policy with conservative mixed-action parsing.

The design prefers a small capability that can be proven safe over a broad capability that depends on the model remembering instructions.

## 6. Inspect failure classification before healing

The failure classifier distinguishes product, automation, locator/UI-contract, data, timing/flakiness, environment, dependency, authentication, configuration, performance, and insufficient-evidence outcomes.

Model interpretation alone cannot prove a class. That prevents a common agent failure mode: treating “the test failed” as synonymous with “the product is broken.”

Related files live under `src/ai_qa_automation/intelligence/` and the corresponding unit/evaluation scenarios.

## 7. Inspect self-healing as a transaction

`tools/browser_evidence.py`, `tools/locators.py`, `intelligence/self_healing.py`, and `tools/safe_patch.py` separate:

1. browser-observed locator facts;
2. the repair proposal;
3. deterministic patch-quality checks;
4. the actual narrow locator mutation;
5. post-change validation.

Playwright measures original/candidate locators in the same DOM. The proposal is bound to that evidence, current failure classification, target test path, and expected file hash. The live runtime does not expose a generic existing-test rewrite tool.

Mutation ownership is deliberately stricter than path resolution alone: absolute/traversal paths and symlink components are rejected, rollback snapshots are confined and hash-verified, and another mutation cannot begin while the current transaction remains unresolved.

Then read [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md). Its state diagram shows why even an authorized mutation remains pending until the new revision closes. Failed/unverified changes roll back; post-crash human edits are protected from automatic overwrite.

## 8. Inspect coverage-aware test generation

`search_test_coverage` records bounded repository coverage evidence. `plan_tests` must consume that evidence, and `create_test_file` must consume the resulting same-run plan evidence.

The provenance chain is:

```text
observed coverage → interpreted gap/plan → guarded creation → deterministic validation
```

Generated Python/JavaScript/TypeScript tests are checked for meaningful assertions and common unsafe shortcuts. Comments or strings that merely contain assertion-like text do not count as meaningful assertion coverage. Python quality review recognizes direct and fluent assertion APIs without counting unrelated helper assertions as proof that a test function is observable.

## 9. Inspect change intelligence and regression safety

[`CHANGE_INTELLIGENCE.md`](CHANGE_INTELLIGENCE.md) explains the merge-base-aware path.

A clean feature branch should not look unchanged merely because the worktree is clean. With `AI_QA_BASE_REF`, the runtime resolves a trusted ref and merge base, combines committed and dirty/untracked changes, classifies risk, resolves CODEOWNERS, identifies explainable test-impact candidates, and assesses changed API contracts.

Test-impact mapping is advisory. Low confidence or scan truncation broadens regression; it cannot be used as proof that omitted tests are safe.

## 10. Inspect runtime control independently from QA state

`state.json` captures QA decision state. `runtime.json` captures process-control facts such as fingerprint, budgets, circuits, lease identity, and pending mutation. `journal.jsonl` records a hash-chained operational sequence.

This separation is intentional: a process checkpoint should not be mistaken for a test conclusion, and a model conversation should not be the only place where recovery-critical state exists.

Relevant files:

- `src/ai_qa_automation/runtime/budget.py`
- `src/ai_qa_automation/runtime/run_control.py`
- `src/ai_qa_automation/runtime/journal.py`
- `src/ai_qa_automation/runtime/stale_recovery.py`
- `src/ai_qa_automation/runtime/recovery.py`

## 11. Inspect external MCP as untrusted evidence

[`MCP.md`](MCP.md) documents the official GitHub/Atlassian integration boundary.

Important points:

- external MCP is disabled by default;
- provider identity is explicitly allowlisted;
- server approval does not auto-approve every tool;
- mixed action names cannot inherit read authority merely from their first verb;
- writes require approval and fail closed unattended;
- destructive actions are denied;
- successful remote output is sanitized and persisted as untrusted evidence;
- configuration alone does not set an integration to `AVAILABLE`.

## 12. Inspect the agent's evaluation architecture

Routine repository checks and the primary corpus are separate from the intentional holdout gate:

```bash
make quality
make test
make eval
make security

# Explicit readiness checkpoint, not routine tuning
make holdout
```

The fixed 34-scenario primary evaluator covers application/test defects, unsafe repair strategies, prompt injection, MCP failures, regression omissions, production-load attempts, and control-plane injection.

The H-series is stored separately and is not consumed by the everyday primary runner. See [`EVALUATION.md`](EVALUATION.md).

## 13. Inspect traceability without confusing it with PASS

```bash
ai-qa lineage artifacts/run-<id>
ai-qa attest artifacts/run-<id>
```

[`TRACEABILITY.md`](TRACEABILITY.md) shows how evidence, artifacts, hypotheses, validation gates, runtime events, and terminal reports relate.

The attestation is deliberately unsigned. Integrity metadata helps detect persisted-record tampering; it does not sign the run, certify compliance, or override validation status.

## 14. Finish with the verification boundary

Read these documents last:

- [`SETUP.md`](SETUP.md) — exact configuration and credentials by operating mode;
- [`OPERATIONS.md`](OPERATIONS.md) — staged verification ladder;
- [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) — repository-contained versus environment-dependent capability;
- [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) — authoritative status vocabulary and release truth table.

The intended conclusion is not “everything is production verified.” It is stronger and more defensible: **the architecture makes it difficult to accidentally claim verification that the system did not actually observe.**

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
