# Technical Walkthrough

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

This walkthrough is the reviewer-oriented path through the implementation. It follows the framework from **trusted objective → deterministic observation → bounded reasoning/action → revision-aware validation → persisted runtime outcome** and highlights the exact points where authority changes hands.

## 1. Begin with runtime truth

Start with:

- `src/ai_qa_automation/models.py`
- `src/ai_qa_automation/agent.py`
- `src/ai_qa_automation/reporting.py`
- [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md)

`determine_terminal_outcome()` is the central anti-false-PASS rule. A model result subtype of `success` is not enough.

The validator preserves gate identity and change revision. Important consequences:

- active deterministic FAIL remains failure;
- non-PASS validation outcomes remain non-PASS;
- PASS and FAIL for the same gate/revision become contradictory evidence and resolve to `NOT_VERIFIED`;
- an older failure is superseded only by the same gate identity at a newer revision;
- a changed test cannot close without patch-safety, targeted pytest, and full-regression PASS at the current revision.

This is the first code path to inspect when evaluating whether the framework can manufacture success.

## 2. Follow trust before functionality

Read [`ARCHITECTURE.md`](ARCHITECTURE.md).

The control repository owns trusted runtime policy, Skills, hooks, tool definitions, and thresholds. The target is an untrusted evidence source even when it ships files that look like agent configuration.

`validate_runtime_roots()` rejects overlapping control/target and artifact/target roots.

That trust split means target:

- `CLAUDE.md`;
- `.claude/`;
- `.mcp.json`;
- comments;
- test code;
- DOM/log/API content

cannot redefine framework authority.

## 3. Inspect trusted configuration parsing

Read `src/ai_qa_automation/config.py` before reviewing network-capable tools.

The configuration boundary does more than type coercion. Trusted host entries are canonicalized and validated before runtime use:

- DNS/IP identity only;
- no wildcard entries;
- no URLs;
- no embedded ports;
- no path/query/fragment/user-info syntax;
- IDNA normalization;
- deduplication;
- independent execution-budget validation.

This prevents API/browser/performance tools from interpreting malformed trusted configuration differently.

`.env` files are not auto-loaded by the settings model.

## 4. Follow deterministic bootstrap into evidence

`runtime/bootstrap.py` captures repository state before Claude receives the objective:

- Git SHA and worktree fingerprint;
- explicit base-ref / merge-base provenance;
- committed plus dirty/untracked changes;
- risk domains;
- repository/test topology;
- dependency manifests/hashes;
- CODEOWNERS routing;
- explainable test-impact candidates;
- OpenAPI/Swagger compatibility drift.

The observed data is persisted first. Only a bounded summary is then presented to the model as context.

The architecture therefore asks Claude to reason **from** repository facts, not invent them.

## 5. Follow evidence into canonical state

Inspect:

- `src/ai_qa_automation/evidence.py`
- `src/ai_qa_automation/state.py`
- `src/ai_qa_automation/models.py`
- `src/ai_qa_automation/runtime/journal.py`

`EvidenceStore` confines run/artifact paths, enforces immutable evidence/artifact identities, sanitizes supported text evidence, hashes artifacts, writes manifests, and optionally appends regulated audit records.

`StateStore` atomically persists canonical QA decision state. `journal.jsonl` provides append-only hash-chained runtime chronology.

The deterministic demo:

```bash
ai-qa demo
```

illustrates a core classification rule: application/network evidence must not be hidden by an eager test repair.

## 6. Inspect the controlled tool surface

`runtime/internal_tools.py` defines 18 narrow QA tools. `policy.py` and `runtime/runtime_hooks.py` independently govern authorization and process safety.

Inspect these boundaries:

- explicit internal tool inventory;
- unknown tools denied;
- Bash/Edit/Write/Web-style generic authority denied;
- path decisions before file access/mutation;
- network decisions before target access;
- budget/circuit enforcement before execution;
- workspace drift checks before mutation;
- mutation transaction preparation before the write;
- canonical state checkpointing after meaningful evidence/state changes.

## 7. Inspect secret and governance path policy

`PolicyEngine._is_protected()` protects authority-bearing and secret-shaped paths.

In addition to governance paths, `.env` and `.env.*` files are protected even when nested. `.env.example` remains readable reference documentation.

This rule reduces the chance that a target repository exposes secret material merely because a bounded source-reading tool is available.

## 8. Inspect failure classification before healing

Read `src/ai_qa_automation/intelligence/failure_analysis.py`.

The classifier is evidence-weighted and model-independent. It distinguishes application, automation, locator/UI-contract, data, timing, environment, dependency, authentication, configuration, performance, and insufficient-evidence outcomes.

The locator path is intentionally conservative. Playwright evidence supports `LOCATOR_UI_CONTRACT_CHANGE` only when:

- original locator is absent;
- a candidate is uniquely observed;
- candidate strategy is supported/stable;
- same-page context evidence exists; and
- the candidate preserves enough **deterministically computed semantic intent** from the original locator.

A unique unrelated button is therefore not sufficient evidence of a locator-contract change.

## 9. Inspect self-healing authority

Read together:

- `src/ai_qa_automation/tools/locators.py`
- `src/ai_qa_automation/tools/browser_evidence.py`
- `src/ai_qa_automation/intelligence/self_healing.py`
- `src/ai_qa_automation/tools/safe_patch.py`
- `.claude/skills/self-heal-test/SKILL.md`

The workflow separates five things that should never be conflated:

1. model proposal;
2. browser observation;
3. deterministic semantic/stability eligibility;
4. mutation authorization;
5. post-change validation.

Playwright measures candidate match counts in the same DOM and records deterministic semantic overlap in verification evidence. `SelfHealingEngine` independently reparses the locator contract, recomputes semantic overlap, overwrites model stability with policy-owned stability, rejects structural/positional selectors, and requires a conservative threshold before producing an allowed proposal.

Therefore:

> **Unique + model confidence ≠ mutation authority.**

The proposal remains bound to exact test path, original locator, verification evidence, and expected file hash. The only live repair path is locator-only replacement.

## 10. Inspect safe mutation and recovery as one subsystem

Read:

- `src/ai_qa_automation/runtime/run_control.py`
- `src/ai_qa_automation/runtime/stale_recovery.py`
- [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md)

Live mutation rejects absolute/traversal/symlink path ambiguity and snapshots original bytes under trusted rollback storage.

Crash recovery intentionally enforces the same ownership philosophy:

- prior run directory confined beneath artifact root;
- non-symlink runtime metadata;
- exact workspace identity;
- exact persisted/current fingerprint match;
- non-symlink pending target path;
- rollback directory confinement;
- non-symlink backup path;
- original SHA-256 verification.

A recovery path that is less strict than the live mutation path would be a security bypass; this implementation avoids that asymmetry.

## 11. Inspect coverage-aware test generation

The generation toolchain is provenance-bound:

```text
search_test_coverage
→ observed coverage evidence
→ plan_tests
→ same-run TEST_PLAN evidence
→ create_test_file
→ deterministic test-quality + patch-safety
→ targeted execution
→ regression closure
```

Generated Python/JavaScript/TypeScript tests are rejected for missing meaningful assertions and common quality shortcuts. Python review does not count assertions inside unused nested scopes; JS/TS review does not count assertion-looking text in comments/strings.

## 12. Inspect change intelligence and regression safety

Read [`CHANGE_INTELLIGENCE.md`](CHANGE_INTELLIGENCE.md).

The important design point is merge-base awareness. A feature branch can be clean and still carry committed risk. With explicit `AI_QA_BASE_REF`, the runtime analyzes the committed delta plus dirty/untracked changes.

CODEOWNERS and test-impact output are review/prioritization evidence, never runtime authorization.

Low confidence or incomplete mapping broadens regression instead of proving omission safe.

## 13. Inspect network adapters

### API

`tools/api_testing.py` enforces:

- host authorization;
- method authorization;
- no ambient proxy inheritance;
- no automatic redirect following;
- bounded response capture;
- sanitized evidence.

### Browser

`tools/browser_evidence.py` enforces:

- host policy for navigation/subresources/WebSockets;
- service-worker blocking in the evidence context;
- final navigation recheck;
- raw screenshot artifact labeling;
- same-DOM locator evidence.

The WebSocket path uses Playwright's routed server-connection API compatible with the framework's supported Playwright range.

### k6

`tools/performance.py` and policy enforce:

- non-production target classification;
- production-like hostname denial;
- injected target binding;
- supported import/module restrictions;
- no local `open()`;
- no unrelated literal network host;
- external-egress prerequisite for non-local targets;
- measured threshold assessment.

## 14. Inspect runtime control independently from QA state

`state.json` is QA decision state. `runtime.json` is process-control state. `journal.jsonl` is operational chronology.

This separation prevents:

- lease ownership from becoming test evidence;
- a model conversation from being the only recovery record;
- process metadata from being interpreted as a QA conclusion.

## 15. Inspect external MCP authorization

Read [`MCP.md`](MCP.md).

External provider trust has two gates:

1. provider identity/configuration;
2. action-level authorization.

Mixed names are tokenized conservatively so destructive semantics dominate writes, and writes dominate recognized reads. A read-looking prefix cannot smuggle a create/delete action.

Provider failures are normalized without fabricating remote evidence. Business IDs that resemble HTTP codes are not treated as transport/auth results unless the surrounding text is status-shaped.

## 16. Inspect evaluation as software engineering

Read [`EVALUATION.md`](EVALUATION.md).

The evaluation design separates:

- unit/integration/policy/security tests;
- fixed 34-scenario primary corpus;
- physically separate H-series holdout;
- browser-marked tests;
- credentialed model tests.

The important governance property is that hard-safety expectations are defined independently of the implementation result. A failing implementation is not “fixed” by weakening the benchmark after the fact.

## 17. Inspect traceability without confusing it with correctness

```bash
ai-qa lineage artifacts/run-<id>
ai-qa attest artifacts/run-<id>
```

[`TRACEABILITY.md`](TRACEABILITY.md) explains evidence/artifact/hypothesis/validation/runtime relationships.

The attestation is deliberately unsigned. Hash integrity can establish persisted-record properties; it cannot certify identity, compliance, or a test outcome.

## 18. Finish with the evidence/deployment boundary

Read:

- [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md)
- [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md)
- [`LIMITATIONS.md`](LIMITATIONS.md)
- [`SETUP.md`](SETUP.md)
- [`OPERATIONS.md`](OPERATIONS.md)

The intended conclusion is simple but strict:

> **Every claim is bound to its evidence source, and model reasoning never outranks deterministic authority, ownership, or validation.**

Return to the documentation [`README.md`](README.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
