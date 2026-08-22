# Evaluation Strategy

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

The ƳƤ AI QA Automation Framework is evaluated as a **software control system**, not by whether model prose sounds intelligent or a generated test becomes green.

The evaluation architecture targets the failure modes that matter for agentic QA: false defect attribution, wrong self-healing, meaningless tests, regression under-selection, prompt injection, authority expansion, stale evidence, unsafe recovery, provider ambiguity, unbounded execution, and false PASS.

## Evaluation layers

| Layer | Purpose | Authority |
|---|---|---|
| Unit tests | schemas, config, policy, redaction, intelligence, evidence, budgets, recovery, traceability | deterministic |
| Integration tests | evidence/state/report flow, manifests, reference-SUT behavior, SDK/tool contracts | deterministic; some runtime-dependent |
| Security/policy tests | governance, secrets, paths, tool/network/MCP/load/mutation boundaries | deterministic |
| Primary evaluator | fixed 34 functional/adversarial scenarios | deterministic benchmark |
| Holdout evaluator | physically separate H-series | independent deterministic benchmark |
| Browser-marked tests | Playwright-backed browser behavior | browser runtime |
| Model-marked tests | live Claude Agent SDK behavior | credentialed provider runtime |

The layers remain separate so one evidence class cannot masquerade as another.

## Primary adversarial corpus

The fixed primary catalog contains exactly 34 scenarios under `evals/scenarios/`:

```bash
python evals/runner.py
# or
make eval
```

Primary scenarios set:

```json
"holdout": false
```

They exercise classes including:

- application versus automation defects;
- locator/UI-contract changes;
- timing/flakiness;
- authentication/data/environment/configuration/dependency failures;
- unsafe healing attempts;
- assertion weakening, sleeps, timeout inflation, skip/xfail, suppression;
- malformed structured model output;
- bounded-loop behavior;
- provider failure normalization;
- prompt injection through provider, DOM, API, test data, and target configuration;
- regression false negatives and mandatory coverage preservation;
- performance regression and production-load denial;
- governance modification attempts;
- target agent/MCP configuration injection.

## Independent H-series holdout

The H-series lives under `evals/holdout/` and uses its own runner:

```bash
python evals/holdout_runner.py
# or
make holdout
```

Holdout scenarios set:

```json
"holdout": true
```

The directory is excluded from `make verify-local` so ordinary implementation work does not optimize directly against exact holdout fixtures.

The H-series includes variants around:

- competing evidence signals;
- observed fact versus model interpretation;
- provider rate limiting;
- nested governance protection;
- security-critical regression preservation;
- uncertainty-driven regression broadening.

A holdout failure should produce a general engineering improvement. Do not:

- relabel a failing case merely to remove the holdout failure;
- change an expected result to match broken behavior;
- relax a hard-safety threshold after observing the failure;
- special-case one fixture while leaving the general weakness intact.

If a holdout case becomes ordinary tuning knowledge, preserve the independent surface by adding a genuinely new holdout variant.

## Fixed hard-safety thresholds

`evals/thresholds.json` defines acceptance rules independently of an individual run. Hard-safety scenarios require zero known failures.

Thresholds are governance inputs. The implementation adapts to the safety bar; the safety bar is not moved to accommodate the implementation.

## Security-critical regression families

In addition to scenario evaluation, deterministic tests cover specific invariants where a subtle code regression could widen authority.

### Terminal truth

- model completion alone cannot produce verified success;
- no-validation completion remains `NOT_VERIFIED`;
- non-PASS validation outcomes cannot be promoted;
- same-gate PASS/FAIL at one revision remains contradictory;
- a different gate cannot erase a historical failure;
- changed tests require current-revision patch-safety + targeted + regression closure.

### Self-healing semantics

- locator uniqueness is measured by Playwright rather than trusted from model input;
- locator expressions must fit the supported literal grammar;
- deterministic semantic tokens are derived from locator contracts;
- a semantically related replacement receives a strong deterministic score;
- a unique unrelated element does not inherit model semantic confidence;
- model stability confidence is overwritten by policy-owned strategy stability;
- unsupported/structural/positional locators are ineligible for autonomous repair.

### Failure classification

- application/network evidence cannot be hidden by an eager locator guess;
- locator-contract classification requires same-page context plus a unique stable **semantically related** candidate;
- a unique semantically unrelated candidate remains insufficient evidence.

### Configuration and network policy

- external network/write/API mutation defaults fail closed;
- trusted host entries are canonicalized/deduplicated;
- wildcard, URL, port, path, user-info, malformed DNS entries are rejected;
- IDNA normalization is deterministic;
- independent runtime budget bounds reject invalid values;
- repository `.env` files are not auto-loaded as trusted settings.

### Secret/governance paths

- `.env`, `.env.*`, including nested copies, are protected from runtime reads;
- `.env.example` remains readable reference documentation;
- governance paths cannot be mutated autonomously;
- absolute/traversal/symlink workspace escapes fail closed.

### Mutation and recovery

- one mutation transaction at a time;
- rollback bytes are hash-bound;
- missing/tampered/escaped/symlinked rollback backups block restoration/commit;
- live mutation rejects symlink aliases;
- stale recovery rejects symlinked target aliases and rollback aliases;
- prior-run traversal is blocked;
- newer human work prevents automatic stale rollback.

### External MCP

- unapproved provider identities fail closed;
- read/write/destructive actions remain distinct;
- mixed action names cannot smuggle write/destructive semantics behind reads;
- business IDs resembling HTTP codes do not become auth/rate-limit outcomes without status context;
- failed provider calls do not fabricate remote evidence.

### Evidence integrity

- run IDs/artifact paths cannot escape trusted storage;
- symlink artifact paths are rejected;
- duplicate evidence IDs/artifact paths cannot overwrite prior records;
- malformed duplicate manifests fail closed;
- regulated audit chains preserve record linkage.

### Test quality

- assertionless tests are rejected;
- strings/comments containing assertion-like text do not count;
- assertions inside unused nested scopes do not make an outer test observable;
- fluent assertion APIs are recognized deliberately;
- tautologies and broad suppression are surfaced;
- generated files cannot overwrite existing tests or escape approved test directories.

## Runtime adapter assertions

The evaluation surface also encodes properties such as:

- API mutations require explicit enablement;
- browser navigation/subrequests/WebSockets remain within host policy;
- k6 scripts bind to approved target and reject forbidden imports/hosts/local reads;
- total tool/network/mutation/repetition/time budgets remain independent;
- concurrent runs cannot share a target mutation lease;
- persisted lineage connects evidence/artifacts/hypotheses/validations/runtime events;
- attestations remain unsigned integrity statements;
- merge-base-aware change intelligence captures committed feature-branch risk;
- CODEOWNERS unsupported grammar is surfaced rather than guessed;
- OpenAPI drift classification remains conservative;
- low-confidence/truncated test impact cannot justify aggressive omission.

## What an evaluation result means

A deterministic evaluator answers whether the implementation behaved as expected for its predefined cases and environment. It does not generalize beyond that evidence boundary to every provider account, real application, device fleet, infrastructure control, or unknown future attack.

## Metrics that matter

When measured against a defined dataset/run, useful quality metrics include:

- failure-classification precision/recall;
- false-positive product-defect rate;
- self-healing semantic correctness and false-heal rate;
- generated-test meaningful-assertion quality;
- regression-selection recall/reduction/escaped-regression rate;
- prompt-injection blocks and policy denials;
- execution duration and tool/network/mutation counts;
- model token/cost information when supplied by the provider.

Benchmark percentages should be quoted only with the dataset and execution record that produced them.

## Interpretation standard

A green-looking suite is not sufficient evidence of quality if it contains:

- false healing;
- weakened test intent;
- escaped mandatory/security/safety/regulatory coverage;
- fabricated or stale evidence;
- policy bypass;
- threshold manipulation;
- hidden flakiness;
- unsafe rollback/recovery;
- unbounded execution.

See [`README.md`](README.md), [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md), [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md), [`OPERATIONS.md`](OPERATIONS.md), and [`TECHNICAL_WALKTHROUGH.md`](TECHNICAL_WALKTHROUGH.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
