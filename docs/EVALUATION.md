# Evaluation Strategy

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

The ƳƤ AI QA Automation Framework is evaluated as a **software control system**, not only by whether a model produces convincing prose or a generated test becomes green.

The evaluation strategy targets the failure modes that matter for an autonomous QA system: false defect attribution, unsafe self-healing, meaningless generated tests, regression under-selection, prompt injection, authority expansion, fabricated external evidence, unbounded execution, and false PASS.

## Evaluation layers

| Layer | Purpose | Typical authority |
|---|---|---|
| Unit tests | Schemas, policy, redaction, intelligence logic, budgets, recovery, change intelligence, traceability | Deterministic |
| Integration tests | Evidence/state/report flow, manifests, audit chaining, reference-SUT behavior, SDK contracts | Deterministic; some marked environment-dependent |
| Security/policy tests | Governance protection, prompt-injection-shaped data, destructive actions, path/tool/network boundaries | Deterministic |
| Primary scenario evaluator | Fixed 34 functional/adversarial scenarios under `evals/scenarios/` | Deterministic benchmark |
| Holdout evaluator | Separate H-series under `evals/holdout/` | Intentional readiness benchmark |
| Browser-marked tests | Real browser behavior, isolated from the default pytest marker set | Browser runtime required |
| Model-marked tests | Live Claude Agent SDK behavior, isolated behind explicit credentials | Environment required |

The architecture deliberately separates repository-contained determinism from live-model/integration checks so a missing credential cannot accidentally turn into a passing simulation of that integration.

## Routine primary evaluation

The fixed primary catalog contains exactly 34 scenarios and is executed by:

```bash
python evals/runner.py
# or
make eval
```

Primary scenarios set:

```json
"holdout": false
```

They cover classes including:

- application versus automation defects;
- locator/UI-contract changes and timing/flakiness;
- authentication, data, environment, configuration, and dependency failures;
- unsafe healing attempts;
- assertion weakening, arbitrary sleeps, timeout inflation, skipping/xfail, and broad suppression;
- malformed structured model output;
- bounded-loop behavior;
- Agent SDK transient-failure normalization;
- GitHub/Atlassian MCP outage and authorization states;
- prompt injection through GitHub, Jira, DOM, API, test data, and target configuration;
- regression-selection false negatives and mandatory-test preservation;
- performance regression and production-load denial;
- governance-file modification attempts;
- target `CLAUDE.md` / `.mcp.json` control-plane injection.

## Holdout discipline

The H-series corpus is physically separate under `evals/holdout/` and executed only by:

```bash
python evals/holdout_runner.py
# or
make holdout
```

Holdout scenarios set:

```json
"holdout": true
```

The holdout directory is intentionally excluded from `make verify-local`. Routine implementation/tuning work should not repeatedly execute the holdout set and then optimize directly against its exact fixtures.

The initial H-series includes variants around:

- competing evidence signals;
- model-interpretation isolation from observed facts;
- MCP rate limiting;
- nested governance protection;
- security-critical regression preservation;
- very-low-confidence regression broadening.

A holdout failure is a readiness signal. The acceptable response is to investigate the underlying behavior and add a general control/regression test. The unacceptable responses are to:

- relabel the failing holdout as primary solely to remove the holdout failure;
- change the expected result to match broken behavior;
- relax hard-safety thresholds after seeing the failure;
- special-case the exact fixture while leaving the general weakness intact.

If a holdout scenario must eventually be retired or promoted into the primary corpus because it is no longer secret from the development loop, replace its independent coverage with a genuinely new holdout case rather than shrinking the readiness surface.

## Fixed thresholds

`evals/thresholds.json` defines thresholds independently of an individual evaluation run. Hard-safety scenarios require zero known failures.

Thresholds are governance inputs. A weak run is not repaired by changing the acceptance bar after observing the result.

The same zero-known-failure principle applies to hard-safety holdout cases.

## Important deterministic assertions

The framework's tests/evaluations are designed to assert behaviors including:

- model completion alone cannot produce verified success;
- a retry at the same change revision cannot hide contradictory PASS/FAIL evidence;
- only a newer approved revision can supersede an older gate result while preserving history;
- unknown tools and unapproved MCP namespaces fail closed;
- approval-required external writes fail closed unattended;
- API mutations require explicit enablement;
- browser navigation, subrequests, and WebSockets cannot escape the network allowlist;
- locator uniqueness comes from Playwright observation, not model assertion;
- generated-test creation requires same-run coverage-search and plan provenance;
- k6 scripts must bind to the approved target and external runs require the infrastructure-egress precondition;
- test patching cannot remove meaningful assertion coverage;
- regulated evidence records maintain hash lineage;
- operational journals detect tampering and preserve append-only hash linkage;
- total tool, network, mutation, repetition, and wall-time budgets are bounded independently;
- concurrent agent runs cannot silently share a target-workspace mutation lease;
- interrupted mutation rollback occurs only when the persisted fingerprint proves newer human work will not be overwritten;
- persisted lineage connects evidence, artifacts, hypotheses, validations, and runtime events;
- run attestations remain unsigned integrity statements and never convert `NOT_VERIFIED` into PASS;
- merge-base-aware change intelligence broadens regression for critical/high-risk changes;
- CODEOWNERS unsupported grammar is reported rather than guessed;
- OpenAPI drift distinguishes breaking/risky/additive classes conservatively;
- low-confidence or truncated test-impact maps cannot justify aggressive omission;
- MCP auth/outage/rate-limit/invalid-response states are normalized without invented remote evidence.

## What an evaluation result means

A deterministic evaluator answers whether the current implementation behaved as expected for its predefined scenarios. It does **not** prove:

- that Claude will behave correctly for every prompt;
- that authenticated GitHub/Atlassian MCP works in a particular account;
- that a real browser/device/application behaves like the reference fixtures;
- that infrastructure sandboxing/egress is correctly deployed;
- that a security control is complete against unknown future attacks.

Those require separate evidence.

## Metrics that matter

The state/reporting model supports quality metrics such as:

- failure-classification precision/recall;
- false-positive product-defect rate;
- self-healing semantic correctness and false-heal rate;
- generated-test meaningful-assertion/acceptance quality;
- regression-selection recall, reduction, and escaped-regression rate;
- prompt-injection blocks and policy denials;
- execution duration and tool/network/mutation counts;
- model token/cost information when actually observed.

Raw numbers need a defined dataset and execution record before they should be quoted. The framework therefore does not invent benchmark percentages from unexecuted cases.

## Interpretation standard

The number of generated tests or repairs that become green is not sufficient evidence of quality. The following are hard quality failures even when a suite appears green:

- false healing;
- weakened test intent;
- escaped mandatory/security/safety/regulatory coverage;
- fabricated or stale evidence;
- policy bypass;
- threshold manipulation;
- hidden flakiness;
- unbounded execution.

Anything not actually executed remains `NOT_VERIFIED`, including the current-head primary and holdout suites until their deliberate execution occurs.

See [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md), [`OPERATIONS.md`](OPERATIONS.md), and [`TECHNICAL_WALKTHROUGH.md`](TECHNICAL_WALKTHROUGH.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
