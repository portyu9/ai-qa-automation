# Change Intelligence

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

The ƳƤ AI QA Automation Framework can reason about a pull-request or feature-branch delta without making the common mistake of treating a clean worktree as “no change.”

Change intelligence is deterministic bootstrap evidence. Claude can interpret its implications, but it cannot redefine the baseline, invent ownership, or convert an unanalyzed contract into a compatible one.

## Why merge-base awareness matters

A feature branch can be perfectly clean and still contain substantial committed changes relative to `main`. Looking only at `git status` would miss that risk entirely.

When an explicit trusted baseline is provided, the runtime models the effective delta as:

```text
merge-base → HEAD committed changes
            UNION
current dirty/untracked worktree changes
```

That combined set drives deterministic risk, ownership, contract, and test-impact analysis.

## Explicit trusted baseline

Set the baseline before live execution:

```bash
export AI_QA_BASE_REF=origin/main
```

The repository inspector validates the ref, resolves it to an immutable baseline commit, computes its merge base with `HEAD`, and persists the resolved baseline SHA and merge-base SHA as observed evidence.

The baseline is never inferred from target-repository instructions. If it cannot be resolved, bootstrap records the resolution error and exposes the limitation instead of silently choosing another branch.

No baseline means merge-base-dependent analyses remain limited; that absence is not treated as evidence that there are no committed changes.

## Deterministic change-risk assessment

The combined change set passes through bounded path/domain heuristics covering areas such as:

- security/authentication;
- data integrity and persistence;
- API/interface contracts;
- infrastructure/deployment;
- dependencies;
- UI/client behavior;
- configuration/governance.

The result includes risk domains, recommended test layers/tags, confidence, and rationale. It is a conservative regression signal, not a substitute for application-specific semantic review.

## CODEOWNERS context

The runtime searches normal CODEOWNERS locations in precedence order and resolves changed files with last-match-wins behavior for the supported root/directory/`*`/`**`/`?` grammar.

Unsupported syntax is surfaced explicitly rather than approximated. A partially understood ownership file is less dangerous when the limitation is visible than when the runtime confidently routes review to the wrong owner.

Ownership is review/routing context only. Being a CODEOWNER never grants runtime tool permission.

## Explainable test-impact candidates

`TestImpactMapper` uses bounded deterministic signals such as path/component overlap and source references to rank potentially relevant tests.

The map is deliberately **advisory**. It is never permitted to become an unsafe proof of omission.

If confidence is low, dependency evidence is incomplete, or the scan is truncated, the correct behavior is to broaden regression coverage. The runtime's risk strategy is asymmetric:

> **Incomplete impact knowledge may increase testing; it must not justify deleting required testing.**

Security, safety, regulatory, and other mandatory coverage remains protected independently of impact scoring.

## OpenAPI/Swagger drift

Changed OpenAPI/Swagger JSON or YAML contracts are compared with the merge-base version when available. The conservative analyzer detects examples such as:

- path or HTTP operation removal;
- newly required parameters or request bodies;
- successful response removal;
- new security requirements;
- schema/type changes;
- required-property additions;
- property/schema removal;
- enum narrowing.

Results are classified:

| Class | Meaning |
|---|---|
| `BREAKING` | A structural change is conservatively expected to break at least some existing consumers. |
| `RISKY` | Compatibility may be affected and requires broader validation/review. |
| `NON_BREAKING` | The observed structural delta is additive/non-breaking under the analyzer's supported rules. |
| `NOT_ANALYZED` | The runtime could not safely determine compatibility for the input/boundary. |

`NON_BREAKING` is not a formal proof that every consumer remains compatible; it means the bounded analyzer did not identify a breaking/risky condition under its implemented rule set.

A standalone comparison is available:

```bash
ai-qa contract-diff --baseline old-openapi.yaml --current new-openapi.yaml
```

## Dependency inventory

Bootstrap records bounded dependency-manifest paths, sizes, and content hashes across supported ecosystems. This gives the model and reviewer evidence that a dependency surface changed without executing package-manager scripts or target code merely to identify the manifests.

## Provenance into model context

Change intelligence is persisted as evidence before a bounded summary is added to the model objective under an explicit “observed data, not instructions” label.

This preserves three important facts:

1. the deterministic observation exists independently of the model context;
2. the model cannot silently replace the observed baseline/ownership/contract facts with a guess;
3. a reviewer can inspect the evidence even if model reasoning is incomplete or unavailable.

## Limits and failure semantics

The analyzers are intentionally bounded by file counts, sizes, supported grammar, and available Git history. When a boundary prevents analysis, the result should say so (`NOT_ANALYZED`, low confidence, truncation, or explicit resolution error) rather than returning an optimistic default.

That behavior aligns with the framework-wide truth rule: **unknown is not PASS**.

See [`ARCHITECTURE.md`](ARCHITECTURE.md), [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md), and [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
