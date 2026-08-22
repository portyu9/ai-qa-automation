---
name: prioritize-regression
description: Risk-based regression selection with mandatory-coverage fail-safes.
---
# Prioritize Regression

> [!IMPORTANT]
> Optimize **risk-adjusted recall before execution reduction**. Uncertainty broadens regression; it never authorizes omission.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

## Use when
A change has an identifiable regression candidate set and execution reduction is useful without sacrificing risk-adjusted recall.

## Do not use when
Candidate inventory is unreliable, mandatory coverage cannot be identified independently, or impact uncertainty is too high to justify reduction.

## Inputs
Changed files/modules/APIs, dependency signals, ownership/mappings, candidate tests, historical failures, runtime cost, and business/security/safety/regulatory criticality.

## Preconditions
Candidate tests are known and mandatory tests are marked independently of model preference.

## Workflow
1. Build deterministic impact signals.
2. Add model semantic reasoning only as supplemental interpretation.
3. Score candidates and explain selected tests; explain omissions when requested.
4. Preserve mandatory smoke/security/safety/regulatory coverage independently from score/model preference.
5. Treat low confidence, incomplete dependency data, truncated mapping, conflicting evidence, or incomplete candidate inventory as reasons to broaden regression.
6. Report selection confidence and reduction ratio together so a smaller suite is never presented without its uncertainty context.

## Evidence requirements
Candidate inventory, change/dependency signals, mandatory flags, selection scores, uncertainty indicators, and final selected/omitted test IDs.

## Allowed actions
Analyze supplied/observed candidate metadata and produce an explainable bounded selection.

## Prohibited shortcuts
Do not optimize for the smallest suite, remove mandatory tests, treat model confidence as dependency evidence, hide uncertainty, or infer safe omission from incomplete mapping.

## Validation requirements
Mandatory coverage must be preserved. Known-regression evaluation uses recall/escaped-regression behavior, not reduction alone.

## Escalate
Incomplete candidate inventory, conflicting impact evidence, low confidence, truncated mapping, or missing mandatory-coverage classification.

## Terminate
Return a reduced selection only when safeguards are satisfied; otherwise broaden to the safer regression set.

## Output
Selected/omitted tests, rationale by test, confidence, reduction ratio, uncertainty indicators, and `broadened_due_to_uncertainty` state.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../../LICENSE`](../../../LICENSE).
