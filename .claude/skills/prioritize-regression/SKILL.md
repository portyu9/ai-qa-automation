---
name: prioritize-regression
description: Risk-based regression selection with mandatory-coverage fail-safes.
---
# Prioritize Regression

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

## Use when
Use when a change has an identifiable regression candidate set and execution reduction is useful without sacrificing risk-adjusted recall.

## Do not use when
There is no reliable candidate inventory, mandatory coverage cannot be identified, or the change impact is too uncertain to justify reduction.

## Inputs
Changed files/modules/APIs, dependency information, ownership/mappings, historical failures, runtime, and business/security/safety/regulatory criticality.

## Preconditions
Candidate tests are known and mandatory tests are marked independently of model preference.

## Workflow
1. Build deterministic impact signals.
2. Add semantic impact reasoning only as supplemental evidence.
3. Score candidates and explain selected tests; explain omissions when requested.
4. Preserve mandatory smoke/security/safety/regulatory coverage regardless of model preference.
5. LOW CONFIDENCE, incomplete dependency data, or conflicting evidence → broaden regression.
6. Report selection confidence and reduction ratio together.

## Evidence requirements
Candidate inventory, change/dependency signals, mandatory flags, selection scores, uncertainty indicators, and final selected/omitted test IDs.

## Allowed actions
Analyze supplied candidate metadata and produce an explainable bounded selection.

## Prohibited shortcuts
Do not optimize for the smallest suite, remove mandatory tests, treat model confidence as dependency evidence, or hide uncertainty.

## Validation requirements
Mandatory coverage must be preserved. Known-regression evaluation uses recall/escape behavior, not reduction alone.

## Escalate
Incomplete candidate inventory, conflicting impact evidence, low confidence, or missing mandatory-coverage classification.

## Terminate
Return a selection when safeguards are satisfied; otherwise broaden to a safer regression set.

## Output
Selected/omitted tests, rationale by test, confidence, reduction ratio, and `broadened_due_to_uncertainty` state.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../../LICENSE`](../../../LICENSE).
