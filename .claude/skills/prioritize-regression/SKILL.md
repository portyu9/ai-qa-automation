---
name: prioritize-regression
description: Risk-based regression selection with mandatory-coverage fail-safes.
---
# Prioritize Regression

## Inputs
Changed files/modules/APIs, dependency information, ownership/mappings, historical failures, runtime, business/security/safety/regulatory criticality.

## Workflow
1. Build deterministic impact signals.
2. Add semantic impact reasoning only as supplemental evidence.
3. Score candidates and explain every selected test; explain omissions when requested.
4. Preserve mandatory smoke/security/safety/regulatory coverage regardless of model preference.
5. LOW CONFIDENCE, incomplete dependency data, or conflicting evidence → broaden regression.
6. Measure recall and escape risk before celebrating execution reduction.

## Prohibited shortcuts
Do not optimize for smallest suite, omit mandatory tests, or treat model confidence as dependency evidence.

## Output
Selected/omitted tests, rationale by test, confidence, reduction ratio, broadened-due-to-uncertainty flag.
