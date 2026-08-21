---
name: self-heal-test
description: Guarded semantic test maintenance that preserves business intent.
---
# Self-Heal Test

## Use when
Evidence shows the product behavior still exists but automation is stale, especially a locator/UI contract change.

## Do not use when
The application behavior is broken, evidence is ambiguous, or the proposed change weakens test intent.

## Inputs
Original locator/assertions, DOM and accessibility evidence, screenshot/trace when available, source/test code, failure evidence.

## Workflow
1. Reproduce and capture before-state evidence.
2. Prove expected business behavior still exists.
3. Rank semantically equivalent candidates: stable test ID > role/name > stable semantic attribute > resilient framework-native locator.
4. Reject generated IDs, fragile chains, positional selectors, ambiguity, and “nearby” elements.
5. Require uniqueness=1 and sufficient semantic/stability score.
6. Validate proposed diff against deterministic unsafe-change policy.
7. Apply only when policy permits.
8. Run targeted test, relevant regression, and intent-preservation review.
9. Record before/after evidence.

## Never heal by
Deleting/weakening assertions, expected=actual substitution, arbitrary sleeps, broad timeout inflation, skip/xfail, exception suppression, or product-code mutation to make a test green.

## Escalate
High/ambiguous risk, non-unique candidate, semantic mismatch, or required approval.

## Output
Allowed/denied, risk, old/new locator, evidence IDs, rationale, required validations.
