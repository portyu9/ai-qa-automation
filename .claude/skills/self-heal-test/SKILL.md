---
name: self-heal-test
description: Guarded semantic locator maintenance that preserves business intent.
---
# Self-Heal Test

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

## Use when
Observed browser evidence shows the expected product behavior still exists but a test locator is stale.

## Do not use when
The application behavior is broken, the current deterministic classification does not support a locator/test-automation defect, the candidate is ambiguous or non-unique, or the proposed change weakens test intent.

## Inputs
Failing test path and file hash, original supported locator, screenshot/accessibility evidence, Playwright locator-verification evidence, and current deterministic failure classification.

## Preconditions
The failure has been reproduced or independently evidenced; the expected behavior is still present; the test path is policy-authorized; and test writes are explicitly enabled.

## Workflow
1. Collect same-page browser evidence, including screenshot plus accessibility/DOM evidence.
2. Verify the original locator and candidate locators with Playwright in the same live DOM.
3. Use observed match counts; never accept a model-declared uniqueness count as proof.
4. Classify the failure from the accumulated observed evidence.
5. Continue only when the current deterministic classification is `LOCATOR_UI_CONTRACT_CHANGE` or `TEST_AUTOMATION_DEFECT` with sufficient confidence.
6. Rank only browser-verified semantic candidates. Prefer stable test ID > accessible role/name > label > placeholder/text > carefully reviewed semantic CSS.
7. Reject dynamic code, XPath/positional/structural selectors, ambiguity, and candidates chosen merely because they are nearby.
8. Create a proposal bound to the verification evidence, exact test path, original locator, and expected file SHA-256.
9. Apply only the approved locator expression; the live agent has no generic existing-test text-replacement tool.
10. Run a targeted pytest validation and a full regression at the new change revision.
11. Do not perform another mutation until patch safety, targeted validation, and regression validation close the current revision.
12. Preserve before/after evidence and historical failures.

## Evidence requirements
Same-page screenshot plus accessibility/DOM evidence, Playwright-observed original/candidate match counts, current deterministic classification, bound healing proposal, patch diff/hash evidence, and post-change targeted/regression results.

## Allowed actions
Verify literal supported locators, propose a semantic candidate, apply one policy-approved locator-only patch when writes are explicitly enabled, and run bounded validations.

## Prohibited shortcuts
Model-declared uniqueness, arbitrary code as a locator, generic text replacement, deleting/weakening assertions, expected=actual substitution, arbitrary sleeps, timeout inflation, skip/xfail, exception suppression, or product-code mutation solely to make a test green.

## Validation requirements
Patch-safety PASS plus targeted pytest PASS plus full-regression pytest PASS at the current change revision. A green retry at the same revision cannot hide a conflicting failure.

## Escalate
High/ambiguous risk, non-unique candidate, semantic mismatch, unclear original intent, insufficient browser evidence, or required approval.

## Terminate
Return an allowed/denied proposal. An applied repair remains incomplete until the current revision is deterministically closed.

## Output
Allowed/denied, risk, bound old/new locator, verification/proposal/patch evidence IDs, rationale, change revision, and deterministic validation outcome when executed.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../../LICENSE`](../../../LICENSE).
