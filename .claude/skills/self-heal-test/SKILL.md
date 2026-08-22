---
name: self-heal-test
description: Guarded semantic locator maintenance that preserves business intent.
---
# Self-Heal Test

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

## Use when
Observed browser evidence shows the expected product behavior still exists but a supported test locator is stale.

## Do not use when
The application behavior is broken, the deterministic classification does not support a locator/test-automation defect, the original locator is outside the supported semantic contract, the candidate is ambiguous/non-unique, or the proposed change weakens test intent.

## Inputs
Failing test path and file hash, original supported locator, screenshot/accessibility evidence, Playwright locator-verification evidence, and deterministic failure classification.

## Preconditions
The failure has been reproduced or independently evidenced; expected behavior remains present; the test path is policy-authorized; and autonomous test writes are explicitly enabled.

## Workflow
1. Collect same-page browser evidence, including screenshot plus accessibility/DOM evidence.
2. Verify the original locator and candidate locators with Playwright in the same live DOM.
3. Use observed match counts; never accept a model-declared uniqueness count as proof.
4. Classify the failure from accumulated observed evidence.
5. Continue only when the deterministic classification is `LOCATOR_UI_CONTRACT_CHANGE` or `TEST_AUTOMATION_DEFECT` with sufficient confidence.
6. Parse the original and candidate locators through the supported non-executable locator grammar.
7. Recompute semantic-intent overlap deterministically from the locator contracts; model-supplied semantic confidence is advisory only and must not authorize mutation.
8. Apply policy-owned strategy stability. Prefer stable test ID > accessible role/name > label > placeholder > exact text > carefully constrained semantic CSS.
9. Reject dynamic code, unsupported syntax, XPath/positional/structural selectors, weak semantic overlap, ambiguity, and candidates chosen merely because they are nearby.
10. Create a proposal bound to verification evidence, exact test path, original locator, and expected file SHA-256.
11. Apply only the approved locator expression; the live agent has no generic existing-test text-replacement tool.
12. Run targeted pytest validation and full regression at the new change revision.
13. Do not perform another mutation until patch safety, targeted validation, and regression validation close the current revision.
14. Preserve before/after evidence and historical failures.

## Evidence requirements
Same-page screenshot plus accessibility/DOM evidence, Playwright-observed original/candidate match counts, deterministic semantic eligibility, deterministic failure classification, bound healing proposal, patch diff/hash evidence, and post-change targeted/regression results.

## Allowed actions
Verify literal supported locators, propose semantic candidates, apply one policy-approved locator-only patch when writes are explicitly enabled, and run bounded deterministic validations.

## Prohibited shortcuts
Model-declared uniqueness or semantic authority, arbitrary code as a locator, generic text replacement, deleting/weakening assertions, expected=actual substitution, arbitrary sleeps, timeout inflation, skip/xfail, exception suppression, or product-code mutation solely to make a test green.

## Validation requirements
Patch-safety PASS plus targeted pytest PASS plus full-regression pytest PASS at the current change revision. A green retry at the same revision cannot hide a conflicting failure.

## Escalate
High/ambiguous risk, unsupported original intent, non-unique candidate, deterministic semantic mismatch, insufficient browser evidence, or required approval.

## Terminate
Return an allowed/denied proposal. An applied repair is trusted only after the current revision deterministically closes.

## Output
Allowed/denied, risk, bound old/new locator, verification/proposal/patch evidence IDs, rationale, change revision, and deterministic validation outcome.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../../LICENSE`](../../../LICENSE).
