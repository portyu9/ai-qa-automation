---
name: self-heal-test
description: Guarded semantic locator maintenance that preserves business intent.
---
# Self-Heal Test

> [!IMPORTANT]
> A unique locator is not automatically a correct locator, and model confidence is never mutation authority.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

## Use when
Observed browser evidence shows expected product behavior still exists but a supported Python test locator is stale.

## Do not use when
Application behavior is broken, deterministic classification does not support locator/test-automation repair, original intent is unsupported, the candidate is ambiguous/non-unique/semantically weak, or the proposed change weakens test intent.

## Inputs
Failing Python test path and file hash, original supported locator, same-page screenshot/accessibility evidence, Playwright locator-verification evidence, and deterministic failure classification.

## Preconditions
The failure has been reproduced or independently evidenced; expected behavior remains present; the Python test path is policy-authorized; and autonomous test writes are explicitly enabled.

## Workflow
1. Collect same-page browser evidence, including screenshot plus accessibility/DOM evidence.
2. Verify original and candidate locators with Playwright in the same live DOM.
3. Use observed match counts; never accept model-declared uniqueness as proof.
4. Classify the failure from accumulated observed evidence.
5. Continue only when deterministic classification supports locator/test-automation repair with sufficient evidence.
6. Parse original and candidate locators through the supported non-executable grammar.
7. Recompute semantic-intent overlap deterministically; model semantic confidence is advisory only.
8. Apply policy-owned strategy stability: stable test ID > accessible role/name > label > placeholder > exact text > constrained semantic CSS.
9. Reject dynamic code, unsupported syntax, XPath/positional/structural selectors, weak semantic overlap, ambiguity, and candidates chosen merely because they are nearby.
10. Create a proposal bound to verification evidence, exact Python test path, original locator, and expected file SHA-256.
11. Apply only the approved locator expression; the live agent has no generic existing-test rewrite tool.
12. Require patch-safety PASS for the changed path.
13. Require targeted pytest PASS whose selected path explicitly matches that exact mutation path.
14. Require full-regression pytest PASS at the same change revision.
15. Do not begin another mutation until the revision is closed.
16. Preserve before/after evidence and historical failures.

## Evidence requirements
Same-page screenshot plus accessibility/DOM evidence, Playwright-observed original/candidate match counts, deterministic semantic eligibility, deterministic failure classification, bound proposal, patch diff/hash evidence, exact-path targeted pytest evidence, and full-regression evidence.

## Allowed actions
Verify literal supported locators, propose semantic candidates, apply one policy-approved Python locator-only patch when writes are explicitly enabled, and run bounded deterministic validations.

## Prohibited shortcuts
Model-declared uniqueness/semantic authority, arbitrary executable locator code, generic text replacement, deleting/weakening assertions, expected=actual substitution, arbitrary sleeps, timeout inflation, skip/xfail, exception suppression, unrelated targeted pytest used as closure, or product-code mutation solely to make a test green.

## Validation requirements
Patch-safety PASS for the pending path + targeted pytest PASS explicitly selecting the same path + full-regression pytest PASS at the current revision. Same-revision contradictory PASS/FAIL evidence remains unresolved.

## Escalate
High/ambiguous risk, unsupported original intent, non-unique candidate, deterministic semantic mismatch, insufficient browser evidence, non-Python live mutation request, or required approval.

## Terminate
Return an allowed/denied proposal. An applied repair is trusted only after exact-subject current-revision deterministic closure.

## Output
Allowed/denied, risk, bound old/new locator, verification/proposal/patch evidence IDs, rationale, change revision, and deterministic validation outcome.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../../LICENSE`](../../../LICENSE).
