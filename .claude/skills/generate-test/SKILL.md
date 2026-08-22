---
name: generate-test
description: Coverage-aware AI-assisted test design and implementation.
---
# Generate Test

> [!IMPORTANT]
> Observed repository coverage is evidence. The test plan is model interpretation. Unsupported “already covered” labels cannot suppress deterministic candidate scenarios.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

## Use when
A requirement, defect, API contract, or source change has a meaningful automated-coverage gap.

## Do not use when
Existing evidence proves the behavior at an appropriate layer, authoritative expected behavior is unknown, or required setup cannot be isolated safely.

## Inputs
Requirement/acceptance criteria, defect or source change, API contract when relevant, repository conventions, and observed coverage-search evidence.

## Preconditions
Authoritative expected behavior is identified; repository coverage can be searched through the bounded read-only tool; and the selected test layer can be executed or its runtime limitation can be reported explicitly.

## Workflow
1. Understand expected behavior and risk.
2. Run `search_test_coverage` and retain its evidence ID.
3. Interpret observed coverage and identify deterministic candidate gaps.
4. Call `plan_tests` with that **same-run** coverage evidence; choose the lowest reliable layer that proves the behavior.
5. Treat interpreted `already covered` labels as advisory only; unsupported labels cannot suppress deterministic candidates.
6. Design relevant happy, negative, boundary, authorization, state, error, contract, and data scenarios without permutation for its own sake.
7. Reconcile candidate scenarios against same-run observed coverage before implementation so redundant coverage is avoided without unsafe under-coverage.
8. Create a test only from the grounded same-run plan evidence.
9. Run deterministic syntax/quality checks and appropriate execution/regression evidence.
10. If the live runtime mutates an approved Python test path, require patch-safety PASS, targeted pytest PASS explicitly selecting that exact changed path, and full-regression PASS at the current change revision.
11. Do not perform another mutation until the current revision is closed.

Prefer unit/component/API/integration over UI when that layer proves behavior reliably.

## Evidence requirements
Requirement/change provenance, `repository_test_coverage_search` evidence, plan evidence bound to that search, generated-file diff/hash evidence, meaningful-assertion review, and deterministic execution/validation evidence.

## Allowed actions
Search bounded test coverage; inspect approved source/tests/contracts; create a grounded plan; create a policy-approved test file from that plan; execute bounded tests; run deterministic quality validation.

Reusable patch/generation components may understand Python/JavaScript/TypeScript test artifacts. Live autonomous commit authority remains intentionally Python/pytest-backed unless an equivalent controlled execution/closure adapter exists.

## Prohibited shortcuts
Invented coverage claims, model-declared coverage suppressing deterministic candidates without evidence, plan-less creation, assertion-free tests, snapshot-everything tests, arbitrary sleeps, `.skip` / `.only`, timeout inflation, redundant E2E coverage, duplicated proven coverage, or tests that only prove mocks were called.

## Validation requirements
For a live autonomous Python mutation: patch-safety PASS for the changed path + targeted pytest PASS whose selected path is that exact mutation + full-regression PASS at the current revision, with meaningful assertion review.

For other generated artifacts, report only the deterministic validation actually available for that ecosystem; do not represent pytest as proof of non-Python bytes.

## Escalate
Unclear requirement, unknown authoritative behavior, unsafe setup, conflicting coverage evidence, unsupported execution environment, or inability to obtain required deterministic validation.

## Terminate
Complete when the gap is covered and deterministically validated for its actual execution boundary, or explicitly `BLOCKED` / `NOT_VERIFIED` with missing evidence identified.

## Output
Coverage-search evidence ID, gap, plan evidence ID, selected layer/rationale, scenarios, implementation evidence, execution result, change revision when applicable, and validation outcome.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../../LICENSE`](../../../LICENSE).
