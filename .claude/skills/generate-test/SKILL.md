---
name: generate-test
description: Coverage-aware AI-assisted test design and implementation.
---
# Generate Test

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

## Use when
A requirement, defect, API contract, or source change has a meaningful automated-coverage gap.

## Do not use when
Existing tests already prove the behavior at an appropriate layer, the expected behavior is unknown, or required setup cannot be isolated safely.

## Inputs
Requirement/acceptance criteria, defect or source change, API contract when relevant, repository conventions, and observed coverage-search evidence.

## Preconditions
The authoritative expected behavior is identified; repository coverage can be searched through the bounded read-only coverage tool; and the selected test layer can be executed or its runtime limitation can be reported explicitly.

## Workflow
1. Understand the expected behavior and risk.
2. Run `search_test_coverage` against the target repository and retain its evidence ID.
3. Interpret the observed coverage and identify the actual gap.
4. Call `plan_tests` with that same-run coverage evidence; choose the lowest reliable layer that proves the behavior.
5. Design relevant happy, negative, boundary, authorization, state, error, contract, and data scenarios without generating permutations for their own sake.
6. Create a test only from the same-run plan evidence; test creation is not authorized from an ungrounded model proposal.
7. Run deterministic syntax/quality checks, targeted execution, and relevant regression.
8. Do not perform another mutation until the current change revision is closed.

Prefer unit/component/API/integration over UI when that layer proves the behavior reliably.

## Evidence requirements
Requirement/change provenance, `repository_test_coverage_search` evidence, plan evidence bound to that search, generated-file diff/hash evidence, and deterministic execution/validation evidence.

## Allowed actions
Search bounded test coverage; inspect approved source/tests/contracts; create a grounded plan; create a policy-approved test file from that plan; execute bounded tests; run deterministic quality validation.

## Prohibited shortcuts
Invented coverage claims, plan-less file creation, assertion-free tests, snapshot-everything tests, arbitrary sleeps, `.skip`/`.only`, timeout inflation, redundant E2E coverage, duplicated existing coverage, or tests that only prove mocks were called.

## Validation requirements
Patch-safety PASS plus targeted deterministic execution and relevant full regression at the current revision, with meaningful assertion review.

## Escalate
Unclear requirement, unknown authoritative behavior, unsafe setup, conflicting coverage evidence, or inability to execute required validation.

## Terminate
Complete when the gap is covered and deterministically validated, or explicitly `BLOCKED`/`NOT_VERIFIED` with the missing evidence identified.

## Output
Coverage-search evidence ID, coverage gap, plan evidence ID, selected layer/rationale, scenarios, implementation evidence, execution result, revision, and validation status.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../../LICENSE`](../../../LICENSE).
