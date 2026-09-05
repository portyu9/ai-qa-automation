---
name: generate-test
description: Coverage-aware AI-assisted test design and proposal.
---
# Generate Test

> [!IMPORTANT]
> Observed repository coverage is evidence. The test plan is model interpretation. Unsupported “already covered” labels cannot suppress deterministic candidate scenarios. Generic generated source remains a proposal unless a separate deterministic semantic implementation gate or explicit human approval authorizes mutation.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

## Use when
A requirement, defect, API contract, or source change has a meaningful automated-coverage gap that should be investigated and designed as a test scenario.

## Do not use when
Existing evidence proves the behavior at an appropriate layer, authoritative expected behavior is unknown, or required setup cannot be isolated safely.

## Inputs
Requirement/acceptance criteria, defect or source change, API contract when relevant, repository conventions, and observed coverage-search evidence.

## Preconditions
Authoritative expected behavior is identified; repository coverage can be searched through the bounded read-only tool; and the selected test layer can be reasoned about without treating model interpretation as execution or correctness proof.

## Workflow
1. Understand expected behavior and risk.
2. Run `search_test_coverage` and retain its evidence ID.
3. Interpret observed coverage and identify deterministic candidate gaps.
4. Call `plan_tests` with that **same-run** coverage evidence; choose the lowest reliable layer that would prove the behavior.
5. Treat interpreted `already covered` labels as advisory only; unsupported labels cannot suppress deterministic candidates.
6. Design relevant happy, negative, boundary, authorization, state, error, contract, and data scenarios without permutation for its own sake.
7. Reconcile candidate scenarios against same-run observed coverage so redundant coverage is avoided without unsafe under-coverage.
8. Submit proposed source through `create_test_file` using the exact grounded plan evidence. The current generic path records a content/path/scenario/repository-bound proposal and does **not** write repository bytes.
9. Require deterministic syntax, path, meaningful-assertion, no-overwrite, and unsafe-diff checks before a proposal is recorded. These checks prove static safety only; they do not prove semantic coverage.
10. Do not claim mutation, execution, or coverage PASS from a proposal. Generic mutation remains denied until a target-specific deterministic semantic implementation gate or explicit human approval exists.
11. If a future separately authorized mutation path changes a Python test, preserve the existing independent closure requirements: patch-safety PASS, trusted exact-path executed-test authority, and full-regression PASS at the current change revision before another mutation.

Prefer unit/component/API/integration over UI when that layer would prove behavior reliably.

## Evidence requirements
Requirement/change provenance, exact `repository_test_coverage_search` evidence, plan evidence bound to that search and repository subject, stable selected scenario/assertion-contract identity, proposed path/content hash, static-safety validation, and an explicit record that semantic implementation and mutation authority are absent.

## Allowed actions
Search bounded test coverage; inspect approved source/tests/contracts; create a grounded plan; submit policy-bounded generated source as a proposal; run deterministic static proposal checks; report the exact missing authority required before mutation.

Reusable patch/generation components may understand Python/JavaScript/TypeScript test artifacts. That syntax support does not grant live autonomous commit authority. The current generic generated-test path is proposal-only.

## Prohibited shortcuts
Invented coverage claims, model-declared coverage suppressing deterministic candidates without evidence, plan-less proposals, assertion-free tests, snapshot-everything tests, arbitrary sleeps, `.skip` / `.only`, timeout inflation, redundant E2E coverage, duplicated proven coverage, tests that only prove mocks were called, or treating a syntactically safe/passing-looking proposal as semantic coverage proof.

## Validation requirements
For the current generic generated-test path: exact requirement/coverage/plan/scenario/repository binding + deterministic static proposal safety. The result remains semantically unverified and non-mutating.

If a separate future authority permits a live autonomous Python mutation, patch-safety, trusted exact-path executed-test proof, full-regression closure, and objective closure remain independent requirements; proposal evidence cannot substitute for any of them.

For non-Python proposed artifacts, report only the deterministic static validation actually available for that ecosystem; do not represent pytest as proof of non-Python bytes.

## Escalate
Unclear requirement, unknown authoritative behavior, unsafe setup, conflicting or incomplete coverage evidence, stale repository subject, unsupported execution environment, or absence of a deterministic semantic implementation authority when mutation is requested.

## Terminate
Complete the current Skill when a bound proposal is recorded and its missing semantic/mutation authority is stated, or explicitly `BLOCKED` / `NOT_VERIFIED` with missing evidence identified. Do not claim the coverage gap is closed merely because a proposal exists.

## Output
Coverage-search evidence ID, requirement provenance/digest, plan evidence ID, selected scenario/layer/rationale, proposal subject/path/content hash, static-safety result, repository subject, and explicit semantic/mutation authority status.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../../LICENSE`](../../../LICENSE).
