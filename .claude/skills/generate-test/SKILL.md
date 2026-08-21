---
name: generate-test
description: Coverage-aware AI-assisted test design and implementation.
---
# Generate Test

## Inputs
Requirement/acceptance criteria, defect or change diff, API contract, existing coverage, repository conventions.

## Workflow
UNDERSTAND → IDENTIFY RISK → SEARCH COVERAGE → IDENTIFY GAP → SELECT LOWEST RELIABLE LAYER → DESIGN → IMPLEMENT → EXECUTE → VALIDATE QUALITY.

Prefer unit/component/API/integration over UI when that layer proves the behavior reliably. Cover relevant happy, negative, boundary, authorization, state, error, contract, and data cases—not permutations for their own sake.

Generated tests must be non-duplicative, deterministic, isolated, convention-aligned, meaningful in assertions, and responsible for cleanup. Where safely practical, prove sensitivity with a controlled defect/fixture/mutation.

## Prohibited shortcuts
No assertion-free tests, snapshot-everything tests, arbitrary sleeps, redundant E2E coverage, or tests that only prove mocks were called.

## Escalate
Unclear requirement, unknown authoritative behavior, unsafe setup, or inability to execute validation.

## Output
Coverage gaps, chosen layer with rationale, scenarios, implementation changes, execution evidence, validation status.
