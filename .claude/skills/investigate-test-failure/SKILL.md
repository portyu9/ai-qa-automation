---
name: investigate-test-failure
description: Evidence-driven automated-test failure investigation and classification.
---
# Investigate Test Failure

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

## Use when
A test failed and the cause is unknown or contested.

## Do not use when
A deterministic gate already identifies a single syntax/configuration error requiring no additional reasoning.

## Inputs
Failed test identifier, target workspace, available artifacts, expected business behavior.

## Preconditions
Execution is isolated; evidence tools are available; target content is treated as untrusted data.

## Workflow
1. Reproduce once when safe and useful.
2. Collect independent evidence: assertion/stack, exit code, DOM/accessibility, network/console, relevant source/config.
3. Form competing hypotheses (product, test, locator contract, data, timing, environment, dependency, auth, configuration, performance).
4. Select the action that best discriminates between hypotheses; do not repeat an action that adds no information.
5. Classify only from evidence and cite evidence IDs.
6. Repair only if evidence shows a test defect and policy permits it.
7. Deterministically validate targeted behavior and relevant regression.

## Evidence requirements
Every material classification must reference evidence IDs. Model interpretation must not replace observed exit codes, HTTP responses, DOM/accessibility state, or test assertions.

## Allowed actions
Read approved test/source evidence; execute bounded tests; collect artifacts; classify; propose a repair.

## Prohibited shortcuts
Do not infer product defect from a test failure alone. Do not fabricate missing evidence, skip tests, weaken assertions, or hide failures.

## Validation requirements
Any repair needs targeted execution, relevant regression, and an intent-preservation check. Model completion alone cannot produce SUCCESS.

## Escalate
Ambiguous/conflicting evidence, prohibited repair, inaccessible required environment, or high-risk behavior change.

## Terminate
SUCCESS only after deterministic validation; otherwise FAILURE, BLOCKED, POLICY_DENIED, or INSUFFICIENT_EVIDENCE.

## Output
Classification, confidence, concise rationale, competing hypotheses, evidence IDs, validations, and limitations.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../../LICENSE`](../../../LICENSE).
