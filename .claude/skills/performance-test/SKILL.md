---
name: performance-test
description: Controlled k6 performance assessment with production-load and egress safety gates.
---
# Performance Test

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

## Use when
A bounded non-production workload and deterministic latency/error/request-rate thresholds are defined.

## Do not use when
The target is production, the environment classification is unknown, the workload is unbounded, or k6/target access is unavailable.

## Inputs
Target environment/URL, k6 script, workload definition in the script, and p95/error/request-rate thresholds.

## Preconditions
The target is explicitly classified as non-production; policy authorizes it; k6 is installed; the script uses injected `BASE_URL`/`TARGET_URL`; test data is safe. For a non-local target, trusted runtime configuration must also assert that infrastructure-level egress enforcement is present (`AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true`).

## Workflow
1. Authorize the environment and target URL deterministically.
2. Apply the runtime host allowlist.
3. For non-local targets, require the trusted infrastructure-egress precondition.
4. Validate the script path and injected target binding.
5. Recursively inspect bounded relative JavaScript imports.
6. Reject remote module imports, `k6/x/*` extensions, local-file reads, and unrelated hard-coded external hosts.
7. Execute k6 with a restricted child environment, disabled usage reporting, an execution timeout, and runtime artifacts outside the SUT workspace.
8. Capture p50/p90/p95/p99, request rate, and error rate.
9. Compare observed metrics with thresholds defined before execution.
10. Register normalized performance evidence and validation status.

## Evidence requirements
Target/environment, policy authorization, script identity, measured metrics, predefined thresholds, breached thresholds, and resulting validation/evidence IDs.

## Allowed actions
Run a bounded k6 script against localhost/reference SUT or an approved non-production external target whose infrastructure egress guard has been explicitly asserted.

## Prohibited shortcuts
No production targeting, unknown environments, target substitution, threshold changes after results, model-only verdicts, remote/dynamic module escape, local-file reads, or scripts that bypass the injected target URL.

## Validation requirements
A real k6 process result plus deterministic threshold assessment. Missing k6/runtime or external-egress evidence remains `NOT_VERIFIED`/blocked rather than PASS.

## Escalate
Unknown environment classification, unavailable runtime, missing external-egress enforcement, policy denial, or a workload whose safety cannot be established.

## Terminate
PASS/FAIL only from measured deterministic thresholds; otherwise `BLOCKED`/`NOT_VERIFIED`.

## Output
Status, target/environment, metrics, breached thresholds, evidence IDs, and explicitly observed limitations.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../../LICENSE`](../../../LICENSE).
