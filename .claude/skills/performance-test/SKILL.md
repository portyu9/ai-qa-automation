---
name: performance-test
description: Controlled k6 performance assessment with production-load and egress safety gates.
---
# Performance Test

> [!IMPORTANT]
> k6 executes JavaScript. Static script inspection is defense in depth, **not** a network sandbox. Every k6 run requires independently enforced deployment-level egress containment.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

## Use when
A bounded non-production workload and deterministic latency/error/request-rate thresholds are defined.

## Do not use when
The target is production, environment classification is unknown, workload is unbounded, k6/target access is unavailable, or deployment-level egress containment cannot be established.

## Inputs
Target environment/URL, k6 script, bounded workload definition, and p95/error/request-rate thresholds.

## Preconditions
The target is explicitly non-production; policy authorizes its exact host; k6 is installed; the script consumes injected `BASE_URL` / `TARGET_URL`; test data is safe; and trusted runtime configuration asserts that infrastructure-level egress enforcement is actually present (`AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true`).

The egress prerequisite applies to **every** target, including localhost, because arbitrary JavaScript can construct destinations dynamically.

## Workflow
1. Authorize environment and target URL deterministically.
2. Apply the canonical runtime host allowlist.
3. Require the trusted infrastructure-egress prerequisite for the workload.
4. Validate script path and injected target binding.
5. Recursively inspect bounded relative JavaScript imports.
6. Reject remote module imports, `k6/x/*` extensions, local-file reads, unsupported imports, and unrelated hard-coded external hosts.
7. Execute k6 with a restricted child environment, disabled usage reporting, bounded runtime, and summary artifacts outside the SUT workspace.
8. Capture p50/p90/p95/p99, request rate, and error rate.
9. Compare observed metrics with thresholds defined **before** execution.
10. Register normalized performance evidence and deterministic validation outcome.

## Evidence requirements
Target/environment, host/policy authorization, asserted deployment-egress prerequisite, script identity, measured metrics, predefined thresholds, breached thresholds, and resulting validation/evidence IDs.

## Allowed actions
Run a bounded k6 script against an authorized non-production target only when deployment-level egress containment has been independently established.

## Prohibited shortcuts
No production targeting, unknown environments, target substitution, threshold changes after results, model-only verdicts, remote/dynamic module escape, local-file reads, scripts that bypass injected target binding, or treating `AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true` as if the flag itself created a firewall.

## Validation requirements
A real k6 process result plus deterministic threshold assessment. Missing runtime, target, policy, or egress evidence remains `BLOCKED` / `NOT_VERIFIED` rather than PASS.

## Escalate
Unknown environment classification, unavailable runtime, missing real deployment egress enforcement, policy denial, or a workload whose safety cannot be established.

## Terminate
PASS/FAIL only from measured deterministic thresholds; otherwise `BLOCKED` / `NOT_VERIFIED`.

## Output
Outcome, target/environment, metrics, breached thresholds, evidence IDs, and explicitly observed limitations.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../../LICENSE`](../../../LICENSE).
