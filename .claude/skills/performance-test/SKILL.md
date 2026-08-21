---
name: performance-test
description: Controlled k6 performance assessment with production-load safety gate.
---
# Performance Test

## Inputs
Target environment/URL, workload, VUs/concurrency, duration, ramp profile, abort thresholds, latency/error thresholds.

## Preconditions
Target is explicitly classified; policy authorizes load; k6 is installed; test data and cleanup are safe.

## Workflow
1. Deny production by default.
2. Validate workload bounds before execution.
3. Execute k6 with explicit timeout/abort behavior.
4. Capture p50/p90/p95/p99, request rate/throughput, and error rate.
5. Deterministically compare measured metrics with predefined thresholds.
6. Preserve raw summary artifact and normalized assessment.

## Prohibited shortcuts
No accidental production targeting, unlimited duration/VUs, threshold changes after results, or model-only performance verdicts.

## Output
PASS/FAIL/NOT_VERIFIED/BLOCKED, metrics, breached thresholds, evidence/artifact references, limitations.
