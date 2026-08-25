# Pytest Execution Isolation

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Security](SECURITY.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md) · [Result contract](RESULT_CONTRACT.md)

---

## Why this boundary exists

The live `run_pytest` tool executes Python from the **target repository**. That code is untrusted target/SUT content, not framework control-plane code.

A restricted environment, bounded timeout, process-tree cleanup, selector validation, and before/after Git workspace fingerprinting are useful controls, but they are **not a process sandbox**. Without infrastructure containment, target test code could still attempt to:

- read or write paths outside the target workspace;
- inspect host-level environment/process state that survived sanitization;
- create child processes;
- open sockets directly instead of using framework network adapters;
- interact with other host resources available to the runner identity.

Workspace-integrity validation detects target-workspace drift after execution. It does not retroactively prevent access to unrelated host resources.

---

## Fail-closed live-runtime contract

The Agent SDK live path refuses `run_pytest` unless **both** trusted deployment assertions are true:

```text
AI_QA_PYTEST_PROCESS_ISOLATION_ENFORCED=true
AI_QA_PYTEST_EXTERNAL_EGRESS_ENFORCED=true
```

Both default to `false`.

Before the pytest runner is reached, `LiveRuntimeServices` checks the two assertions. If either is false, the runtime:

1. does **not** invoke `TestRunner`;
2. records a current-revision `pytest` validation with `BLOCKED` status;
3. binds that record to the same stable pytest gate identity and scope that execution would have used;
4. records `execution_started=false` plus the two prerequisite states;
5. latches the run terminal status to `BLOCKED`;
6. persists the state before returning the tool error.

A model cannot convert that block into PASS, and later advisory work cannot erase the terminal block.

The two settings are part of the normal `Settings` model, so their values are included in the run configuration fingerprint.

---

## What the assertions mean

### Process/filesystem isolation

`AI_QA_PYTEST_PROCESS_ISOLATION_ENFORCED=true` may be set only when the deployment actually confines target pytest execution so target code cannot freely traverse the runner host or reach trusted framework/control/evidence roots outside the intended execution boundary.

Examples of infrastructure mechanisms that can contribute to this guarantee include a dedicated container/VM/sandbox, constrained mounts, non-root execution, namespace or equivalent process isolation, and narrowly scoped filesystem access. The exact mechanism is deployment-owned.

### Outbound-egress enforcement

`AI_QA_PYTEST_EXTERNAL_EGRESS_ENFORCED=true` may be set only when the deployment actually constrains outbound connections made by the pytest process and its descendants.

`AI_QA_ALLOWED_NETWORK_HOSTS` and `AI_QA_ALLOW_EXTERNAL_NETWORK` are **not sufficient** for this assertion. Those settings govern controlled framework adapters. Arbitrary target Python can create sockets without going through those adapters, so pytest egress must be enforced outside the Python process—for example by container/network namespace, firewall, proxy, or equivalent infrastructure policy.

If tests legitimately require a target service, the deployment egress policy must permit only the intended test endpoints and still deny unrelated destinations.

---

## What the flags do not prove

The flags are trusted **prerequisite assertions**. They do not create or inspect the sandbox, firewall, namespace, VM, container security context, or organization policy themselves.

Setting a flag to `true` without the corresponding infrastructure control is a deployment misconfiguration. Repository code cannot transform that assertion into independent infrastructure evidence.

The framework therefore distinguishes:

- **repository proof:** the live runtime fails closed when the assertion is absent;
- **configuration provenance:** the asserted values are bound into the run configuration fingerprint;
- **deployment proof:** the organization/platform must independently establish that the asserted isolation actually exists.

---

## Relationship to repository CI

This guard applies to the **live Agent SDK `run_pytest` tool**, where the framework may execute code from an arbitrary target repository.

The repository's own GitHub Actions pytest jobs validate this framework's checked-in source in the CI trust context. They are not treated as evidence that a future deployment sandbox exists, and they do not require these live-runtime assertions merely to execute the framework's own test suite.

---

## Relationship to k6

k6 already has a separate fail-closed infrastructure assertion:

```text
AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true
```

That setting remains k6-specific. Pytest requires two independent assertions because arbitrary Python has a broader process/filesystem authority surface in addition to network egress.

---

## Operator checklist

Before enabling live pytest execution, verify that:

1. target code executes inside a deployment-owned containment boundary;
2. trusted control/evidence/secrets and unrelated host paths are outside that boundary or inaccessible;
3. child processes inherit the containment policy;
4. outbound network policy is enforced below the Python application layer;
5. only intended non-production test destinations are reachable when network access is required;
6. the runtime identity is least-privileged;
7. setting both assertions to `true` is backed by deployment evidence, not convenience.

If any item is unknown, leave the corresponding assertion `false`. `BLOCKED` is the correct runtime truth.

---

[← Documentation home](README.md) · [Verification boundaries →](VERIFICATION_BOUNDARIES.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
