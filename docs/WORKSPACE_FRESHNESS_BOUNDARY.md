# Workspace Freshness Boundary

> [!IMPORTANT]
> **A validation result is never enough by itself to certify whatever bytes happen to occupy the target workspace later.** The live runtime accepts controlled execution, result evidence, and terminal `SUCCESS` only while the target still matches the framework-owned workspace fingerprint lineage.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Runtime control](RUNTIME_CONTROL.md) · [Result contract](RESULT_CONTRACT.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Purpose

The target repository is an untrusted mutable subject. A successful deterministic check can become stale if target bytes, Git metadata, the index, or changed-file state move after that check. The framework therefore separates two concepts that must not be conflated:

- **observation** — what a read-only tool saw at a point in time; and
- **workspace authority** — the exact fingerprint lineage that controlled execution and terminal truth are allowed to rely on.

A read-only observation can add evidence. It cannot advance workspace authority.

## Authoritative baseline

Runtime bootstrap records one content-sensitive repository fingerprint in `RuntimeControl.expected_workspace_fingerprint`. The fingerprint is produced by `RepositoryInspector` and binds the observed Git/worktree subject under the run's pinned workspace-root identity.

That expected fingerprint is an **authority baseline**, not an observation cache. It may advance only through framework-owned state transitions whose purpose is to change or restore the target:

- initial deterministic runtime bootstrap;
- an authorized autonomous mutation after PostToolUse has observed the candidate state completely;
- deterministic mutation commit/rollback closure; or
- owned crash/stale-mutation recovery.

Read-only repository inspection, browser/API observation, external MCP use, classification, validation, and other non-mutation work never replace the expected fingerprint merely because they observed newer bytes.

## Three freshness gates

Workspace freshness is re-proved at three independent boundaries.

### 1. Before controlled tool execution

The universal `PreToolUse` authority checks the current repository fingerprint against the expected runtime baseline after bounded tool-input validation and before request fingerprinting, policy evaluation, network-budget charging, mutation-budget charging, or controlled execution.

If the current subject cannot be bound safely, the request is denied. In particular:

- missing fingerprint baseline → `BLOCKED`;
- incomplete fingerprint coverage → `BLOCKED`;
- fingerprint mismatch / out-of-band workspace drift → `BLOCKED`;
- inability to revalidate repository/root subject identity safely → `INFRASTRUCTURE_FAILURE`.

The attempted tool call is still charged against the overall tool-attempt budget before this check. Stale-workspace retries therefore cannot be used to obtain free unbounded attempts. A freshness-denied external request does not consume network authority because no network action is allowed to begin.

`LiveRuntimeServices` independently repeats this check before an internal QA tool body. That second check is defense in depth for direct live-service invocation and for drift in the gap between the SDK hook and the internal body.

### 2. Before accepting a non-mutation tool result

A tool can begin against a fresh target and the workspace can still change while the tool is running. Therefore successful-looking non-mutation output is checked again in `PostToolUse` before it is accepted.

If freshness changed during execution:

- the tool result is rewritten to an error-shaped result;
- the tool is recorded as failed by runtime control;
- external MCP success is not promoted to provider `AVAILABLE` truth;
- no successful external MCP evidence is registered from that result;
- a validation-bearing tool receives an additional revision-bound `workspace_freshness=NOT_VERIFIED` validation gate; and
- terminal state is latched to a non-success truth according to the freshness failure category.

Internal non-mutation tools also re-prove freshness at their durable checkpoints. The PostToolUse check remains necessary because a final race still exists between the last internal checkpoint/tool return and SDK PostToolUse acceptance, and external MCP tools do not execute through the internal service checkpoint path.

### 3. Before terminal `SUCCESS`

Even a result accepted while the workspace was fresh can become stale after the final tool completes. A candidate terminal `SUCCESS` is therefore rechecked after unresolved-mutation rollback handling and immediately before terminal state is persisted.

Terminal mapping is conservative:

| Freshness observation | Terminal effect on candidate `SUCCESS` |
|---|---|
| exact complete fingerprint match | `SUCCESS` may remain eligible |
| missing authorized baseline | `BLOCKED` |
| complete fingerprint differs | `BLOCKED` |
| fingerprint observation incomplete | `NOT_VERIFIED` |
| repository/root subject cannot be revalidated safely | `INFRASTRUCTURE_FAILURE` |

This final gate does not manufacture success. All normal result-contract requirements still have to be satisfied independently.

## Mutation exception is narrow and explicit

Autonomous mutation tools are special only because their authorized purpose is to change target bytes.

Before the mutation body starts, the universal and live-service freshness checks must prove that the current workspace still matches the prior authorized baseline. `RuntimeControl.prepare_mutation` must then establish rollback/ownership authority.

While that one mutation body is active, its internal checkpoint does not demand equality with the old fingerprint; doing so would reject the very candidate change the policy just authorized. PostToolUse instead observes the complete candidate fingerprint and advances runtime authority only through the mutation transaction path. Incomplete candidate fingerprinting causes rollback and blocks further mutation authority rather than adopting an ambiguous state.

Mutation failure and rollback paths similarly refresh the baseline only after framework-owned restoration/closure logic has run. Read-only tools never receive this exception.

## Why repository inspection cannot rebase authority

`inspect_repository` is an observation tool. It may report that the repository changed, but it cannot make that change authorized.

If a target changes after a prior validation and a later inspection simply replaced `expected_workspace_fingerprint` with the newly observed value, stale validation lineage could appear current again without any policy-owned mutation or revalidation. The runtime therefore keeps observation and authority separate: inspection evidence may describe a different subject, while the expected fingerprint remains unchanged and later controlled work fails closed until a fresh run/authorized transition establishes new authority.

## Evidence semantics

A workspace fingerprint proves identity of the repository/worktree state covered by the bounded `RepositoryInspector` observation. It does **not** prove:

- that a validation itself was correct;
- that an external provider response is trustworthy;
- that deployment isolation exists;
- that another operating-system principal cannot write the workspace; or
- that a future target state will remain unchanged.

Those are separate trust domains. The freshness boundary only prevents evidence and terminal truth from silently floating from one observed target state to another.

## Concurrency and deployment boundary

The framework's workspace lease coordinates cooperating framework runs and pins the authorized workspace object where supported. It is not claimed to be an operating-system mandatory-write sandbox.

A non-cooperating process with independent write authority to the same target can still race the application. The pre-tool, internal-checkpoint, PostToolUse, and terminal gates detect such drift at their respective observation boundaries and fail closed when it is visible.

There is one unavoidable application-level window during an authorized mutation: the policy-owned mutation itself is expected to change the workspace, so the old fingerprint cannot remain equal while the mutation is in progress. Preventing an unrelated non-cooperating writer from changing a second path inside that exact window requires deployment-owned workspace/process isolation. The repository does not fabricate that infrastructure control from an application flag or advisory lock.

## Failure truth

Freshness failures are authority failures, not test passes:

- `BLOCKED` means required baseline/current-subject authority is absent or the target moved outside authorized lineage;
- `NOT_VERIFIED` means a candidate terminal success cannot be retained because complete current-subject proof is unavailable;
- `INFRASTRUCTURE_FAILURE` means the runtime could not safely re-establish the repository/root observation authority needed to decide freshness; and
- no freshness failure can be converted into `PASS`/`SUCCESS` by model output, external content, retries, or read-only observation.

---

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
