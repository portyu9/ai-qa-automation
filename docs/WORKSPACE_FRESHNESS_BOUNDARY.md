# Workspace Freshness Boundary

> [!IMPORTANT]
> **A validation result is never enough by itself to certify whatever bytes happen to occupy the target workspace later.** The live runtime keeps controlled execution and terminal `SUCCESS` bound to framework-owned workspace fingerprint lineage.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Runtime control](RUNTIME_CONTROL.md) · [Result contract](RESULT_CONTRACT.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Purpose

The target repository is an untrusted mutable subject. A successful deterministic check can become stale if target bytes, Git metadata, the index, or changed-file state move after that check. The framework therefore separates two concepts that must not be conflated:

- **observation** — what a read-only or external tool saw at a point in time; and
- **workspace authority** — the exact fingerprint lineage that controlled target execution and terminal truth are allowed to rely on.

A read-only observation can add evidence. It cannot advance workspace authority.

## Authoritative baseline

Runtime bootstrap records one content-sensitive repository fingerprint in `RuntimeControl.expected_workspace_fingerprint`. The fingerprint is produced by `RepositoryInspector` and binds the observed Git/worktree subject under the run's pinned workspace-root identity.

That expected fingerprint is an **authority baseline**, not an observation cache. It may advance only through framework-owned state transitions whose purpose is to change or restore the target:

- initial deterministic runtime bootstrap;
- an authorized autonomous mutation after PostToolUse has observed the candidate state completely;
- deterministic mutation commit/rollback closure; or
- owned crash/stale-mutation recovery.

Read-only repository inspection, browser/API observation, external MCP use, classification, validation, and other non-mutation work never replace the expected fingerprint merely because they observed newer bytes.

## Three freshness boundaries

Workspace freshness is re-proved at three independent target-authority boundaries.

### 1. Before controlled tool execution

Freshness admission deliberately does **not** run inside the bounded `PreToolUse` callback. `RepositoryInspector` has its own bounded Git-subprocess budgets, and nesting that observation inside a shorter SDK hook timeout would create a fragile timeout-dependent authorization path.

`PreToolUse` therefore remains responsible for bounded tool-input validation plus canonical attempt, repetition, network/mutation-budget, and policy accounting. Freshness is enforced at the execution boundary that actually owns each tool class:

- internal QA MCP tools are pre-approved by the SDK only because `LiveRuntimeServices` re-proves the current repository fingerprint at the first in-process tool-body checkpoint, before tool-specific side effects;
- for internal mutation tools, rollback/pending transaction authority is prepared **only after** that freshness proof succeeds, so already-drifted target bytes cannot become the rollback source for a new autonomous mutation;
- external MCP tools are not placed in `allowed_tools`; after deterministic policy allows a read-only operation, the independent `can_use_tool` permission callback re-proves workspace freshness before granting provider execution;
- external write/destructive/unknown operations are denied by deterministic policy before repository freshness observation, avoiding expensive subject work for requests that can never execute unattended.

If the current subject cannot be bound safely at an execution-owned freshness check:

- missing fingerprint baseline → `BLOCKED`;
- incomplete fingerprint coverage → `BLOCKED`;
- fingerprint mismatch / out-of-band workspace drift → `BLOCKED`;
- inability to revalidate repository/root subject identity safely → `INFRASTRUCTURE_FAILURE`.

A denied external request may already have its attempt/network budget conservatively reserved by `PreToolUse`; that accounting does not mean provider execution occurred. The permission callback denies before the provider action. Stale retries therefore cannot create free attempts.

### 2. Before accepting internal non-mutation target results

An internal validation/read tool can begin against a fresh target and the workspace can still change while it is running. Internal non-mutation tools therefore re-prove freshness at durable checkpoints, and `PostToolUse` re-proves freshness once more before a successful internal result can participate in deterministic closure.

If freshness changed before internal result acceptance:

- the tool result is rewritten to an error-shaped result;
- the tool is recorded as failed by runtime control;
- a validation-bearing tool receives an additional revision-bound `workspace_freshness=NOT_VERIFIED` validation gate; and
- terminal state is latched to a non-success truth according to the freshness failure category.

The final PostToolUse check closes the race between the last internal checkpoint/tool return and SDK result acceptance.

External MCP output is different. It is remote observed data, not local target-validation authority. External responses continue through their existing deterministic output-size, JSON-shape, sanitization, and untrusted-evidence boundary without first performing another potentially expensive repository snapshot inside `PostToolUse`. This avoids making remote-output sanitization depend on repository-snapshot latency. Later controlled work rechecks freshness, and candidate terminal `SUCCESS` is independently revalidated against the workspace baseline.

A remote result observed while local bytes changed can therefore remain recorded as sanitized **remote evidence**, but it cannot authorize or certify the changed local target and cannot preserve terminal `SUCCESS` for stale local bytes.

### 3. Before terminal `SUCCESS`

Even an internal result accepted while the workspace was fresh can become stale after the final tool completes. A candidate terminal `SUCCESS` is therefore rechecked after unresolved-mutation rollback handling and immediately before terminal state is persisted.

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

`PreToolUse` may reserve mutation budget and establish that deterministic policy allows the requested path, but it does not capture rollback bytes. At internal tool entry, `LiveRuntimeServices` first proves that the current workspace still matches the prior authorized baseline. Only then may `RuntimeControl.prepare_mutation` read the target and durably establish pending/rollback ownership. If freshness is missing, incomplete, unavailable, or drifted, no new pending transaction or rollback backup is created.

While that one prepared mutation body is active, its internal checkpoint does not demand equality with the old fingerprint; doing so would reject the very candidate change the policy just authorized. PostToolUse instead observes the complete candidate fingerprint and advances runtime authority only through the mutation transaction path. Incomplete candidate fingerprinting causes rollback and blocks further mutation authority rather than adopting an ambiguous state.

Mutation failure and rollback paths similarly refresh the baseline only after framework-owned restoration/closure logic has run. Read-only tools never receive this exception.

## Why repository inspection cannot rebase authority

`inspect_repository` is an observation tool. It may report that the repository changed, but it cannot make that change authorized.

If a target changes after prior validation and a later inspection simply replaced `expected_workspace_fingerprint` with the newly observed value, stale validation lineage could appear current again without any policy-owned mutation or revalidation. The runtime therefore keeps observation and authority separate: inspection evidence may describe a different subject, while the expected fingerprint remains unchanged and later controlled work fails closed until a fresh run or authorized transition establishes new authority.

## Evidence semantics

A workspace fingerprint proves identity of the repository/worktree state covered by the bounded `RepositoryInspector` observation. It does **not** prove:

- that a validation itself was correct;
- that an external provider response is trustworthy;
- that remote evidence describes local target bytes;
- that deployment isolation exists;
- that another operating-system principal cannot write the workspace; or
- that a future target state will remain unchanged.

Those are separate trust domains. The freshness boundary prevents target validation and terminal truth from silently floating from one observed local target state to another; external MCP evidence remains separately classified as untrusted remote observation.

## SDK permission and hook dependency boundary

The repository pins `claude-agent-sdk==0.2.136`, but it does not independently pin or attest a bundled Claude CLI sub-version or convert undocumented SDK hook/permission behavior into repository-owned authority. Exact protected validation must exercise the pinned dependency set's hook, auto-approval, and `can_use_tool` behavior; upstream documentation or historical fixes are not revision-bound repository evidence.

The design therefore avoids making repository freshness depend on the 10-second PreToolUse hook timeout. Internal tools enforce freshness inside application-owned code before their bodies proceed. External tools remain outside SDK auto-approval and receive the freshness decision through `can_use_tool` only after deterministic policy allows the operation. External writes retain the independent unattended permission denial, while internal high-impact tools continue to re-check their path/network/mutation/runner boundaries inside the in-process MCP server.

These are defense-in-depth controls; they do not make missing protected validation into PASS. The runtime also does not inflate hook or repository-inspection timeouts merely to obtain green execution.

PostToolUse external-response sanitization intentionally does not wait behind a repository snapshot. This preserves the existing deterministic remote-output boundary independently of workspace-fingerprint observation cost. Local target success remains protected by execution-owned and terminal freshness checks, while internal target-validation results retain the stronger post-execution acceptance check.

## Concurrency and deployment boundary

The framework's workspace lease coordinates cooperating framework runs and pins the authorized workspace object where supported. It is not claimed to be an operating-system mandatory-write sandbox.

A non-cooperating process with independent write authority to the same target can still race the application. Internal entry/checkpoint/PostToolUse gates, external permission admission, and terminal freshness detect such drift at their respective observation boundaries and fail closed when it is visible.

There is one unavoidable application-level window during an authorized mutation: the policy-owned mutation itself is expected to change the workspace, so the old fingerprint cannot remain equal while the mutation is in progress. Preventing an unrelated non-cooperating writer from changing a second path inside that exact window requires deployment-owned workspace/process isolation. The repository does not fabricate that infrastructure control from an application flag or advisory lock.

## Failure truth

Freshness failures are authority failures, not test passes:

- `BLOCKED` means required baseline/current-subject authority is absent or the target moved outside authorized lineage;
- `NOT_VERIFIED` means a candidate terminal success or internal validation result cannot be retained because complete current-subject proof is unavailable;
- `INFRASTRUCTURE_FAILURE` means the runtime could not safely re-establish the repository/root observation authority needed to decide freshness; and
- no freshness failure can be converted into `PASS`/`SUCCESS` by model output, external content, retries, or read-only observation.

---

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
