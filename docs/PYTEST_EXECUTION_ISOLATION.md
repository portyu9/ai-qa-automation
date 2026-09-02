# Pytest Execution Isolation

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Security](SECURITY.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md) · [Result contract](RESULT_CONTRACT.md)

---

## Why this boundary exists

The live `run_pytest` tool executes Python from the **target repository**. That code is untrusted target/SUT content, not framework control-plane code.

A restricted environment, bounded timeout, process-tree cleanup, selector validation, and before/after Git workspace fingerprinting are useful controls, but they are not a process sandbox. Target test code can otherwise attempt to read unrelated host paths, inspect host process state, create child processes, or open sockets directly instead of using framework network adapters.

Workspace-integrity validation detects target-workspace drift after execution. It does not retroactively prevent access to unrelated host resources.

---

## Live-runtime contract

Live target pytest now requires **both deployment intent and an observed sandbox capability proof**.

The existing trusted intent assertions remain explicit:

```text
AI_QA_PYTEST_PROCESS_ISOLATION_ENFORCED=true
AI_QA_PYTEST_EXTERNAL_EGRESS_ENFORCED=true
```

Both default to `false`, but setting them to `true` is no longer sufficient to execute pytest.

When both assertions are present, `LiveRuntimeServices` invokes the concrete `TestRunner` sandbox preflight. The initial supported backend is Linux Bubblewrap (`bwrap`). The preflight must complete successfully immediately before the tool body is admitted. `TestRunner` then repeats the sandbox proof on its own execution path; there is no direct-host fallback if the live-service boundary is bypassed or races with backend loss.

If intent is missing, Bubblewrap is unavailable, the kernel refuses the required namespaces, the sandbox executable is ambiguous/changed, or any capability observation is incomplete, the live runtime records a current-revision pytest validation as `BLOCKED`, sets `execution_started=false`, latches terminal `BLOCKED`, persists state, and does not invoke target pytest.

---

## Bubblewrap authority

Bubblewrap is used because it starts from an empty filesystem namespace and can construct a narrow target execution view without giving target code the host root filesystem.

The repository-owned command contract requires:

- a new user namespace;
- further user-namespace creation disabled and explicitly re-asserted inside the sandbox;
- separate PID, network, IPC, and UTS namespaces;
- a new mount namespace (Bubblewrap's normal execution model);
- all effective capabilities dropped;
- a new terminal session and parent-death cleanup;
- a fresh `/proc` scoped to the sandbox PID namespace;
- a fresh minimal `/dev`;
- private writable tmpfs for `/tmp` and `/home`, each size-bounded to 64 MiB;
- only Python runtime/system executable/library roots mounted read-only;
- the target workspace mounted read-only at `/workspace`;
- no host-root bind and no evidence-root bind;
- a cleared environment rebuilt from a small deterministic set;
- no host network namespace (`--unshare-net`), with the probe requiring no non-loopback interface;
- bounded stdout/stderr, wall time, and process-tree cleanup through the existing subprocess authority;
- hard pre-exec resource ceilings: at most 16 processes for the runtime identity, 512 MiB virtual address space per process, 64 MiB per regular output file, 256 open descriptors, no core dumps, and a CPU-time ceiling tied to the tool timeout.

The target workspace remains read-only even when autonomous test-writing is enabled. Framework-owned mutations happen through the separate transaction/rollback authority, never from pytest itself.

---

## Capability proof

A successful preflight is more than successful `bwrap --version` output.

The sandbox launches a repository-owned isolated Python probe and requires all of the following before target execution can be admitted:

1. mount, PID, network, and user namespace identities differ from the controller process;
2. a write attempt inside `/workspace` is rejected and leaves no host-side probe file;
3. the evidence root is not visible from the sandbox filesystem;
4. no non-loopback network interface is visible;
5. effective Linux capabilities are zero;
6. the Bubblewrap executable remains the same regular-file identity and SHA-256 before and after the probe.

Actual pytest execution uses the same command builder. Immediately before `exec`, the trusted guard revalidates namespace/workspace/network/capability facts and lowers hard Linux `RLIMIT_*` ceilings; failure to apply those ceilings exits through the sandbox-authority code instead of starting pytest. Bubblewrap's `--json-status-fd` channel must prove that the sandbox child started. On non-timeout completion, its reported child exit code must equal the controller's observed process result. Missing, malformed, contradictory, or oversized status evidence cannot become a pytest result.

The observed Bubblewrap path, version, SHA-256, namespace identities, capability facts, configured process/memory/file/descriptor/tmpfs ceilings, and execution CPU ceiling are persisted with pytest evidence. These fields bind what was observed; they are not a claim that the host package manager or kernel is immutable.

The `RLIMIT_*` ceilings are per-process/runtime-identity controls inherited by descendants inside the sandbox. They are not cgroup quotas, aggregate host resource attestation, or proof that other workloads on the host cannot consume resources. Deployments that require stronger aggregate CPU/memory/I/O guarantees must add environment-owned cgroup/VM/container limits outside this repository boundary.

---

## Why the two assertions still exist

The repository can prove that its selected process actually entered the configured sandbox. It cannot determine whether an organization intended that particular deployment to enable target-code execution.

The two existing assertions therefore remain **operator intent gates**, while the Bubblewrap preflight is the **execution capability gate**. Neither substitutes for the other:

```text
trusted deployment intent
+ concrete sandbox capability proof
+ sandboxed target execution
+ unchanged exact workspace subject
= eligible pytest validation evidence
```

A boolean can no longer turn missing isolation into execution authority.

---

## Environment boundary

Bubblewrap and the Linux namespace features it uses are deployment inputs. The repository does not install Bubblewrap with a privileged package-manager step during untrusted PR CI and does not expose a Docker socket as a fallback.

If a deployment or validation host does not provide a usable `bwrap`, live target pytest remains `BLOCKED`. That is a truthful unavailable capability, not a reason to fall back to direct host execution.

The framework also does not claim that observing a Bubblewrap SHA-256 establishes package publisher identity, kernel integrity, VM isolation, or host attestation. Those remain deployment/supply-chain concerns.

---

## Relationship to repository CI

The sandbox guard applies to the **live Agent SDK `run_pytest` tool**, where the framework may execute code from an arbitrary target repository.

The repository's own GitHub Actions pytest jobs validate this framework's checked-in source in the CI trust context. They do not become evidence that a future deployment has Bubblewrap or namespace support. Repository CI does not install the sandbox backend with privileged or mutable package-manager steps merely to manufacture a live-sandbox PASS.

Unit/adversarial tests therefore verify the sandbox command, preflight protocol, child-start status binding, fail-closed behavior, and no-direct-host invariant deterministically. A real Bubblewrap execution is additional environment evidence only when the host already provides the backend.

---

## Relationship to k6

k6 has its own execution-authority contract because JavaScript module loading, runner resource ceilings, target workload limits, and performance-target semantics differ from pytest. Pytest isolation does not authorize k6, and k6's egress assertion does not authorize pytest.

---

## Operator checklist

Before enabling live pytest execution, verify that:

1. both pytest intent assertions are explicitly enabled for the deployment;
2. the trusted host provides a non-target-controlled Bubblewrap executable;
3. unprivileged user namespaces and the required Bubblewrap lockdown operations are permitted;
4. framework evidence/control roots are outside the sandbox filesystem view;
5. target dependencies required by pytest are present in the read-only interpreter/runtime roots;
6. tests do not require external network access, because the initial sandbox intentionally provides no host/external network namespace;
7. the runtime identity is least-privileged and the fixed pytest resource ceilings are appropriate for the target test workload;
8. the persisted preflight/evidence records show the required namespace, filesystem, network, capability, and resource-policy facts.

If any item is unknown, leave execution blocked. `BLOCKED` is the correct runtime truth.

---

[← Documentation home](README.md) · [Verification boundaries →](VERIFICATION_BOUNDARIES.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
