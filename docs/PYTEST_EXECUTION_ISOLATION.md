# Pytest Execution Isolation

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Security](SECURITY.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md) · [Result contract](RESULT_CONTRACT.md)

---

## Why this boundary exists

The live `run_pytest` tool executes Python derived from the **target repository**. That code is untrusted target/SUT content, not framework control-plane code.

A restricted environment, bounded timeout, process-tree cleanup, selector validation, and before/after Git workspace fingerprinting are useful controls, but they are not a process sandbox. Target test code can otherwise attempt to read unrelated host paths, inspect host process state, create child processes, or open sockets directly instead of using framework network adapters.

Workspace-integrity validation detects drift in the repository subject covered by its fingerprint. It does not retroactively prevent access to unrelated host resources, and ordinary Git-ignored host bytes are intentionally outside that repository fingerprint. Live pytest therefore combines a frozen execution subject with OS isolation instead of treating ignored host bytes as freshness-certified.

---

## Live-runtime contract

Live target pytest requires **deployment intent, a provenance-bound execution subject, and an observed sandbox capability proof**.

The existing trusted intent assertions remain explicit:

```text
AI_QA_PYTEST_PROCESS_ISOLATION_ENFORCED=true
AI_QA_PYTEST_EXTERNAL_EGRESS_ENFORCED=true
```

Both default to `false`, but setting them to `true` is not sufficient to execute pytest.

When both assertions are present, `LiveRuntimeServices` invokes the concrete `TestRunner` sandbox preflight. The initial supported backend is Linux Bubblewrap (`bwrap`). That admission preflight executes only the repository-owned isolation probe; it does not execute target code. `TestRunner` then freezes the admissible repository bytes and repeats the sandbox proof on the actual materialized execution tree immediately before pytest. There is no direct-host fallback if the live-service boundary is bypassed, subject materialization cannot be proven, or the backend races with loss of authority.

If intent is missing, the repository subject is non-Git/incomplete, materialization is ambiguous, Bubblewrap is unavailable, the kernel refuses the required namespaces, the sandbox executable is ambiguous/changed, the source workspace could reappear through an exposed runtime root, or any required capability observation is incomplete, the live runtime records the pytest validation as `BLOCKED`, sets `execution_started=false`, latches terminal `BLOCKED`, persists state, and does not invoke target pytest.

---

## Frozen execution subject

Before target pytest starts, `TestRunner` obtains a complete Git-backed `RepositorySnapshot` and constructs a fresh controller-owned temporary tree. The tree is not a copy of every host path beneath the target directory. It is a bounded execution subject whose membership is derived from repository authority:

- stage-zero tracked regular files enter the tree;
- non-ignored untracked regular files already represented by the repository snapshot may enter;
- physical changed paths already represented by the fingerprint remain eligible, including the staged-delete plus ignored-replacement edge case;
- ordinary Git-ignored paths are absent;
- `.git` metadata is absent;
- symlinks, submodules, other non-regular tracked entries, unsafe paths, incomplete subjects, disappearing inputs, and path/file/aggregate bound violations fail closed.

The raw Git index is read through confined metadata authority. Its exact bytes are checksum-validated and parsed directly for supported index versions and object formats; the SHA-256 of those same bytes is already part of the repository fingerprint. Split indexes and unknown mandatory lowercase index extensions are rejected instead of being interpreted incompletely. Optional uppercase extensions may be skipped because they do not redefine the stage-zero entries consumed by this boundary. This avoids trusting a separate live `git ls-files --stage` enumeration for tracked OIDs or modes. Unchanged tracked content must reproduce its index blob OID. Changed/untracked copied bytes must reconstruct the exact authorized repository fingerprint, and the source snapshot must still match after materialization.

Executable authority is stricter than ordinary content inclusion. A tracked file may be executable only when the stage-zero Git index binds mode `100755`, and the observed worktree executable bit must agree. An unstaged executable-mode divergence therefore blocks. A path without a stage-zero index entry may enter only as non-executable; executable untracked or executable physical-replacement content blocks because the repository fingerprint does not independently bind that execution mode. Staged mode changes remain admissible because the index binds them.

The materialized tree receives fresh files rather than source hardlinks, is mounted read-only for target execution, and is removed after the run. Pytest evidence records the source Git SHA/fingerprint plus the frozen subject digest, file count, total bytes, and the facts that ordinary ignored inputs and Git metadata were excluded. Those fields bind the constructed execution subject; they do not claim excluded host bytes were immutable or observed.

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
- the **frozen materialized execution tree**, not the mutable source workspace, mounted read-only at `/workspace`;
- no host-root bind and no evidence-root bind;
- no runtime-root mount that overlaps the original source workspace; such overlap blocks execution rather than re-exposing source bytes at another host path;
- a cleared environment rebuilt from a small deterministic set;
- no host network namespace (`--unshare-net`), with the probe requiring no non-loopback interface;
- bounded stdout/stderr, wall time, and process-tree cleanup through the existing subprocess authority;
- hard pre-exec `RLIMIT_*` values for CPU time, virtual address space, output-file size, open descriptors, core dumps, and `RLIMIT_NPROC=16`; the process-count limit remains subject to Linux real-UID/capability enforcement semantics rather than constituting a cgroup task quota.

The frozen pytest subject remains read-only even when autonomous test-writing is enabled. Framework-owned mutations happen through the separate transaction/rollback authority against the source workspace, never from pytest itself.

Custom sandbox injection is also fail-closed: the factory must explicitly bind the supplied materialized workspace and attest that the original source workspace is hidden. A custom sandbox that cannot establish both facts is not allowed to execute target pytest.

---

## Capability proof

A successful preflight is more than successful `bwrap --version` output.

The sandbox launches a repository-owned isolated Python probe and requires all of the following before target execution can be admitted:

1. mount, PID, network, user, IPC, and UTS namespace identities differ from the controller process;
2. a write attempt inside `/workspace` is rejected and leaves no host-side probe file;
3. the evidence root is disjoint from the mounted workspace and is not visible from the sandbox filesystem;
4. no non-loopback network interface is visible;
5. effective Linux capabilities are zero;
6. the Bubblewrap executable remains the same regular-file identity and SHA-256 before and after the probe.

For actual target execution, `/workspace` is the frozen materialized tree. Immediately before `exec`, the trusted guard revalidates all six namespace identities plus workspace/network/capability facts and lowers the configured Linux `RLIMIT_*` values; failure to apply those limits exits through the sandbox-authority code instead of starting pytest. Bubblewrap's `--json-status-fd` channel must prove that the sandbox child started. On non-timeout completion, its reported child exit code must equal the controller's observed process result. Missing, malformed, contradictory, or oversized status evidence cannot become a pytest result.

The observed Bubblewrap path, version, SHA-256, namespace identities, capability facts, configured process/memory/file/descriptor/tmpfs limits, execution CPU limit, and frozen execution-subject evidence are persisted with pytest evidence. These fields bind what was observed; they are not a claim that the host package manager, kernel, or excluded source bytes are immutable.

The `RLIMIT_*` values are inherited process/runtime-identity controls, not cgroup quotas or aggregate host resource attestation. In particular, Linux scopes `RLIMIT_NPROC` to the real user ID and exempts real UID 0 or processes with the relevant resource/admin capabilities. The guard requires zero effective capabilities, but deployments that require a hard aggregate task, CPU, memory, or I/O ceiling must add environment-owned cgroup/VM/container controls outside this repository boundary.

---

## Why the two assertions still exist

The repository can prove that its selected process entered the configured sandbox and can bind the target bytes admitted at `/workspace`. It cannot determine whether an organization intended that particular deployment to enable target-code execution.

The two existing assertions therefore remain **operator intent gates**, while materialization and Bubblewrap are **execution-subject and capability gates**. None substitutes for the others:

```text
trusted deployment intent
+ complete Git-backed source authority
+ frozen provenance-bound execution subject
+ concrete sandbox capability proof
+ sandboxed target execution
+ unchanged authorized source fingerprint through closure
= eligible pytest validation evidence
```

A boolean can no longer turn missing subject authority or missing isolation into execution authority.

---

## Environment boundary

Bubblewrap and the Linux namespace features it uses are deployment inputs. The repository does not install Bubblewrap with a privileged package-manager step during untrusted PR CI and does not expose a Docker socket as a fallback.

If a deployment or validation host does not provide a usable `bwrap`, or if its required Python/system runtime mounts would overlap the original source workspace, live target pytest remains `BLOCKED`. That is a truthful unavailable capability, not a reason to fall back to direct host execution or broaden filesystem authority.

The framework also does not claim that observing a Bubblewrap SHA-256 establishes package publisher identity, kernel integrity, VM isolation, or host attestation. Those remain deployment/supply-chain concerns.

---

## Relationship to repository CI

The sandbox guard applies to the **live Agent SDK `run_pytest` tool**, where the framework may execute code from an arbitrary target repository.

The repository's own GitHub Actions pytest jobs validate this framework's checked-in source in the CI trust context. They do not become evidence that a future deployment has Bubblewrap or namespace support. Repository CI does not install the sandbox backend with privileged or mutable package-manager steps merely to manufacture a live-sandbox PASS.

Unit/adversarial tests therefore verify subject materialization, raw-index binding, ignored-input exclusion, executable-mode authority, sandbox command/preflight protocol, child-start status binding, source hiding, fail-closed behavior, and the no-direct-host invariant deterministically. A real Bubblewrap execution is additional environment evidence only when the host already provides the backend.

---

## Relationship to k6

k6 has its own execution-authority contract because JavaScript module loading, runner resource ceilings, target workload limits, and performance-target semantics differ from pytest. Pytest isolation does not authorize k6, and k6's egress assertion does not authorize pytest.

---

## Operator checklist

Before enabling live pytest execution, verify that:

1. both pytest intent assertions are explicitly enabled for the deployment;
2. the trusted host provides a non-target-controlled Bubblewrap executable;
3. unprivileged user namespaces and the required Bubblewrap lockdown operations are permitted;
4. the target is a complete Git-backed subject that can be materialized within repository path/file/byte limits;
5. the original source workspace is outside every Python/system runtime root that will be exposed read-only to pytest;
6. persisted sandbox evidence shows the evidence root hidden, and the trusted control root is deployed outside the target workspace and runtime roots intentionally exposed read-only to target pytest;
7. target dependencies required by pytest are present in the read-only interpreter/runtime roots;
8. tests do not require external network access, because the initial sandbox intentionally provides no host/external network namespace;
9. the runtime identity is least-privileged and the configured pytest `RLIMIT_*` values are appropriate for the target test workload;
10. the persisted preflight/evidence records show the required execution-subject, namespace, filesystem, network, capability, and resource-policy facts.

If any item is unknown, leave execution blocked. `BLOCKED` is the correct runtime truth.

---

[← Documentation home](README.md) · [Verification boundaries →](VERIFICATION_BOUNDARIES.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
