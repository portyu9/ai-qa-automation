# Controller Executable Authority

**ƳƤ AI QA Automation Framework** · **Ƴunior Ƥortal (ƳƤ)**

Host-side subprocess execution is an authority boundary. A target workspace, artifact directory, evidence directory, virtual environment, or launch-shell `PATH` must not be able to select which executable the controller runs.

## Runtime invariant

Controller subprocess selection follows these rules:

1. `restricted_subprocess_env()` does not inherit ambient `PATH`, `VIRTUAL_ENV`, or `PATHEXT` as executable-selection authority.
2. Controller `PATH` is derived from deployment-owned system locations rather than the target workspace or current working directory.
3. Every executable search root must resolve to an existing absolute directory. Empty and relative entries fail closed.
4. A named command is resolved only through those explicit roots.
5. An absolute command path is accepted only when its resolved path remains inside one of the same roots. Resolving a symlink outside the authority root is rejected.
6. Missing or ambiguous controller executable authority is an execution failure or `NOT_VERIFIED` boundary; the framework does not fall back to ambient discovery.

On POSIX, the built-in controller roots are the resolved standard system executable directories corresponding to `/usr/bin` and `/bin`. An existing selected root must be owned by uid 0 and must not be group- or world-writable. `/bin` aliases that resolve to `/usr/bin` are deduplicated.

On Windows, the system executable directory is obtained from the operating system through `GetSystemDirectoryW`; it is not selected from `SYSTEMROOT`, `WINDIR`, or `PATH`. Fixed Git installation candidates under `Program Files` on that OS-selected system drive may be used when present. Windows ACL integrity for those system-owned locations remains a deployment/OS prerequisite; the Python permission-bit model does not claim to attest Windows ACLs.

These checks establish executable-selection authority. They do not cryptographically attest operating-system packages or replace host hardening, package integrity, measured boot, or deployment provenance.

## Callers

### Repository inspection

`RepositoryInspector` invokes Git through the bounded subprocess adapter with `restricted_subprocess_env()`. Bare `git` can therefore resolve only through the controller authority path. A target-provided `git` placed first on the launch process's ambient `PATH` cannot become the controller executable.

Git environment minimization, bounded output, process cleanup, no-prompt configuration, repository confinement, and exact repository-subject checks remain separate controls and are not weakened by executable binding.

### k6

The controlled k6 runner builds its restricted controller environment first and resolves `k6` through that environment before execution. If k6 is installed only in a user, target, virtual-environment, or other non-authoritative location, execution remains `NOT_VERIFIED` rather than widening controller authority to find it.

Executable binding does not replace k6's independent requirements for approved target policy, deployment egress containment, process/filesystem isolation, module-loading isolation, CPU/memory/process limits, and workload/concurrency/rate limits.

### Pytest / Bubblewrap

Target pytest execution has a different authority shape. The host launches Bubblewrap only after its own fixed `/usr/bin:/bin` discovery, regular-file checks, executable identity/hash binding, workspace/evidence exclusion, capability proof, and pre-spawn identity recheck. Python/pytest then execute inside the proven sandbox namespace using sandbox-contained runtime roots.

The generic controller authority change therefore does not turn target Python or target pytest into host-side executable authority and does not replace Bubblewrap's stronger binary identity proof.

### Process-tree cleanup

Windows `taskkill` cleanup is resolved through the same explicit subprocess environment rather than partial-path ambient process execution. POSIX cleanup uses process-group signaling and does not spawn a separate cleanup executable.

## Adversarial verification contract

The deterministic test suite covers the following security properties:

- hostile ambient `PATH` and `VIRTUAL_ENV` do not enter controller executable authority;
- executable-authority keys cannot be reintroduced through `restricted_subprocess_env(extra=...)`;
- empty and relative search roots fail closed;
- absolute executables in target, artifact, and evidence-style runtime roots are rejected;
- symlink resolution cannot escape an authorized root;
- mutable POSIX candidate roots are rejected;
- a trusted system Git resolves deterministically to an absolute path under the controlled roots;
- repository snapshot, fingerprint, baseline, HEAD, and worktree evidence remain functional while a malicious workspace `git` is first on ambient `PATH`;
- k6 lookup occurs only after its independent isolation prerequisites and receives the restricted environment; and
- simulated k6 execution receives an already-resolved absolute controller executable.

These are repository-visible deterministic assertions. They prove the implemented selection policy on the tested revision and platform; they do not prove external host package integrity or Windows ACL configuration that CI did not observe.

## Failure semantics

Executable discovery is never evidence of test success. If a required controller executable cannot be resolved within authorized roots, the operation fails before meaningful execution. For optional/runtime-dependent tooling such as k6, absence from trusted roots is reported as unavailable / `NOT_VERIFIED`, not converted into `PASS`.

This preserves the framework authority chain:

**objective → advisory reasoning → deterministic policy → controlled tool → real execution/observation → persisted evidence → deterministic validation → structured terminal report**
