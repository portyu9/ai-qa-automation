# Controller Executable Authority

**ƳƤ AI QA Automation Framework** · **Ƴunior Ƥortal (ƳƤ)**

Host-side subprocess execution is an authority boundary. A target workspace, artifact directory, evidence directory, virtual environment, launch-shell `PATH`, or mutable tool-specific environment must not be able to select which executable the controller runs.

## Runtime invariant

Controller subprocess selection follows these rules:

1. `restricted_subprocess_env()` does not inherit ambient `PATH`, `VIRTUAL_ENV`, `PATHEXT`, or `COMSPEC` as executable-selection authority.
2. Controller `PATH` is derived from deployment-owned system locations rather than the target workspace or current working directory.
3. Every executable search root must resolve to an existing absolute directory. Empty and relative entries fail closed.
4. A named command is resolved only through those explicit roots.
5. An absolute host-tool command is accepted only when its resolved path remains inside one of the same roots. Resolving a symlink outside the authority root is rejected.
6. The exact Python interpreter already running the controller is a distinct re-execution case: its canonical `sys.executable` path may be launched again without adding that interpreter's parent directory, virtual environment, or hosted tool cache to generic executable-search authority. A sibling executable in that directory receives no authority from this exception.
7. Missing or ambiguous controller executable authority is an execution failure or `NOT_VERIFIED` boundary; the framework does not fall back to ambient discovery.

On POSIX, the built-in controller roots are the resolved standard system executable directories corresponding to `/usr/bin` and `/bin`. An existing selected root must be owned by uid 0 and must not be group- or world-writable. `/bin` aliases that resolve to `/usr/bin` are deduplicated.

On Windows, the system executable directory is obtained from the operating system through `GetSystemDirectoryW`; it is not selected from `SYSTEMROOT`, `WINDIR`, or `PATH`. Fixed Git installation candidates under `Program Files` on that OS-selected system drive may be used when present. The restricted controller environment authorizes `.EXE` files only; batch/command-script suffixes and ambient `COMSPEC` are not controller execution authority. Windows ACL integrity for those system-owned locations remains a deployment/OS prerequisite; the Python permission-bit model does not claim to attest Windows ACLs.

These checks establish executable-selection authority. They do not cryptographically attest operating-system packages or replace host hardening, package integrity, measured boot, daemon integrity, or deployment provenance.

## Callers

### Repository inspection and build provenance

`RepositoryInspector` invokes Git through the bounded subprocess adapter with `restricted_subprocess_env()`. Bare `git` can therefore resolve only through the controller authority path. A target-provided `git` placed first on the launch process's ambient `PATH` cannot become the controller executable.

Build-manifest provenance Git uses the same controller environment with an isolated temporary `HOME`, so build evidence does not recover executable-selection authority from the launch environment.

Git environment minimization, bounded output, process cleanup, no-prompt configuration, repository confinement, and exact repository-subject checks remain separate controls and are not weakened by executable binding.

### Controller Python re-execution

The JSON Schema validation worker is intentionally a separate process. It re-executes the exact canonical interpreter already running the controller through the bounded subprocess adapter. This is not a PATH search and does not authorize the interpreter's parent directory. Hosted setup-Python directories or virtual environments therefore do not become generic locations from which Git, k6, Docker, or other host tools may be selected.

### k6

The controlled k6 runner builds its restricted controller environment first and resolves `k6` through that environment before execution. If k6 is installed only in a user, target, virtual-environment, or other non-authoritative location, execution remains `NOT_VERIFIED` rather than widening controller authority to find it.

Executable binding does not replace k6's independent requirements for approved target policy, deployment egress containment, process/filesystem isolation, module-loading isolation, CPU/memory/process limits, and workload/concurrency/rate limits.

### Mermaid Docker validation

Mermaid documentation validation builds a restricted controller environment before resolving Docker. `docker` is selected only through controller executable roots and every `docker run`, `docker exec`, and cleanup invocation receives that restricted environment. Ambient `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`, and launch-shell `PATH` therefore do not choose a Docker executable or redirect the validator through inherited Docker client configuration.

The Mermaid container remains bound to a digest-pinned official CLI image with no container network, a read-only filesystem, dropped capabilities, `no-new-privileges`, bounded pids/memory/CPU/file size, a read-only source mount, and bounded tmpfs output. Those controls are independent of executable selection. The framework does not claim that resolving the local Docker client attests Docker daemon integrity, host daemon policy, or operating-system package bytes.

### Pytest / Bubblewrap

Target pytest execution has a different authority shape. The host launches Bubblewrap only after its own fixed `/usr/bin:/bin` discovery, regular-file checks, executable identity/hash binding, workspace/evidence exclusion, capability proof, and pre-spawn identity recheck. Python/pytest then execute inside the proven sandbox namespace using sandbox-contained runtime roots.

The generic controller authority change therefore does not turn target Python or target pytest into host-side executable authority and does not replace Bubblewrap's stronger binary identity proof.

### Trusted PR Gate OpenSSL signer

The external Trusted PR Gate uses a separate, gate-local executable contract. `AppTokenProvider` no longer accepts an OpenSSL executable override. It resolves only reviewed `/usr/bin/openssl`; on the supported POSIX deployment model, the resolved `/usr/bin` root and executable must be root-owned and must not be group- or world-writable, and a symlink may not escape that trusted root.

Both Lambda and standalone service construction use this same provider contract. The former standalone `TRUSTED_GATE_OPENSSL_BIN` environment selector is not executable authority. JWT signing still passes the GitHub App private key through an anonymous inherited descriptor, uses a minimal fixed environment, applies a bounded timeout, rejects stderr/nonzero/empty/oversized signing results, and never creates a named private-key file.

These checks bind which OpenSSL executable is selected; they do not cryptographically attest the OpenSSL package, underlying OS image, or host kernel.

### Release-candidate identity verification

The protected release-candidate verifier was included in the subprocess audit. It does not perform PATH-based Git selection: its pre-install identity check uses fixed absolute `/usr/bin/git` with a minimal Git environment. That protected release path remains separate from the generic runtime resolver because it executes before the project is installed. The fixed absolute path is not widened into ambient executable-search authority.

### Process-tree cleanup

Windows `taskkill` cleanup is resolved through the same explicit subprocess environment rather than partial-path ambient process execution. POSIX cleanup uses process-group signaling and does not spawn a separate cleanup executable.

## Adversarial verification contract

The deterministic test suite covers the following security properties:

- hostile ambient `PATH` and `VIRTUAL_ENV` do not enter controller executable authority;
- executable-authority keys cannot be reintroduced through `restricted_subprocess_env(extra=...)`;
- empty and relative search roots fail closed for ordinary controller tools;
- the exact current interpreter can re-execute without authorizing hostile/missing sibling search roots;
- absolute executables in target, artifact, and evidence-style runtime roots are rejected;
- symlink resolution cannot escape an authorized root;
- mutable POSIX candidate roots are rejected;
- a trusted system Git resolves deterministically to an absolute path under the controlled roots;
- repository snapshot, fingerprint, baseline, HEAD, and worktree evidence remain functional while a malicious workspace `git` is first on ambient `PATH`;
- build-manifest Git drops hostile ambient PATH and virtual-environment authority;
- k6 lookup occurs only after its independent isolation prerequisites and receives the restricted environment;
- simulated k6 execution receives an already-resolved absolute controller executable;
- Mermaid Docker resolution ignores hostile ambient PATH and Docker client context/host variables, and every Docker operation receives the restricted environment;
- Trusted PR Gate construction exposes no OpenSSL executable override and rejects mutable POSIX OpenSSL roots; and
- the trusted-gate signer continues to pass private-key bytes only through an anonymous inherited descriptor.

These are repository-visible deterministic assertions. They prove the implemented selection policy on the tested revision and platform; they do not prove external host package integrity, Docker daemon integrity, or Windows ACL configuration that CI did not observe.

## Failure semantics

Executable discovery is never evidence of test success. If a required controller executable cannot be resolved within authorized roots, the operation fails before meaningful execution. For optional/runtime-dependent tooling such as k6, absence from trusted roots is reported as unavailable / `NOT_VERIFIED`, not converted into `PASS`.

This preserves the framework authority chain:

**objective → advisory reasoning → deterministic policy → controlled tool → real execution/observation → persisted evidence → deterministic validation → structured terminal report**
