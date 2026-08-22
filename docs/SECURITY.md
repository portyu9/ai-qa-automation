# Security Architecture

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

Security controls in the ƳƤ AI QA Automation Framework are enforced in deterministic code in addition to model instructions. The design assumes the model can be confused by adversarial content and therefore does not make prompt compliance the primary security boundary.

## Security principles

1. **Fail closed** — unknown tools, unknown MCP namespaces, unsupported high-risk actions, path escape, stale workspace state, and missing approval do not receive optimistic permission.
2. **Separate trust zones** — control-plane configuration is trusted; target and remote content is evidence, not authority.
3. **Minimize authority** — the runtime exposes narrow QA actions rather than generic shell/edit/web capabilities.
4. **Bind mutation to evidence and validation** — autonomous test changes are restricted, transactionally reversible, and cannot close without deterministic validation.
5. **Keep uncertainty visible** — infrastructure failures, missing evidence, and conflicting validation cannot become synthetic PASS.
6. **Do not confuse application controls with infrastructure isolation** — host/path/tool policy is defense in depth; OS/container/network enforcement remains deployment evidence.

## Fail-closed runtime authority

The live runtime exposes the framework-owned QA tool inventory rather than general mutation/network tools. Unknown tools are denied. Unapproved MCP namespaces are denied. Approval-required actions fail closed during unattended execution.

Agent SDK configuration additionally restricts generic Bash/Edit/Write/Web surfaces and uses project-only settings with a fixed Skill allowlist.

A model instruction cannot grant itself new authority because authorization is performed by deterministic policy/hooks outside the model output.

## Filesystem and workspace integrity

`PolicyEngine.authorize_path` resolves candidate paths before policy checks, rejects target-workspace escape, protects governance/secret paths, and restricts optional writes to approved test directories.

For autonomous mutations, path authorization is only the first control. The runtime also requires:

- an isolated Git-backed target worktree;
- an exclusive workspace lease;
- a current fingerprint matching the inspected baseline;
- explicit test-write enablement;
- no unresolved previous mutation transaction;
- unambiguous mutation-path ownership with no absolute path, traversal, or symlink component.

Out-of-band changes block mutation. This prevents an agent from silently writing against a workspace whose contents changed after analysis or redirecting a write through a symlink alias.

## Transactional patch integrity

Safe patching combines:

- optimistic-concurrency hashes;
- narrow mutation types;
- syntax/test-quality validation;
- unsafe-diff pattern checks;
- trusted rollback snapshots outside the SUT;
- rollback snapshot path confinement and hash verification;
- post-change patch-safety + targeted pytest + full-regression requirements.

Guardrails block common “make it green” shortcuts such as skips/xfails, arbitrary sleeps, focused-only tests, indiscriminate timeout inflation, assertion removal/weakening, tautologies, and broad exception suppression.

A transaction without deterministic closure rolls back only when rollback integrity is established. Crash recovery restores a stale mutation only when the persisted fingerprint proves no newer human/out-of-band change would be overwritten.

## Evidence and artifact confinement

Run-scoped evidence directories are resolved under the trusted artifact root. Empty/root-aliasing, absolute, and traversal-style run identifiers that would escape or collapse that boundary are rejected. Artifact paths are resolved under the run root, duplicate evidence IDs and artifact paths are immutable, and symlink-based artifact escapes are rejected.

These controls reduce cross-run and filesystem-boundary ambiguity; they do not substitute for deployment-level access controls or storage policy.

## API and browser network boundaries

API access is host-allowlisted and read-only by default. Mutating methods require separate explicit enablement. API requests avoid ambient proxy inheritance.

Browser evidence collection checks initial navigation, HTTP(S) subresources, and WebSocket connections against the runtime allowlist. Service workers are disabled in the evidence context so they cannot silently extend the network surface.

Network-capable actions consume an independent runtime budget in addition to the total tool budget.

## Performance-test safety

Production load testing is denied by policy. k6 targets must pass the runtime network allowlist and be explicitly classified as non-production. The policy also rejects production-like DNS labels such as `prod`/`production` forms even when caller-supplied environment metadata claims staging or QA.

The runner requires scripts to bind to the injected approved target and applies bounded static restrictions including rejection of:

- remote modules;
- `k6/x/*` extensions;
- local-file reads;
- unrelated hard-coded external hosts.

Usage reporting is disabled and runtime summary files remain outside the SUT.

Non-local k6 additionally requires the trusted `AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true` precondition. That flag is an explicit assertion that the deployment has separately established infrastructure-level egress enforcement; it is not itself a firewall.

## MCP security

External MCP must match an approved vendor identity and be explicitly enabled. GitHub MCP is additionally configured read-only at the server layer. Runtime policy independently separates recognized read operations, approval-required writes, destructive actions, and unknown actions.

External action names are normalized across snake/camel naming and evaluated conservatively: destructive verbs dominate write verbs, which dominate recognized reads. Resource-noun collisions such as `pull request` are handled explicitly so legitimate reads are not mislabeled while mixed names such as read-plus-create/delete cannot smuggle higher authority behind a read prefix.

Target/user/plugin MCP configuration is not inherited into the live runtime. Remote MCP content is sanitized and persisted as untrusted evidence; it cannot redefine policy, hooks, Skills, thresholds, or terminal-outcome rules.

An integration is marked `AVAILABLE` only after an observed successful call.

See [`MCP.md`](MCP.md).

## Secrets and artifacts

Evidence is sanitized recursively along model-facing/text persistence paths. Pytest output is redacted before it is returned or stored as sanitized text evidence. Runtime pytest/k6/git subprocesses use credential-minimal environments and do not inherit the control process `PYTHONPATH`.

Raw binary artifacts such as screenshots are labeled `RAW` rather than falsely marked sanitized. Their access and retention remain an operational/deployment responsibility.

`.env.example` contains names/defaults only. Runtime settings deliberately do not auto-load a repository `.env` file. Real credentials must be injected through the environment or an approved secret-management mechanism and must never be committed.

## Governance protection

The runtime protects policy/configuration assets that could redefine its authority or evidence standard, including:

- `CLAUDE.md`;
- `.claude/` settings/hooks/Skills;
- `.mcp.json`;
- core policy/runtime-hook paths;
- evaluation thresholds;
- GitHub workflow paths through trusted development hooks.

A governance change is expected to receive explicit human review rather than autonomous self-modification.

## Supply-chain and dependency posture

The repository defines dependency compatibility checking, Bandit source analysis, dependency vulnerability auditing, and secret scanning as deterministic security gates.

Dependencies and external MCP versions should be updated deliberately: verify official provenance/version, review behavior/tool-surface changes, update deterministic tests/policy if authority changes, and rerun the applicable gates before promoting the new state.

## Threat-model relationship

[`THREAT_MODEL.md`](THREAT_MODEL.md) enumerates primary threats and residual boundaries. A material new threat should result in one or more of:

- a narrower deterministic policy;
- a safer tool contract;
- stronger evidence semantics;
- a regression/security test;
- an adversarial primary/holdout scenario;
- an explicit environment boundary when the repository itself cannot enforce the control.

## Reporting a security issue

Follow the root [`SECURITY.md`](../SECURITY.md). Never include real credentials, private customer data, production artifacts, or sensitive exploit material in a public report.

## Verification boundary

Security claims are scoped to their evidence source: source-level controls, deterministic gates, credentialed providers, and deployment infrastructure are evaluated within their respective trust boundaries.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
