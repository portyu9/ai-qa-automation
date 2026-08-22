# Security Architecture

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

Security in the ƳƤ AI QA Automation Framework is enforced in deterministic code in addition to model instructions. The design assumes probabilistic reasoning can be wrong and target/provider content can be adversarial; prompt compliance is therefore never the primary security boundary.

## Security principles

1. **Fail closed** — unknown tools, namespaces, actions, paths, environments, or ownership conditions do not receive optimistic permission.
2. **Separate trust zones** — control-plane configuration is trusted; target and remote content are evidence, not authority.
3. **Minimize authority** — narrow QA capabilities replace generic shell/edit/web power.
4. **Keep model confidence advisory** — probabilistic scores can guide reasoning but cannot independently authorize mutation or certify evidence.
5. **Bind mutation to ownership and validation** — writes are path-confined, revision-bound, transactionally recoverable, and deterministically closed.
6. **Preserve uncertainty** — missing, conflicting, blocked, or insufficient evidence cannot become synthetic PASS.
7. **Separate application controls from infrastructure controls** — host/path/tool rules are defense in depth; process/container/network enforcement belongs to deployment infrastructure.

## Fail-closed runtime authority

The live runtime exposes the framework-owned QA tool inventory rather than general mutation/network tools. Unknown tools and unapproved MCP namespaces are denied. Approval-required actions fail closed during unattended execution.

Agent SDK configuration additionally:

- uses trusted project settings;
- allowlists five Skills;
- enables strict MCP configuration;
- denies Bash/Edit/Write/Web-style built-ins;
- passes tool requests through deterministic permission handling and hooks.

A prompt cannot grant itself authority because authorization is performed outside model output.

## Trusted network configuration

The network allowlist is validated at configuration load rather than interpreted loosely at point of use.

Entries must be explicit hostnames or IP literals. The configuration layer canonicalizes DNS/IP values and rejects:

- wildcard hosts;
- URL-shaped entries;
- embedded ports;
- user-info, paths, query strings, or fragments;
- malformed DNS labels;
- empty allowlists.

This prevents ambiguous trusted configuration from later being interpreted differently by API, browser, or performance adapters.

## Filesystem and workspace integrity

`PolicyEngine.authorize_path` resolves candidate paths, rejects workspace escape, protects governance/secret paths, and limits optional writes to approved test directories.

Autonomous mutation additionally requires:

- an isolated Git-backed target worktree;
- an exclusive OS-backed workspace lease;
- a content-sensitive fingerprint matching the analyzed baseline;
- explicit test-write enablement;
- no unresolved previous mutation transaction;
- non-ambiguous path ownership: no absolute path, traversal, workspace escape, or symlink component.

Out-of-band changes block mutation rather than allowing the agent to write against stale analysis.

## Transactional patch integrity

Safe patching combines:

- optimistic-concurrency file hashes;
- narrow mutation types;
- syntax/test-quality validation;
- unsafe-diff checks;
- trusted rollback snapshots outside the SUT;
- rollback path confinement and hash verification;
- current-revision patch-safety, targeted pytest, and full-regression requirements.

Guardrails reject common “make it green” shortcuts such as skips/xfails, arbitrary sleeps, focused-only tests, indiscriminate timeout inflation, assertion erosion, tautologies, and broad exception suppression.

A transaction without deterministic closure rolls back only when rollback ownership and integrity are established.

## Crash recovery uses the same ownership model

Recovery is not a weaker alternate write path.

Stale mutation recovery validates:

- the prior run directory remains under the trusted artifact root;
- prior runtime metadata is a regular non-symlink file;
- the recorded workspace matches the lease workspace;
- current fingerprint exactly matches the crashed mutation checkpoint;
- pending target path is confined and contains no symlink component;
- rollback backup remains inside the trusted rollback directory;
- rollback path contains no symlink component;
- backup bytes match the recorded SHA-256 digest.

If newer human/out-of-band work exists or any ownership/integrity property is ambiguous, automatic rollback is blocked.

## Deterministic self-healing authority

A unique locator is not automatically a safe locator.

The framework separates model proposal quality from autonomous authorization:

1. Playwright observes original/candidate match counts in the same DOM.
2. Supported locator expressions are reparsed by deterministic code.
3. Semantic intent is recomputed from original/candidate locator contracts.
4. Model-supplied semantic confidence is overwritten.
5. Model-supplied stability is overwritten with policy-owned strategy stability.
6. Positional/XPath-style and weak-semantic candidates are rejected.
7. Proposal remains bound to exact file path/hash and observed evidence.
8. Applied locator-only mutation must close current-revision deterministic validation.

The same semantic rule also constrains locator-contract failure classification so an unrelated unique element cannot make the classifier overconfident.

## Evidence and artifact confinement

Run-scoped evidence directories are confined beneath the trusted artifact root. Empty/root-aliasing, absolute, traversal, and symlink-shaped run paths are rejected. Artifact paths remain beneath the run root, duplicate evidence IDs/artifact paths are immutable, and symlink-based artifact escapes are rejected.

These controls reduce cross-run and filesystem-boundary ambiguity; deployment storage/access policy remains an independent responsibility.

## API and browser network boundaries

API access is host-allowlisted and read-only by default. Mutating methods require separate explicit enablement. HTTP requests avoid ambient proxy inheritance and do not automatically follow redirects.

Browser evidence collection checks:

- initial navigation;
- HTTP(S) subresources;
- WebSocket connections;
- final navigation after page load.

Service workers are disabled in the evidence context so they cannot silently extend the routed network surface. Allowed WebSockets use Playwright's supported routed-server connection path; disallowed sockets are closed by policy.

Network-capable actions consume an independent runtime budget in addition to the total tool budget.

## Performance-test safety

Production load testing is denied by policy. k6 targets must pass the host allowlist and be explicitly classified as non-production. Production-like DNS labels such as `prod` / `production` forms are denied even when caller-supplied environment metadata claims staging or QA.

The controlled runner requires target injection and rejects:

- remote modules;
- `k6/x/*` extensions;
- local-file reads;
- unrelated literal external hosts;
- unsupported imports.

Usage reporting is disabled and runtime summary files live outside the SUT.

Non-local k6 additionally requires `AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true` as a trusted prerequisite asserting deployment-level egress enforcement. The flag is not itself a firewall.

## MCP security

External MCP must match an approved vendor identity and be explicitly enabled. GitHub MCP is additionally configured read-only at the server layer. Runtime policy independently separates read operations, approval-required writes, destructive actions, and unknown actions.

External action names are normalized across snake/camel/mixed conventions. Authorization precedence is conservative:

```text
destructive token > write token > recognized read token
```

Resource-noun collisions such as `pull request` are handled explicitly while mixed names such as read-plus-create/delete cannot smuggle higher authority behind a safe-looking prefix.

Target/user/plugin MCP configuration is not inherited. Remote MCP content is sanitized, persisted as untrusted evidence, and cannot redefine policy, hooks, Skills, thresholds, or terminal rules.

An integration becomes `AVAILABLE` only after an observed successful provider interaction.

See [`MCP.md`](MCP.md).

## Secrets and artifacts

Evidence is recursively sanitized along supported model-facing/text persistence paths. Pytest output is redacted before it is returned or stored as sanitized text evidence. Runtime pytest/k6/git subprocesses use credential-minimal environments and do not inherit the control process `PYTHONPATH`.

Raw binary artifacts such as screenshots are labeled `RAW`; their access and retention remain deployment concerns.

`.env.example` contains reference names/defaults only. Runtime settings do not auto-load a repository `.env` file. Real credentials must be injected through the operating environment or an approved secret-management mechanism and never committed.

## Governance protection

The runtime protects authority-bearing assets including:

- `CLAUDE.md`;
- `.claude/` settings/hooks/Skills;
- `.mcp.json`;
- policy/runtime-hook paths;
- evaluation thresholds;
- secret-bearing environment files;
- workflow/governance surfaces through trusted development controls.

Governance changes require reviewed engineering work rather than autonomous self-modification.

## Supply-chain posture

The repository defines deterministic gates for dependency compatibility, Bandit source analysis, dependency vulnerability auditing, and secret scanning.

Dependencies and external-provider versions should be updated deliberately: validate official provenance, review behavioral/tool-surface changes, update policy/tests if authority changes, and evaluate the resulting configuration under the applicable framework gates.

## Threat-model relationship

[`THREAT_MODEL.md`](THREAT_MODEL.md) enumerates primary threats and residual deployment boundaries. A material threat should result in one or more of:

- narrower deterministic policy;
- safer tool contract;
- stronger evidence semantics;
- security/regression test;
- adversarial evaluation case;
- explicit deployment boundary when repository code cannot enforce the control.

## Reporting a security issue

Follow root [`SECURITY.md`](../SECURITY.md). Never include real credentials, private customer data, production artifacts, or sensitive exploit material in a public report.

## Evidence ownership

Security claims remain scoped to their evidence source: source-level controls, deterministic runtime observations, credentialed providers, and deployment infrastructure each have distinct trust owners.

See [`README.md`](README.md), [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md), [`THREAT_MODEL.md`](THREAT_MODEL.md), and [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
