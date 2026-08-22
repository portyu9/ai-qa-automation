# Security Policy

**ƳƤ AI QA Automation Framework**  
**Designed and engineered by Ƴunior Ƥortal (ƳƤ)**

## Security posture

The ƳƤ AI QA Automation Framework is built around least privilege and evidence integrity rather than model trust.

Its security architecture includes:

- trusted-control-plane / untrusted-target separation;
- narrow QA tools instead of generic shell/edit/web authority;
- fail-closed tool/path/provider authorization;
- canonical host/IP network configuration;
- secret-shaped environment path protection;
- credential-minimal subprocess environments and recursive redaction;
- vendor-official MCP allowlisting plus action-level authorization;
- browser/API/performance network controls;
- deterministic semantic self-healing eligibility;
- content-sensitive workspace fingerprints;
- OS-backed mutation leases;
- rollback-backed revision transactions;
- non-symlink ownership during live mutation and stale recovery;
- immutable run-scoped evidence/artifact identities;
- hash-chained runtime chronology;
- explicit runtime non-PASS outcomes when evidence, authorization, or integrity is insufficient.

Implementation details:

- [`docs/SECURITY.md`](docs/SECURITY.md)
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- [`docs/RESULT_CONTRACT.md`](docs/RESULT_CONTRACT.md)
- [`docs/RUNTIME_CONTROL.md`](docs/RUNTIME_CONTROL.md)
- [`docs/VERIFICATION_BOUNDARIES.md`](docs/VERIFICATION_BOUNDARIES.md)
- [`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md)

## Reporting a vulnerability

Do **not** place sensitive security material in a public issue, pull request, discussion, fixture, log, or screenshot.

Examples include:

- API keys, access tokens, passwords, private keys, cookies, or session material;
- customer/private source code or data;
- production artifacts;
- exploitable details against a live third-party system before coordination;
- screenshots/traces containing sensitive application information.

If GitHub exposes a private **Report a vulnerability** path for this repository, prefer that channel. Otherwise, contact the repository owner through GitHub before sharing sensitive reproduction material.

A public issue is appropriate only when the problem can be described safely without exposing credentials, private data, or exploitable secrets.

## Useful report contents

Where safe, include:

- affected component/path;
- minimal reproduction conditions;
- expected versus observed policy behavior;
- security impact;
- relevant target/deployment assumptions;
- whether model, target, provider, filesystem, network, or recovery input is involved;
- a deterministic regression test or adversarial scenario, if known.

The most useful reports identify the **violated invariant**, not only the visible symptom.

## Credential and artifact hygiene

Never commit real credentials or private customer/production artifacts.

`.env.example` is reference documentation only. Runtime configuration deliberately does not auto-load repository `.env` files, and runtime policy protects `.env` / `.env.*` secret-shaped paths while preserving `.env.example` as readable documentation.

If a credential is exposed:

1. treat it as compromised;
2. revoke/rotate it at the provider;
3. remove it from current content;
4. assess Git history, forks, logs, caches, and artifacts;
5. review whether the exposure path needs a deterministic regression/security control.

Removing a secret from a later commit does not make the earlier exposure harmless.

## Security-fix standard

A material security weakness should be addressed with the narrowest deterministic control that closes the behavior, plus appropriate regression or adversarial coverage.

Do not “fix” a security problem by:

- weakening an expected outcome;
- broadening model/tool authority;
- converting missing evidence into PASS;
- trusting model confidence as authorization;
- bypassing path/network/provider policy;
- disabling integrity checks;
- special-casing one fixture while leaving the general weakness intact.

Security fixes that affect authority, evidence, mutation, recovery, provider semantics, or evaluation thresholds should receive explicit architecture/security review.

## Coordinated engineering principle

> **When a security property can be enforced deterministically, enforce it in code and prove it with regression coverage rather than relying on the model to remember a warning.**

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution/review standards.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`LICENSE`](LICENSE).
