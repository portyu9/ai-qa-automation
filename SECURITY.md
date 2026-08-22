# Security Policy

> [!IMPORTANT]
> The ƳƤ AI QA Automation Framework is built around **least privilege, evidence integrity, and deterministic authority** rather than trust in model behavior.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Security architecture](docs/SECURITY.md) · [Threat model](docs/THREAT_MODEL.md) · [Result contract](docs/RESULT_CONTRACT.md) · [Runtime control](docs/RUNTIME_CONTROL.md)

---

## Security posture

The framework's security design includes:

- trusted-control-plane / untrusted-target separation;
- narrow QA tools instead of generic shell/edit/web authority;
- fail-closed tool/path/provider/action authorization;
- canonical exact-host/IP network configuration;
- protected secret/governance paths;
- credential-minimal subprocess environments and recursive redaction;
- vendor-official MCP allowlisting plus action-level authorization;
- browser/API network controls;
- universal deployment-egress prerequisite for k6 workloads;
- deterministic semantic self-healing eligibility;
- OS-backed workspace leases with symlink-resistant ownership;
- content-sensitive workspace fingerprints;
- rollback-backed revision transactions;
- exact-path mutation validation closure;
- trusted rollback/journal/evidence/recovery ownership checks;
- immutable run-scoped evidence/artifact identities;
- hash-chained runtime chronology;
- unsigned attestations that verify registered artifact bytes without claiming identity/PASS;
- explicit runtime non-PASS outcomes when evidence, authorization, or integrity is insufficient.

For design detail, see:

- [`docs/SECURITY.md`](docs/SECURITY.md)
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- [`docs/RESULT_CONTRACT.md`](docs/RESULT_CONTRACT.md)
- [`docs/RUNTIME_CONTROL.md`](docs/RUNTIME_CONTROL.md)
- [`docs/VERIFICATION_BOUNDARIES.md`](docs/VERIFICATION_BOUNDARIES.md)
- [`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md)

---

## Reporting a vulnerability

> [!CAUTION]
> Do **not** place sensitive security material in a public issue, pull request, discussion, fixture, log, trace, or screenshot.

Sensitive material includes:

- API keys, access tokens, passwords, private keys, cookies, session material;
- customer/private source or data;
- production artifacts;
- sensitive live-system exploit details before coordination;
- screenshots/traces containing private application information.

If GitHub exposes a private **Report a vulnerability** path for this repository, prefer it. Otherwise contact the repository owner through GitHub before sharing sensitive reproduction material.

A public issue is appropriate only when the problem can be described safely without exposing credentials, private data, or exploitable secrets.

---

## Useful report contents

Where safe, include:

- affected component/path;
- minimal reproduction conditions;
- expected vs observed policy behavior;
- security impact;
- target/deployment assumptions;
- whether model, target, provider, filesystem, network, mutation, evidence, or recovery input is involved;
- deterministic regression/adversarial case, if known.

The highest-value report identifies the **violated invariant**, not only the visible symptom.

---

## Credential and artifact hygiene

`.env.example` is reference documentation only. Runtime configuration deliberately does not auto-load repository `.env` files, and runtime policy protects `.env` / `.env.*` secret-shaped paths while preserving `.env.example` as readable documentation.

If a credential is exposed:

1. treat it as compromised;
2. revoke/rotate it at the provider;
3. remove it from current content;
4. assess Git history, forks, logs, caches, and artifacts;
5. repair the exposure path;
6. add deterministic regression/security coverage where appropriate.

Removing a secret from a later commit does not make earlier exposure harmless.

Raw binary evidence—especially screenshots—can contain sensitive data even when the surrounding text path is sanitized. Storage/access/retention policy belongs to the deployment environment.

---

## Security-fix standard

A material security weakness should be closed by the narrowest deterministic control that addresses the **general behavior**, plus appropriate regression/adversarial coverage.

Do not “fix” security by:

- weakening expected outcomes;
- broadening model/tool authority;
- converting missing evidence into PASS;
- trusting model confidence as authorization;
- allowing unsupported coverage claims to suppress deterministic test candidates;
- bypassing path/network/provider policy;
- weakening exact-path mutation closure;
- disabling trusted-path ownership/integrity checks;
- special-casing one fixture while leaving the general weakness intact;
- treating an application flag as proof of infrastructure enforcement.

Security changes affecting authority, evidence, mutation, recovery, provider semantics, trusted filesystem ownership, or evaluation thresholds deserve explicit architecture/security review.

---

## Coordinated engineering principle

> **When a security property can be enforced deterministically, enforce it in code and prove it with regression coverage rather than relying on the model to remember a warning.**

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for engineering/review standards.

---

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`LICENSE`](LICENSE).
