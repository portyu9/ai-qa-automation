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

## Fork and cloud-authority isolation

A fork copies public source and workflow definitions; it does **not** receive upstream repository/environment secrets, GitHub App private keys, AWS credentials, SSM SecureStrings, or KMS key authority. Fork owners remain free to edit and run their own copy, so fork-local YAML conditions are defense in depth rather than an upstream security boundary.

Upstream cloud authority follows these invariants:

- GitHub Actions is not an AWS authentication plane for this repository. Checked-in workflows must not request GitHub OIDC identity-token authority, configure AWS credentials, embed AWS access/session credentials, assume AWS web-identity roles, or use `pull_request_target`.
- `scripts/verify_fork_cloud_authority.py` deterministically scans the complete bounded workflow set for those forbidden authority paths. Required repository pytest coverage executes the verifier and adversarially proves representative OIDC/static-credential/STS/fork-trigger attempts fail closed.
- the automatic Trusted PR Gate re-fetches live GitHub state from default-branch-owned code and requires the workflow run repository, head repository, PR base/head repository, and owner actor identity to match `portyu9/ai-qa-automation`; fork/external-head runs are ineligible before App credential use;
- the external AWS Trusted Gate is separate from Actions. A copied workflow cannot manufacture its webhook HMAC secret, App private key, exact one-shot policy, or AWS IAM/KMS authority;
- environment-owned AWS IAM/KMS/App configuration remains the ultimate boundary. Repository checks prevent accidental source/workflow drift but never claim that editable fork code can constrain a fork owner.

If GitHub-to-AWS OIDC or another workflow cloud-authentication mechanism is ever required, it is a control-plane redesign: the repository verifier, tests, IAM trust policy, exact repository/ref/environment subject binding, documentation, and protected-gate review must all change explicitly. Do not weaken the verifier merely to make such a workflow green.

Live AWS configuration is environment-dependent and must be audited directly; repository documentation does not convert a historical AWS observation into a permanent claim.

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
