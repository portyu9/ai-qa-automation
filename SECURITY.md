# Security Policy

**ƳƤ AI QA Automation Framework**  
**Designed and engineered by Ƴunior Ƥortal (ƳƤ)**

## Security posture

The ƳƤ AI QA Automation Framework is designed around least privilege, trusted-control-plane / untrusted-SUT separation, secret redaction, vendor-official MCP allowlisting, path confinement, bounded execution, transactional test mutation, deterministic policy hooks, and explicit non-PASS runtime outcomes when evidence or authorization is insufficient.

For the implementation-level security architecture, see:

- [`docs/SECURITY.md`](docs/SECURITY.md)
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- [`docs/VERIFICATION_BOUNDARIES.md`](docs/VERIFICATION_BOUNDARIES.md)
- [`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md)

## Reporting a vulnerability

Please do **not** place any of the following in a public issue, pull request, discussion, test fixture, or screenshot:

- API keys, access tokens, passwords, private keys, or session material;
- customer/private source code or production data;
- exploit details that would expose a live third-party system before coordination;
- sensitive artifacts collected from a real target environment.

If GitHub offers a private **Report a vulnerability** path for this repository, prefer that channel for sensitive security reports. Otherwise, contact the repository owner through GitHub before sharing sensitive reproduction material. A non-sensitive public issue may be used to coordinate only when the report can be described safely without credentials, private data, or exploitable secrets.

A useful report should include, where safe:

- affected component/path;
- minimal reproduction conditions;
- expected versus observed policy behavior;
- security impact;
- relevant deployment assumptions;
- a proposed deterministic regression test or adversarial scenario, if known.

## Credential and artifact hygiene

Never commit real credentials or private customer/production artifacts. `.env.example` is a reference template only; the runtime deliberately does not auto-load committed `.env` configuration.

If a credential is accidentally exposed, treat it as compromised and rotate/revoke it at the provider. Removing it from a later commit is not sufficient because Git history, caches, forks, logs, or artifacts may already contain the value.

## Security-fix standard

A material security weakness should be addressed with the narrowest deterministic control that closes the behavior, plus an appropriate regression test or adversarial evaluation. Do not “fix” a security gate by weakening expected outcomes, broadening tool authority, or converting missing evidence into PASS.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`LICENSE`](LICENSE).
