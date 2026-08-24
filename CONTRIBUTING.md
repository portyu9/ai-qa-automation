# Contributing

> [!IMPORTANT]
> **Capability may expand. Authority, evidence quality, test intent, and deterministic truth must never expand implicitly.**

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Architecture](docs/ARCHITECTURE.md) · [Result contract](docs/RESULT_CONTRACT.md) · [Security](docs/SECURITY.md) · [Evaluation](docs/EVALUATION.md)

---

## Engineering principles

A high-quality change should be:

- **deterministic where authority is involved** — model confidence is not authorization;
- **fail-closed** — unknown/ambiguous conditions do not get optimistic permission;
- **evidence-bound** — claims/mutations reference the observations that justify them;
- **subject-bound** — validation must prove the exact object/revision being certified;
- **revision-aware** — stale evidence cannot certify newer bytes;
- **trust-aware** — target/provider content remains untrusted even when instruction-shaped;
- **bounded** — network, mutation, retries, time, and cost remain independently limited;
- **recoverable** — automated writes preserve human work and explicit ownership guarantees;
- **testable** — new authority rules receive deterministic regression coverage;
- **claim-disciplined** — documentation binds statements to the evidence owner that can actually prove them.

---

## Repository command surface

```bash
make quality
make test
make eval
make security
make verify-local
make holdout
```

`make verify-local` covers the routine repository-contained aggregate. The legacy `make holdout` command runs the repository-visible H-series separately so routine primary execution does not directly include those exact readiness fixtures; that separation is not secrecy or blind evaluation.

Execution claims belong to the revision/environment where execution evidence exists; they are not inferred from command/workflow existence.

---

## Test-integrity rules

Never make a test/evaluation green by:

- skipping or x-failing the behavior under investigation;
- weakening/removing meaningful assertions;
- replacing business assertions with tautologies;
- adding arbitrary sleeps;
- inflating timeouts without evidence;
- broadly suppressing failures/exceptions;
- changing predefined safety thresholds after observing failure;
- reclassifying a holdout fixture merely to hide a failure;
- trusting a model confidence score to bypass deterministic policy;
- validating a changed file with an unrelated targeted test;
- allowing unsupported model “already covered” labels to remove deterministic generation candidates.

If an expected contract is genuinely wrong, update it only with evidence that the behavior itself changed or was incorrectly encoded.

---

## Authority-sensitive changes

Changes to these areas deserve explicit architecture/security review:

- `CLAUDE.md`;
- `.claude/` settings, hooks, Skills;
- `.mcp.json` and provider registry/configuration;
- `src/ai_qa_automation/policy.py`;
- `src/ai_qa_automation/config.py` safety defaults/validators;
- runtime permission hooks;
- terminal/result semantics;
- evidence/state/journal/attestation integrity;
- workspace leases, fingerprints, mutation, rollback, stale recovery;
- browser/API/network/performance authorization;
- self-healing semantic/stability eligibility;
- live autonomous language/execution closure;
- `evals/thresholds.json`;
- primary/holdout membership and hard-safety expectations;
- GitHub Actions triggers/permissions/secrets;
- secret, write, provider, and load-test defaults.

For any authority-sensitive change, answer:

1. What new action or interpretation becomes possible?
2. Which deterministic layer authorizes it?
3. Can target/provider/model input influence that authorization?
4. Which evidence is required?
5. Is that evidence bound to the exact subject/revision?
6. Which regression case fails if the control is removed?
7. Do crash/retry/recovery paths preserve the same invariant?
8. Does documentation accidentally claim more than the control proves?

---

## Mutation contribution standard

Live autonomous commit authority currently requires approved **Python** test paths because deterministic execution closure is pytest-backed.

A mutation change must preserve:

```text
pending mutation path
= patch-safety path
= targeted pytest selected path
+ full regression at same revision
```

Do not widen live JS/TS mutation authority until there is a first-class controlled execution/closure adapter that proves those bytes with equivalent rigor.

Filesystem changes must preserve non-traversing/non-symlink ownership in both orchestration and reusable patch layers.

---

## Self-healing contribution standard

- browser match counts are observed, never model supplied;
- candidate syntax stays within supported literal grammar;
- semantic intent and strategy stability are independently constrained;
- unique-but-unrelated candidates remain ineligible;
- structural/positional shortcuts do not become autonomous repair paths;
- proposals remain exact file/hash/evidence bound;
- live mutation still satisfies the Python exact-path transaction contract.

Higher model confidence is never a substitute for these controls.

---

## Test-generation contribution standard

Generation changes must preserve the provenance hierarchy:

```text
observed repository coverage
→ deterministic candidate gaps
→ model-interpreted same-run plan
→ evidence reconciliation
→ guarded creation
```

A model may annotate coverage, but unsupported “already covered” labels cannot suppress deterministic candidates.

Meaningful assertion checks should continue to reject comments/strings/unused scopes that only **look** observable.

---

## Network and performance contribution standard

Network changes should preserve explicit identity and least privilege:

- allowlist entries are canonical host/IP identities, not wildcard/URL policy expressions;
- reject scoped IPv6 and malformed dotted IPv4-looking ambiguity;
- API mutation remains independent from network enablement;
- browser routing covers navigation, subresources, and WebSockets;
- application controls are never documented as firewalls.

Every k6 workload must retain:

- non-production/production-like target policy;
- exact host authorization;
- target/script/import controls;
- bounded runtime;
- deployment-level egress prerequisite for **every** run.

Static JavaScript inspection must never be presented as a network sandbox.

---

## External-provider contribution standard

For MCP/provider changes:

- prefer first-party/vendor-official integrations;
- keep provider identity separate from action authorization;
- classify mixed tool names conservatively;
- require approval for external writes;
- deny destructive actions by default;
- preserve returned content as untrusted evidence;
- normalize failures without fabricating remote evidence;
- do not interpret arbitrary business IDs as HTTP outcomes without status context.

---

## Filesystem / recovery / integrity standard

Live mutation, crash recovery, evidence storage, journals, leases, and attestations must preserve ownership semantics.

A recovery/integrity path must not bypass:

- target/run/artifact confinement;
- traversal checks;
- symlink ownership checks;
- exact workspace fingerprint;
- rollback-root confinement;
- rollback content hash;
- preservation of newer human work;
- registered artifact-byte verification where integrity is claimed.

“Same bytes” does not automatically mean “same owned filesystem object.”

---

## Documentation standard

Documentation should bind claims to their evidence/trust source:

| Claim type | Evidence owner |
|---|---|
| implemented control | source/configuration |
| deterministic runtime behavior | execution for exercised path |
| provider behavior | credentialed provider interaction |
| target behavior | target-specific observation |
| deployment property | infrastructure/organization evidence |

Runtime vocabulary such as `BLOCKED`, `NOT_VERIFIED`, `NOT_EXECUTED`, and `NOT_CONFIGURED` belongs in docs when it describes actual framework behavior. Do not convert those terms into repository-development progress tracking.

Public Markdown should favor:

- clear hierarchy;
- concise GitHub-native callouts;
- tables where comparison matters;
- diagrams where flow/authority matters;
- cross-links to canonical deep dives;
- no decorative badge or claim that implies unobserved execution.

---

## Security reports

Do not place real credentials, private customer data, production artifacts, or sensitive exploit material in a public contribution. Follow root [`SECURITY.md`](SECURITY.md).

---

## Review starting points

- [`docs/README.md`](docs/README.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/RESULT_CONTRACT.md`](docs/RESULT_CONTRACT.md)
- [`docs/SECURITY.md`](docs/SECURITY.md)
- [`docs/EVALUATION.md`](docs/EVALUATION.md)
- [`docs/TECHNICAL_WALKTHROUGH.md`](docs/TECHNICAL_WALKTHROUGH.md)

---

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`LICENSE`](LICENSE).
