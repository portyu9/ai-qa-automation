# Contributing

**ƳƤ AI QA Automation Framework**  
**Designed and engineered by Ƴunior Ƥortal (ƳƤ)**

Contributions to the ƳƤ AI QA Automation Framework must preserve its defining hierarchy:

> **Capability may expand. Authority, evidence quality, test intent, and deterministic truth must never expand implicitly.**

## Engineering principles

A high-quality change should be:

- **deterministic where authority is involved** — model confidence is not an authorization mechanism;
- **fail-closed** — unknown or ambiguous conditions should not receive optimistic permission;
- **evidence-bound** — claims and mutations should reference the observations that justify them;
- **revision-aware** — stale evidence must not certify newer bytes;
- **path- and trust-aware** — target/provider content remains untrusted even when instruction-shaped;
- **bounded** — network, mutation, retries, time, and cost remain independently controlled;
- **recoverable** — mutation paths should preserve human work and explicit integrity guarantees;
- **testable** — a new authority rule should have deterministic regression coverage;
- **documented at the right layer** — documentation explains architecture/runtime semantics without substituting prose for enforcement.

## Repository command surface

```bash
make quality
make test
make eval
make security
make verify-local
make holdout
```

`make verify-local` covers the routine repository-contained aggregate. The H-series holdout remains independent so ordinary development does not tune directly against exact holdout fixtures.

Execution claims should always be tied to the corresponding execution record rather than inferred from the existence of a command, test, or workflow.

## Test-integrity rules

Never make a test/evaluation green by:

- skipping or x-failing the behavior under investigation;
- weakening/removing a meaningful assertion;
- replacing a business assertion with a tautology;
- adding arbitrary sleeps;
- inflating timeouts without evidence;
- broadly suppressing exceptions/failures;
- changing predefined safety thresholds after observing a failure;
- reclassifying a holdout fixture merely to hide a failure;
- teaching a model-produced confidence score to bypass deterministic policy.

If a test contract is genuinely wrong, update it only with evidence that the expected behavior itself changed or was incorrectly encoded.

## Authority-sensitive changes

Changes to these areas deserve explicit architecture/security review:

- `CLAUDE.md`;
- `.claude/` settings, hooks, or Skills;
- `.mcp.json` and provider registry/configuration;
- `src/ai_qa_automation/policy.py`;
- `src/ai_qa_automation/config.py` safety defaults/validators;
- runtime permission hooks;
- terminal/result semantics;
- evidence/state integrity;
- workspace leases, fingerprints, mutation, rollback, or stale recovery;
- browser/API/network/performance authorization;
- self-healing semantic/stability eligibility;
- `evals/thresholds.json`;
- primary/holdout membership and expected hard-safety outcomes;
- GitHub Actions triggers/permissions/secrets;
- secret, write, provider, and load-test safety defaults.

For any authority-sensitive change, answer:

1. What new action or interpretation becomes possible?
2. Which deterministic layer authorizes it?
3. Can untrusted target/provider/model input influence that authorization?
4. Which evidence is required?
5. Which regression case fails if the control is removed?
6. Does crash/retry/recovery behavior preserve the same invariant?

## Self-healing contribution standard

Locator-healing changes must preserve the separation between proposal and authority.

- browser match counts are observed, not model supplied;
- candidate syntax must remain in the supported literal grammar;
- semantic intent and strategy stability must be independently constrained;
- unique-but-unrelated candidates must remain ineligible;
- structural/positional shortcuts must not become autonomous repair paths;
- mutation remains exact-file/hash bound;
- patch-safety + targeted + regression closure remains mandatory.

A higher model confidence score is not a substitute for any of these controls.

## Network contribution standard

Network changes should preserve explicit identity and least privilege.

- trusted allowlist entries are host/IP identities, not wildcard/URL policy strings;
- API mutation remains independent from network enablement;
- browser routing should cover navigation, subresources, and WebSockets;
- application controls should not be documented as infrastructure firewalls;
- performance execution must preserve non-production and target-binding guarantees.

## External-provider contribution standard

For MCP/provider changes:

- prefer first-party/vendor-official integrations;
- keep provider identity separate from action authorization;
- classify mixed tool names conservatively;
- require approval for external writes;
- deny destructive actions by default;
- preserve returned content as untrusted evidence;
- normalize provider failures without fabricating remote evidence;
- do not interpret arbitrary business IDs as HTTP outcomes without status context.

## Filesystem/recovery contribution standard

Live mutation and crash recovery must enforce the same ownership philosophy.

A recovery implementation must not become a bypass around:

- target confinement;
- traversal checks;
- symlink ownership;
- exact workspace fingerprint;
- rollback-root confinement;
- rollback content hash;
- preservation of newer human work.

## Documentation standard

Documentation should bind claims to their evidence/trust source:

- source/configuration describes implemented control structure;
- deterministic execution describes behavior observed for the exercised path;
- provider interaction describes credentialed integration behavior;
- target/deployment observation describes environment-specific behavior.

Runtime outcome vocabulary such as `BLOCKED`, `NOT_VERIFIED`, `NOT_EXECUTED`, and `NOT_CONFIGURED` should remain where it describes framework behavior. Do not turn those terms into repository-development progress tracking.

Start with:

- [`docs/README.md`](docs/README.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/RESULT_CONTRACT.md`](docs/RESULT_CONTRACT.md)
- [`docs/SECURITY.md`](docs/SECURITY.md)
- [`docs/EVALUATION.md`](docs/EVALUATION.md)

## Security reports

Do not place real credentials, private customer data, production artifacts, or sensitive exploit material in a public contribution. Follow root [`SECURITY.md`](SECURITY.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`LICENSE`](LICENSE).
