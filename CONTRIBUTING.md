# Contributing

**ƳƤ AI QA Automation Framework**  
**Designed and engineered by Ƴunior Ƥortal (ƳƤ)**

The ƳƤ AI QA Automation Framework treats deterministic safety gates as higher authority than model judgment. Contributions should preserve that hierarchy.

## Local contribution gates

After installing the development dependencies, the routine repository-contained checks are intentionally separated by concern:

```bash
make quality
make test
make eval
make security
```

Or run the same routine set with:

```bash
make verify-local
```

The H-series holdout corpus is separate from the everyday contribution loop so it preserves an independent readiness signal:

```bash
make holdout
```

Describe verification from recorded execution evidence rather than from the presence of a command, test file, or workflow definition.

## Non-negotiable test-integrity rules

Never make a test or evaluation green by:

- skipping or x-failing the behavior under investigation;
- weakening or removing a meaningful assertion;
- replacing an assertion with a tautology;
- adding an arbitrary sleep;
- inflating timeouts without evidence;
- broadly suppressing exceptions/failures;
- changing predefined safety thresholds after seeing a failing result;
- moving a failing holdout case into the normal tuning corpus to hide the readiness failure.

If behavior is genuinely wrong, fix the implementation or update a test only when the test's intended contract is demonstrably incorrect.

## Governance-sensitive changes

Changes to the following deserve explicit security/architecture review because they can alter runtime authority or what counts as evidence:

- `CLAUDE.md`;
- `.claude/` settings, hooks, or Skills;
- `.mcp.json` and external MCP registry/configuration;
- `src/ai_qa_automation/policy.py`;
- runtime hooks, terminal-outcome rules, mutation/recovery controls, or evidence semantics;
- `evals/thresholds.json`;
- primary/holdout corpus membership or expected hard-safety outcomes;
- GitHub Actions permissions/triggers;
- secret/network/write/performance safety defaults.

A governance change should explain why authority is not being widened accidentally and should add deterministic coverage for any newly allowed behavior.

## Documentation standard

Documentation should bind claims to the source of evidence:

- source/configuration describes implemented control structure;
- deterministic runs describe repository behavior for exercised paths;
- provider interaction describes credentialed integration behavior;
- target/deployment observation describes environment-specific behavior.

Avoid wording that lets one evidence class stand in for another.

Start with [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/SETUP.md`](docs/SETUP.md), [`docs/EVALUATION.md`](docs/EVALUATION.md), and [`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md).

## Security reports

Do not put real credentials, private customer data, production artifacts, or sensitive exploit material in a public contribution. Follow the root [`SECURITY.md`](SECURITY.md) disclosure guidance.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`LICENSE`](LICENSE).
