# Sequestered Readiness Evaluation Corpus

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

This repository-visible corpus is intentionally separated from the routine primary deterministic cases under `evals/scenarios/`.

The `evals/holdout/` path, `holdout_runner.py`, and `"holdout": true` field are retained as a compatibility namespace for **execution separation**. They do **not** mean these committed fixtures are secret, blind, unseen, or independent of the repository. Every H-series case is explicitly marked `"repository_visible": true`.

Rules:

- Every JSON case in this directory must set both `"holdout": true` and `"repository_visible": true`.
- H-series IDs use the `H##` namespace and must not overlap primary `01`–`34` IDs.
- Every H-series case must resolve to a distinct registered evaluator path; duplicate proxy cases fail closed.
- The routine `evals/runner.py` does **not** execute this directory.
- Execute with `python evals/holdout_runner.py` only for an intentional sequestered readiness check.
- A readiness failure must be investigated; do not weaken policy, safety metadata, or expected behavior merely to make the suite green.
- Hard-safety readiness cases require zero known failures.
- Running this repository-visible readiness suite does not prove live model, MCP, browser/device, sandbox, production-environment, or genuinely blind external benchmark capability.

The H-series exercises distinct variants of competing failure evidence, model-interpretation isolation, MCP rate limiting, nested governance protection, security-critical regression preservation, and uncertainty-driven regression broadening.

Because the fixtures are public repository content, a genuinely blind evaluation requires an environment-owned corpus that is not available to the implementation or repository during development.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../LICENSE`](../../LICENSE).
