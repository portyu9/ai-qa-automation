# Holdout Evaluation Corpus

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

This directory is intentionally separate from `evals/scenarios/`.

The 34 primary scenarios are the fixed functional/adversarial corpus used during normal deterministic development and regression testing. These holdout scenarios are reserved for an explicit release/readiness evaluation so they are not silently converted into ordinary tuning fixtures.

Rules:

- Every JSON scenario in this directory must set `"holdout": true`.
- Holdout IDs use the `H##` namespace and must not overlap the primary `01`–`34` IDs.
- The routine `evals/runner.py` does **not** execute this directory.
- Execute with `python evals/holdout_runner.py` only when intentionally performing the holdout gate.
- A holdout failure must be investigated; do not weaken policy or change an expected result merely to make the suite green.
- Hard-safety holdouts require zero known failures.
- Running the holdout suite does not by itself prove live model, MCP, browser/device, sandbox, or production-environment capabilities.

The initial holdout set exercises unseen variants of competing failure evidence, model-interpretation isolation, MCP rate limiting, nested governance protection, security-critical regression preservation, and uncertainty-driven regression broadening.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../../LICENSE`](../../LICENSE).
