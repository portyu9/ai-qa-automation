# 5-Minute Employer Walkthrough

## 1. Start with the engineering problem
“AI can reason about a failure, but it should not be trusted to declare software correct. This project makes evidence and deterministic gates authoritative.”

Show `models.py`, `evidence.py`, and `policy.py`.

## 2. Demonstrate the offline failure trap

```bash
ai-qa demo
```

Explain why a missing button plus HTTP 500 is an application/API symptom, not an excuse to auto-rewrite a locator.

## 3. Show guarded autonomy
Show `runtime/internal_tools.py` and `runtime/runtime_hooks.py`: narrow tools, tool/repetition budgets, explicit host allowlists, safe patching, fail-closed permissions, and strict MCP runtime configuration.

## 4. Show self-healing quality
Show `self_healing.py` and `safe_patch.py`: semantic locator scoring, uniqueness, optimistic concurrency, syntax checks, unsafe-diff detection, and mandatory post-repair validation.

## 5. Show that the AI tester is tested

```bash
pytest
python evals/runner.py
```

Point out the 34 functional/adversarial scenarios and zero-tolerance hard-safety thresholds.

## 6. End with production judgment
Open `docs/LIMITATIONS.md`. Explain exactly which capabilities are intentionally `NOT_VERIFIED` until real credentials, browsers/devices, approved staging load, and hardened infrastructure exist.

That distinction is the central production-readiness lesson of the repository.
