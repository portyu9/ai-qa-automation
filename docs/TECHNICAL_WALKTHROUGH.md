# Technical Walkthrough

## 1. Start with the result contract

The central rule is implemented in `agent.py`: a successful model result does not produce `SUCCESS` by itself. Deterministic gates have revision-aware lineage; same-revision PASS/FAIL conflicts remain `NOT_VERIFIED`, while a newer approved change revision can supersede the older result for the same gate without deleting history. A changed test must close its current revision with patch-safety, targeted pytest, and full-regression PASS.

Related files:

- `src/ai_qa_automation/models.py`
- `src/ai_qa_automation/agent.py`
- `src/ai_qa_automation/reporting.py`

## 2. Follow evidence into state

`EvidenceStore` sanitizes structured evidence, hashes artifacts, maintains the run manifest, and optionally emits a hash-chained audit log. `StateStore` persists canonical run state outside conversation history.

```bash
ai-qa demo
```

The deterministic scenario shows why a missing UI control plus HTTP 500 should not be repaired as a locator defect.

## 3. Inspect the controlled tool surface

`runtime/internal_tools.py` defines the 18 narrow Agent SDK QA tools. `policy.py` and `runtime/runtime_hooks.py` enforce tool, Skill, path, network, write, MCP, and performance rules before actions execute. The five project Skills are explicitly enabled by name; unrelated Skills are not accepted.

Key properties:

- explicit internal tool inventory
- unknown tools fail closed
- repeated-action and total-tool budgets
- API mutation control
- browser host/subrequest allowlisting
- restricted test writes
- production-load denial

## 4. Inspect self-healing and test changes

`tools/browser_evidence.py`, `tools/locators.py`, `intelligence/self_healing.py`, and `tools/safe_patch.py` separate observed locator facts from the repair decision and the actual mutation. Playwright measures the original and candidate locators in the same DOM; the proposal is then bound to that evidence, current failure classification, test path, and expected hash. The live mutation tool can change only the approved literal locator expression.

A patch is checked for intent-weakening patterns, syntax errors, test-quality regressions, and stale-file hashes before it can be written. Afterward the new revision still requires targeted and full-regression pytest validation.

## 5. Inspect coverage-aware test generation

`search_test_coverage` records a bounded repository observation. `plan_tests` must consume that evidence, and `create_test_file` must consume the resulting same-run plan evidence. This makes the mutation provenance explicit: observed coverage → interpreted gap/plan → deterministic file checks → execution validation.

## 6. Inspect the agent's own evaluation

```bash
pytest
python evals/runner.py
```

The 34-scenario evaluator includes application/test defects, unsafe repair strategies, prompt injection, MCP failures, regression omissions, production-load attempts, and control-plane injection.

## 7. Inspect verification boundaries

`docs/VERIFICATION_BOUNDARIES.md` distinguishes repository-contained deterministic behavior from live model, MCP, browser/device, load, and infrastructure capabilities that need external execution evidence.
