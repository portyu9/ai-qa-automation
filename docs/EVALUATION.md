# Evaluation Strategy

The agent is evaluated as a software system, not only by subjective response quality.

## Layers

1. **Unit tests** — schemas, policies, redaction, intelligence logic, runtime budgets, evidence integrity.
2. **Integration tests** — evidence/state/report flow, artifact manifests, regulated audit chaining, reference behavior.
3. **Security tests** — governance protection, prompt-injection-shaped data, destructive operations, path and tool boundaries.
4. **Deterministic scenario evaluator** — 34 functional/adversarial scenarios in `evals/scenarios/`.
5. **Model-marked tests** — tests requiring Anthropic credentials are isolated behind the `model` marker and are not treated as verified when they are not executed.

## Fixed thresholds

`evals/thresholds.json` defines release thresholds independently of an individual run. Hard-safety scenarios require zero known failures. A weak run is not repaired by relaxing the threshold afterward.

## Important assertions

The deterministic suite directly checks behaviors including:

- a retry at the same change revision cannot hide a conflicting failure; only a newer approved revision of the same gate can supersede historical failure
- unknown tools and unapproved MCP namespaces fail closed
- approval-required external writes fail closed unattended
- API mutations require explicit enablement
- browser navigation, subrequests, and WebSockets cannot escape the network allowlist
- locator uniqueness is taken from Playwright observation rather than model input
- generated-test creation requires same-run coverage-search and plan provenance
- k6 scripts must bind to the approved target; external runs require a trusted infrastructure-egress precondition
- test patching cannot remove meaningful assertion coverage
- regulated evidence records maintain a hash chain
- repeated identical actions and total tool calls are bounded
- MCP auth/outage/invalid-response states are normalized without invented remote evidence

## Metrics

The models and reports support metrics such as:

- failure-classification precision/recall
- self-healing semantic correctness and false-heal rate
- regression-selection recall, reduction, and escape rate
- prompt-injection blocks and policy denials
- execution duration, tool calls, token usage, and model cost when observed

## Interpretation

The number of generated tests or repairs that become green is not sufficient evidence of quality. False healing, escaped regressions, fabricated PASS, unsafe policy bypasses, and omitted mandatory coverage are hard failures.
