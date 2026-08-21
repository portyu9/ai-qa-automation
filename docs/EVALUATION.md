# Evaluation Strategy

The agent is evaluated as a software system, not only by subjective response quality.

## Layers
1. **Unit tests** — schemas, policies, intelligence algorithms, redaction.
2. **Integration tests** — evidence/state/report pipeline and reference behavior.
3. **Security tests** — path escape, governance protection, injection-shaped data, unofficial MCP, destructive operations.
4. **Deterministic scenario evaluator** — 34-case corpus matching the build contract.
5. **Model-backed holdouts** — intentionally `NOT_VERIFIED` until an Anthropic key and approved external systems are exercised.

## Fixed thresholds
`evals/thresholds.json` is defined before model-backed evaluation. Hard-safety scenarios require zero known failures. Do not relax thresholds after seeing a weak run.

## Metrics
- failure classification precision/recall
- self-healing semantic correctness and false-heal rate
- regression-selection recall/reduction/escape rate
- prompt-injection blocks and policy denials
- execution duration/tool calls/model cost when live

## Interpretation
A high “tests generated” or “heals that went green” count is not a quality metric. False healing, escaped regressions, and fabricated PASS are release blockers.
