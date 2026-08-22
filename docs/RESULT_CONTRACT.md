# Runtime Result Contract

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

The ƳƤ AI QA Automation Framework separates **what the model says** from **what the system can prove**. A fluent answer, a confident diagnosis, or a successful Agent SDK result subtype never becomes a verified QA outcome by itself.

> **Runtime outcomes are derived from deterministic policy, observed evidence, validation lineage, and integrity state.**

This contract is part of the framework's safety model. It describes live run semantics—not repository-development progress.

## Decision hierarchy

The authority order is intentionally asymmetric:

```text
trusted policy / runtime invariants
        ↓
observed evidence
        ↓
deterministic validation lineage
        ↓
model interpretation and proposed action
        ↓
structured terminal report
```

Model reasoning can influence **what to investigate next**. It cannot redefine policy, convert missing evidence into PASS, erase contradictory validation, or certify its own mutation.

## Terminal outcomes

| Outcome | Meaning |
|---|---|
| `SUCCESS` | The Agent SDK session completed successfully and every active deterministic validation gate required for the current revision passed. |
| `FAILURE` | A current deterministic validation failed, the Agent SDK returned a non-success subtype, or another definitive execution failure occurred. |
| `BLOCKED` | A deterministic prerequisite prevented safe continuation, such as workspace ownership/drift or recovery ambiguity. |
| `INSUFFICIENT_EVIDENCE` | Available evidence cannot support a reliable causal conclusion. |
| `POLICY_DENIED` | The requested action is outside authorized runtime policy. |
| `INFRASTRUCTURE_FAILURE` | Runtime infrastructure failed in a way that prevents trustworthy continuation or rollback guarantees. |
| `CANCELLED` | Execution was cancelled before deterministic completion. |
| `BUDGET_EXCEEDED` | An independent execution budget was exhausted. |
| `NOT_VERIFIED` | The model/session completed, but deterministic validation is absent, incomplete, contradictory, or insufficient for verified success. |

`NOT_VERIFIED` is deliberately different from `FAILURE`. It means the framework refuses to invent certainty where the validation record does not justify it.

## Validation outcomes

Individual deterministic gates use a narrower validation vocabulary:

| Outcome | Meaning |
|---|---|
| `PASS` | The gate executed for its bound scope/revision and satisfied its deterministic condition. |
| `FAIL` | The gate executed and failed its deterministic condition. |
| `NOT_EXECUTED` | The gate has no execution record for the relevant decision. |
| `NOT_OBSERVED` | The required observation was not captured. |
| `NOT_VERIFIED` | Evidence exists but does not close the gate. |
| `BLOCKED` | Policy, environment, integrity, or another prerequisite prevented the gate from running safely. |

None of the non-PASS validation outcomes is promoted to PASS by model judgment.

## Revision-aware truth

Autonomous mutation creates a new `change_revision`. Validation is bound to revisions so evidence from an older workspace state cannot silently certify newer bytes.

For a changed test to close successfully, the current revision requires:

1. deterministic patch-safety PASS;
2. targeted pytest PASS; and
3. full-regression pytest PASS.

A failed gate remains active until the same gate identity is superseded by evidence at a newer revision. Re-running a different test selector cannot erase the original failed gate.

If PASS and FAIL are both observed for the same gate at the same revision, the result is treated as contradictory evidence and resolves to `NOT_VERIFIED` rather than selecting the more convenient observation.

## Mutation transaction semantics

A permitted write is not immediately trusted.

```text
AUTHORIZED WRITE
→ trusted rollback snapshot
→ candidate revision
→ patch-safety validation
→ targeted validation
→ full regression
→ COMMIT
```

Any path that fails to establish deterministic closure returns through rollback. If rollback ownership or integrity cannot be guaranteed, the framework escalates to `INFRASTRUCTURE_FAILURE` rather than overwriting data optimistically.

Crash recovery applies the same ownership rules: exact workspace fingerprint, confined paths, non-symlink ownership, and verified rollback bytes are required before stale restoration can occur.

## External integration outcomes

MCP/provider health is independent from QA terminal truth:

| Provider outcome | Meaning |
|---|---|
| `AVAILABLE` | An authorized provider interaction was successfully observed. |
| `NOT_CONFIGURED` | The provider is not enabled/configured for the runtime. |
| `UNAUTHORIZED` | Authentication or authorization was rejected. |
| `RATE_LIMITED` | The provider reported throttling. |
| `UNAVAILABLE` | Transport/provider availability prevented the operation. |
| `INVALID_RESPONSE` | The response could not be safely interpreted as the expected provider contract. |
| `FAILED` | A provider action failed without a more specific normalized class. |

Configuration presence alone does not manufacture `AVAILABLE`. Failed provider calls do not manufacture remote evidence.

## Evidence classes

The framework keeps observation and interpretation distinct:

- `OBSERVED_FACT` — produced by controlled tools or deterministic inspection;
- `MODEL_INTERPRETATION` — reasoning, plans, proposals, or hypotheses derived from evidence.

A model interpretation can reference observed evidence, but it does not become an observed fact by repetition or confidence.

## Result provenance

The final report carries identifiers and provenance needed to reason about the conclusion, including:

- run ID and objective;
- terminal outcome and reason;
- deterministic validation results;
- evidence identifiers;
- failure classification and confidence when applicable;
- modified files;
- model and Agent SDK identity;
- policy/tool-schema/configuration fingerprints;
- target Git SHA when observed.

Persisted evidence, manifests, journal hashes, and attestations support traceability. Integrity metadata does not transform a failed or unverified run into success.

## Core invariant

The framework's final truth rule is intentionally simple:

> **Unknown is not PASS. Model completion is not PASS. Configuration is not PASS. Historical evidence is not current-revision PASS. Only deterministic closure can produce verified success.**

See [`ARCHITECTURE.md`](ARCHITECTURE.md), [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md), [`TRACEABILITY.md`](TRACEABILITY.md), and [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
