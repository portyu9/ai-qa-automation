# Contract Drift Ingestion Boundary

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Change intelligence](CHANGE_INTELLIGENCE.md) · [Runtime control](RUNTIME_CONTROL.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Purpose

OpenAPI/Swagger drift is authority-bearing change intelligence: a `NON_BREAKING` classification can influence how a reviewer understands a candidate change. Repository-controlled JSON or YAML therefore cannot be interpreted with ambiguous parser defaults or allowed to exhaust the runtime before the analyzer reaches an explicit result.

The contract path preserves this ordering:

```text
bounded subject bytes
→ deterministic JSON/YAML parse boundary
→ JSON-compatible tree validation
→ conservative structural drift comparison
→ explicit BREAKING / RISKY / NON_BREAKING / NOT_ANALYZED report
```

Parser failure, unsupported syntax, resource exhaustion, or ambiguous document meaning is **`NOT_ANALYZED`**. It is never converted to compatibility evidence.

## Byte authority

Runtime bootstrap already reads changed worktree contracts through the descriptor-confined filesystem boundary and reads the merge-base contract from immutable Git object identity. Each contract side is limited to **2,000,000 bytes** before parsing.

The standalone `ai-qa contract-diff` command applies the same 2,000,000-byte per-document ingestion ceiling. It no longer materializes arbitrary-size input with unrestricted `Path.read_bytes()` before validation.

The byte ceiling bounds raw input size; it is not sufficient by itself because small serialized documents can still carry deep structures, aliases, duplicate keys, or parser-specific scalar semantics.

## JSON contract

JSON contract documents are parsed with the following fail-closed rules:

- maximum lexical/structural nesting depth: **64**;
- duplicate object keys are rejected recursively rather than using last-key-wins semantics;
- `NaN`, `Infinity`, and `-Infinity` are rejected;
- parser recursion failure becomes `NOT_ANALYZED`;
- post-parse values must satisfy the same bounded JSON-compatible tree contract used for YAML normalization.

A duplicate key is not treated as a deterministic choice between two meanings. An ambiguous contract cannot certify itself as non-breaking because the host JSON parser happened to retain the final value.

## YAML contract

YAML is admitted only as a bounded serialization of a JSON-compatible OpenAPI data tree. The parser does not grant the full YAML data model authority over drift semantics.

Before object construction:

| Boundary | Limit |
|---|---:|
| YAML scanner tokens | 200,000 |
| YAML anchors | 1,024 |
| YAML aliases | 1,024 |
| Nesting depth | 64 |
| Direct mapping entries | 50,000 |
| Direct sequence items | 50,000 |

Additional semantics are deliberately strict:

- duplicate mapping keys are rejected;
- mapping keys must resolve to strings;
- YAML merge keys (`<<`) are rejected instead of being flattened, because merge expansion can amplify an alias graph before a post-parse bound can protect the process;
- container aliases that create shared or circular object graphs are rejected rather than promoted as a JSON tree;
- explicit YAML-only values such as timestamp objects, sets, binary values, or other non-JSON types are rejected;
- plain `true` / `false` retain boolean meaning;
- PyYAML YAML-1.1 words such as `on`, `off`, `yes`, and `no` are not silently coerced to booleans, preserving their YAML-1.2-style string meaning for OpenAPI keys/values;
- implicit numeric conversion is restricted to a deterministic decimal/exponent subset; legacy YAML-only numeric spellings are not silently reinterpreted as another numeric value.

These restrictions intentionally prefer `NOT_ANALYZED` over parser-dependent compatibility claims.

## Post-parse shape bounds

Both JSON and YAML results must form a finite JSON-compatible tree:

- maximum nesting depth: **64**;
- maximum structural nodes: **100,000**;
- maximum items in one object or array: **50,000**;
- integer magnitude: at most **4,096 bits**;
- floating-point values must be finite;
- values are limited to JSON null/string/boolean/number/object/array types;
- object keys must be strings;
- repeated container identity is rejected so YAML cannot retain shared/circular container authority after construction.

These limits are enforced before structural comparison. Exceeding one means the document was not safely analyzed.

## Drift truth

Only two safely parsed, recognized OpenAPI/Swagger documents enter the comparison engine. Existing conservative rules then identify path/operation removals, required-input changes, response removals, security changes, schema/property changes, enum narrowing, and other implemented structural signals.

| Result | Meaning |
|---|---|
| `BREAKING` | an implemented structural rule found a conservatively breaking change |
| `RISKY` | an implemented rule found compatibility risk requiring broader validation/review |
| `NON_BREAKING` | both documents passed the bounded parser and no implemented breaking/risky rule matched |
| `NOT_ANALYZED` | document meaning or safe bounded analysis could not be established |

`NON_BREAKING` remains scoped to the implemented structural rules; it is not a complete protocol-compatibility proof.

## Non-claims

This boundary does **not**:

- validate every OpenAPI semantic constraint;
- dereference remote `$ref` resources or grant network/filesystem retrieval authority to contract content;
- prove consumer compatibility beyond implemented drift rules;
- make repository-controlled contracts trusted;
- turn unsupported YAML features into low risk;
- allow missing baseline history or unreadable current bytes to become compatibility evidence.

> **Ambiguous parse is not compatibility. Unsupported YAML is not compatibility. Resource exhaustion is not compatibility. `NOT_ANALYZED` is a legitimate terminal fact for the drift analyzer.**

---

[← Change intelligence](CHANGE_INTELLIGENCE.md) · [Verification boundaries →](VERIFICATION_BOUNDARIES.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
