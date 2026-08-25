# Tool Input Boundaries

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Security architecture](SECURITY.md) · [Runtime control](RUNTIME_CONTROL.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Purpose

Live tool requests are untrusted runtime inputs even when they originate from model reasoning or an approved provider. They must be bounded **before** they can become a repetition fingerprint, consume execution budget, reach deterministic policy, or enter a tool body.

The live runtime therefore applies a code-owned ingestion contract before request serialization or execution. Deployment configuration cannot raise or disable these limits.

## Live request contract

A live tool input must be a JSON object composed only of JSON-compatible values. The common boundary rejects requests that exceed any of these limits:

| Boundary | Limit |
|---|---:|
| Aggregate UTF-8 bytes across string values and object keys | 2,100,000 |
| Structural nodes | 20,000 |
| Nesting depth | 16 |
| Items in one object or array | 10,000 |
| Integer magnitude | 4,096 bits |
| Floating-point values | finite only |

The aggregate UTF-8 limit measures decoded string/key content, not transport framing or JSON escape expansion. Canonical repetition fingerprints are streamed incrementally after validation instead of materializing one additional full JSON string.

Inputs containing tuples, arbitrary Python objects, non-string object keys, `NaN`, or infinities are outside the live JSON contract and are denied.

## Raw JSON-string fields

Several narrow tools intentionally accept JSON text as a string. Those fields receive a second boundary **before** `json.loads()`:

- at most 1,000,000 UTF-8 bytes per JSON text field;
- maximum JSON nesting depth of 64, preflighted without invoking the parser;
- at most 100,000 parsed structural nodes;
- at most 50,000 entries in one parsed object or array;
- the same finite-number and bounded-integer rules after parsing.

The guarded fields are:

- `plan_tests.existing_coverage_json`;
- `prioritize_regression.candidates_json`;
- `verify_locator_candidates.candidates_json`;
- `propose_locator_heal.candidates_json`;
- `validate_json_contract.instance_json`;
- `validate_json_contract.schema_json`.

Malformed JSON is denied at the request boundary. Parser recursion cannot become an optimistic or partially verified tool result.

### Browser candidate bound

Locator verification and healing additionally allow at most **20 candidate entries**, matching the controlled browser execution surface. The limit is enforced for both the SDK-prefixed tool name and the internal tool name before a live tool body can construct browser execution state.

## Enforcement order

For the live Agent SDK path, the ordering is:

1. validate request shape and bounded JSON fields;
2. deny and journal only the tool name plus a bounded reason code if invalid;
3. sanitize the accepted input for the repetition fingerprint;
4. stream the canonical fingerprint hash;
5. charge tool/network/mutation budgets as applicable;
6. evaluate deterministic policy;
7. enter the controlled tool;
8. revalidate in `LiveRuntimeServices.consume()` as defense in depth before tool-specific work.

An input-bound denial does **not** increment the tool-call budget and does not persist the rejected raw value in the runtime journal.

The programmatic permission handler applies the same request validator, so the permission path cannot become a weaker input surface than `PreToolUse`.

## Authority boundary

`LiveRuntimeServices` is the authority-bearing adapter used by the production-shaped Agent SDK execution path. The reusable base `RuntimeServices` remains a lower-level implementation/test helper and is not documented as an independent live authorization boundary.

This distinction is deliberate: production guarantees are attached to the path that is actually wired into `run_agent`, rather than inferred from every reusable class that can be instantiated in tests.

## What this does not prove

Input bounding is a resource-safety and fail-closed ingestion control. It does not prove that:

- a syntactically valid request is authorized;
- a browser page, API, or test result is correct;
- provider output is trustworthy;
- target-controlled code is sandboxed;
- a validation PASS exists for the requested objective.

Those claims remain governed by deterministic policy, execution isolation prerequisites, observed evidence, subject-bound validation, and terminal truth.

---

[← Documentation home](README.md) · [Security architecture →](SECURITY.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
