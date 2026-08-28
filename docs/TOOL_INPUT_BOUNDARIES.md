# Tool Input Boundaries

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Security architecture](SECURITY.md) · [Runtime control](RUNTIME_CONTROL.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Purpose

Live tool requests are untrusted runtime inputs even when they originate from model reasoning or an approved provider. Every attempted request is first charged against the cheap universal tool-call/wall-clock budget, then its potentially large request body is bounded **before** it can become a repetition fingerprint, consume network or mutation budget, reach deterministic policy, or enter a tool body.

The live runtime applies this source-owned ingestion contract before request serialization or execution. Deployment configuration cannot raise or disable these limits.

## Live request contract

A live tool input must be a JSON object composed only of JSON-compatible values. The common boundary rejects requests that exceed any of these limits:

| Boundary | Limit |
|---|---:|
| Tool name UTF-8 bytes | 256 |
| Aggregate UTF-8 bytes across string values and object keys | 2,100,000 |
| Structural nodes | 20,000 |
| Nesting depth | 16 |
| Items in one object or array | 10,000 |
| Integer magnitude | 4,096 bits |
| Floating-point values | finite only |

The aggregate UTF-8 limit measures decoded string/key content, not transport framing or JSON escape expansion. After validation, repetition fingerprints are hashed across encoder chunks rather than first joining the complete canonical request document into one additional string.

Inputs containing tuples, arbitrary Python objects, non-string object keys, `NaN`, infinities, or Unicode surrogate code points are outside the live JSON/UTF-8 contract and are denied. `PreToolUse` does not coerce an unvalidated tool name through `str()`; a non-string name is rejected as untrusted metadata.

## Raw JSON-string fields

Several narrow tools intentionally accept JSON text as a string. Those fields receive a second bounded parsing contract. UTF-8 size and lexical nesting depth are preflighted before parser invocation; duplicate-key and numeric-constant semantics are enforced by strict parser hooks before any parsed value is accepted:

- at most 1,000,000 UTF-8 bytes per JSON text field;
- maximum JSON nesting depth of 64, preflighted without invoking the parser;
- at most 100,000 parsed structural nodes;
- at most 50,000 entries in one parsed object or array;
- the same finite-number and bounded-integer rules after parsing;
- duplicate object keys are rejected recursively rather than accepted with last-key-wins semantics;
- Python JSON extensions `NaN`, `Infinity`, and `-Infinity` are rejected as non-standard numeric constants.

The guarded fields are:

- `plan_tests.existing_coverage_json`;
- `prioritize_regression.candidates_json`;
- `verify_locator_candidates.candidates_json`;
- `propose_locator_heal.candidates_json`;
- `validate_json_contract.instance_json`;
- `validate_json_contract.schema_json`.

Malformed, duplicate-key-ambiguous, or non-standard JSON is denied at the request boundary. Parser recursion cannot become an optimistic or partially verified tool result. In particular, an authority-bearing JSON Schema validation cannot derive a gate subject or `PASS` from a document whose meaning depends on duplicate-key collapse. Accepted raw JSON fields are not reparsed merely to create a repetition fingerprint; fingerprinting rechecks only the generic bounded request shape.

JSON Schema validation is additionally confined to resources already supplied in the schema document. Same-document references and embedded resources identified by `$id` remain available to the validator, but any reference that would require resolver retrieval from a file, network URL, or another external resource is `BLOCKED`. The validation tool is intentionally not a network or filesystem reader, and an attempted external reference does not inherit ambient authority merely because the JSON Schema library supports retrieval. Persisted denial details retain only a fixed normalized scheme category (`http`, `https`, `file`, `ftp`, `urn`, `data`, `relative`, or `other`), never the potentially secret-bearing URI or an attacker-chosen scheme string.

An explicit `$schema` dialect identifier is authoritative input, not a hint that may be silently reinterpreted. Unsupported or malformed explicit dialect identifiers are `NOT_VERIFIED`; supported legacy dialects such as Draft-07 remain valid. When `$schema` is absent, the tool uses a project-owned Draft 2020-12 default rather than inheriting whichever draft a future installed `jsonschema` release considers latest. Actual schema-bearing subresources are walked using the active JSON Schema specification, so an embedded resource cannot silently switch to an unknown or different dialect. The same traversal binds the supplied schema resource namespace: two schema resources may not resolve to the same effective identifier, and anchor names (including dynamic anchors) must be unique within one effective resource. Ambiguous duplicate resource/anchor identity is `NOT_VERIFIED` rather than accepting traversal-order first-wins behavior. The same anchor name remains valid in distinct resources. `$schema`-shaped objects used only as literal instance data are not promoted into schema authority. Boolean schemas remain valid JSON Schema values.

Schema checking and instance validation execute in a fresh isolated Python worker rather than borrowing signal/timer authority from the live Agent SDK process. The direct-call worker serializer first enforces the same 64-level nesting, 100,000-node, 50,000-container-item, 4,096-bit integer, finite-number, aggregate UTF-8, and strict JSON-value constraints used by the raw JSON boundary, so direct callers cannot bypass those resource limits or silently reinterpret Python tuples, non-string mapping keys, arbitrary Python objects, repeated/shared container identities, or cyclic container graphs as another JSON subject. UTF-8 size is counted before JSON encoder allocation. The parent then serializes one bounded JSON payload into a private temporary workspace, records the exact SHA-256 of those bytes, launches the current Python executable with isolated startup (`-I -S`), supplies only interpreter-owned installed dependency roots for `jsonschema`/`referencing`, and uses the shared restricted subprocess environment and process-tree cleanup boundary. The worker opens only a regular bounded payload file (with symlink refusal where the platform exposes `O_NOFOLLOW`), reads at most the configured payload ceiling, verifies the parent-provided SHA-256 before JSON parsing, and validates from those in-memory bytes. Temp-path replacement or mutation therefore cannot silently change the subject that receives validation authority. Worker output is bounded to 8,192 bytes, and the serialized worker input has a 2,100,000-byte defense-in-depth ceiling in addition to the live raw-field limits. PASS/FAIL authority also requires the worker to exit normally with complete, untruncated stdout and no stderr diagnostics; unexpected worker output is `NOT_VERIFIED`.

The worker owns a private **2-second `ITIMER_REAL`/`SIGALRM` evaluation budget** covering dialect inspection, schema checking, and instance validation, including hostile regular expressions and combinatorial schemas. The parent allows a separate **5-second startup/cleanup grace** around that evaluation budget so interpreter/dependency startup does not silently consume validation time; this grace cannot extend schema evaluation because the child timer is authoritative once evaluation begins. Parent interval timers, signal handlers, and caller-thread identity are not borrowed or replaced. If the child cannot provide its private evaluation timer, execution is `BLOCKED`; evaluation timeout or an incomplete/invalid worker result is `NOT_VERIFIED`; worker startup/cleanup failure is `BLOCKED`. Only a completely evaluated matching payload can produce `PASS`.

Failure details are deliberately low-information. Schema or payload mismatch diagnostics do not persist attacker-controlled property/reference paths, and worker failures do not echo temporary or dependency paths into validation results.

### Browser candidate bound

Locator verification and healing additionally allow at most **20 candidate entries**, matching the controlled browser execution surface. The limit is enforced for both the SDK-prefixed tool name and the internal tool name before a live tool body can construct browser execution state.

## Enforcement order

For the live Agent SDK path, the ordering is:

1. charge one tool-attempt and enforce the tool-call/wall-clock budget without inspecting unvalidated tool metadata;
2. validate tool-name and request shape plus bounded JSON fields;
3. if invalid, journal bounded denial metadata only and deny; raw unvalidated tool names and rejected input values are not persisted;
4. sanitize the accepted input for the repetition fingerprint;
5. hash the canonical fingerprint incrementally across encoder chunks;
6. apply repetition/circuit checks and charge network or mutation budgets when applicable;
7. evaluate deterministic policy;
8. enter the controlled tool;
9. revalidate in `LiveRuntimeServices.consume()` as defense in depth before tool-specific work.

This ordering is deliberate. A rejected large or malformed request still consumes one tool-call attempt, so repeated invalid requests cannot evade the request-count circuit by failing before execution. Once that tool budget is exhausted, the next request is denied before its potentially large body or unvalidated tool name is scanned. Invalid input does **not** consume network or mutation budget.

Pre-validation persistence is intentionally low-information. An input-bound denial records only its bounded reason code. A budget denial that occurs before request validation records the fixed state `tool_name_state="unvalidated"` rather than the raw tool name. This prevents oversized or secret-bearing rejected metadata from creating a second redaction/serialization workload or entering the durable journal.

The programmatic permission handler applies the same request validator, so the permission path cannot become a weaker input surface than `PreToolUse`. Canonical request budgeting remains owned by `RuntimeControl`/`PreToolUse` rather than duplicated in the permission callback.

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
