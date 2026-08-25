# Persistence Resource Boundary

Authority-bearing state is only useful if its durability path cannot become an unbounded resource surface. Canonical run state, evidence manifests, and regulated audit metadata therefore retain their existing durable file ceilings while enforcing those ceilings before complete JSON text or complete UTF-8 copies are materialized.

## Protected persistence paths

Two durable registries are covered:

- `StateStore` persists canonical `AgentRunState` to `state.json` under the existing 16,000,000-byte ceiling.
- `EvidenceStore` persists `evidence-manifest.json` under the existing 16,000,000-byte ceiling, alongside the separate evidence/artifact count and artifact-byte limits.

The change does not increase either persistence threshold.

## Pre-serialization contract

`io_safety.py` owns a bounded JSON preflight used by these persistence paths. Before `JSONEncoder` is allowed to emit text, the preflight:

- bounds the cumulative JSON-escaped byte contribution of string values and object keys without constructing escaped copies;
- validates Unicode before a potentially oversized string reaches encoder iteration;
- rejects circular structures;
- rejects non-finite numbers and integers above the deterministic 4,096-bit numeric ceiling;
- limits nesting depth to 128, structural nodes to 1,000,000, and items in any one container to 100,000;
- rejects shape or string content that already exceeds the configured persistence ceiling before encoder iteration.

The standard-library JSON encoder remains the sole formatting authority for punctuation, indentation, separators, and ordering. Its emitted chunks are counted incrementally in UTF-8, so the exact aggregate document ceiling is enforced during the dry-run capacity check and again during the atomic write. Structural punctuation can therefore be the final bytes that cross the ceiling without requiring a second JSON implementation. A value that fails the shape/string preflight never reaches encoder iteration.

## Canonical state

`StateStore.save()` no longer calls `AgentRunState.model_dump_json()` for the complete state. It exposes one declared state field at a time to Pydantic JSON-mode conversion and to the bounded serializer. This preserves the existing JSON representation while avoiding a second complete JSON-compatible object, complete text string, and complete UTF-8 copy of the state.

A failed save writes only to an owned temporary file. The prior durable `state.json` remains untouched unless the bounded write completes, the temporary file is flushed with `fsync`, ownership is rechecked, and the atomic replacement succeeds.

## Evidence manifest

`EvidenceStore` keeps registered `EvidenceItem` and `ArtifactRecord` objects as references while calculating capacity and writing the manifest. Each registry model is converted one field at a time instead of first materializing a duplicate Python representation of the entire registry.

Before recursive redaction/sanitization, a new `EvidenceItem` must itself satisfy the persistence serialization boundary. This prevents an oversized or structurally hostile evidence record from reaching the recursive sanitizer and only discovering the manifest limit after additional copies have already been created.

Cumulative manifest capacity is checked before audit registration and durable manifest replacement. If a non-regulated evidence registration would exceed the manifest ceiling, the staged in-memory item is removed and the previous manifest remains authoritative. Regulated-mode recovery semantics remain unchanged: once an audit record is durably appended, the corresponding live registry entry is retained if a later manifest write fails so the framework cannot pretend the audited event disappeared.

## Compatibility and authority

The state and manifest JSON representation retains the existing indentation, key-ordering behavior, Unicode escaping behavior, and Pydantic field serialization semantics. Restore paths remain strict, bounded, duplicate-key rejecting, and schema validated.

Persistence success does not make evidence true and cannot create `SUCCESS`. This boundary only controls resource use and durability mechanics; deterministic validation remains the sole terminal authority.

## What this does not claim

The bound begins when an already-created Python state/evidence object is submitted to the persistence layer. It cannot prevent an upstream caller from allocating an oversized object before `StateStore.save()` or `EvidenceStore.add()` is invoked.

An accepted individual field may still be large, up to the enclosing persistence ceiling. The invariant is bounded peak framework serialization work, not zero-copy persistence. Filesystem, process-memory, and host-level quotas remain deployment responsibilities outside this application-level boundary.
