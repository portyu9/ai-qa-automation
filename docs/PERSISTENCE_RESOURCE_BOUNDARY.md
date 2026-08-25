# Persistence Resource Boundary

Authority-bearing state is only useful if its durability path cannot become an unbounded resource surface. Canonical run state, evidence manifests, and regulated audit records therefore retain their existing durable ceilings while enforcing shape and byte bounds before complete JSON text or complete UTF-8 copies are materialized.

## Protected persistence paths

The boundary covers three authority-bearing persistence paths:

- `StateStore` persists canonical `AgentRunState` to `state.json` under the existing 16,000,000-byte ceiling.
- `EvidenceStore` persists `evidence-manifest.json` under the existing 16,000,000-byte ceiling, alongside the separate evidence/artifact count and artifact-byte limits.
- regulated `EvidenceStore` appends `audit-log.jsonl` records under the existing 1,000,000-byte per-line ceiling and 64,000,000-byte cumulative log ceiling.

This hardening does not increase any persistence threshold.

## Pre-serialization contract

`io_safety.py` owns the bounded JSON preflight used by these persistence paths. Before `JSONEncoder` may emit text, the preflight:

- bounds cumulative JSON-escaped byte contribution of string values and object keys without constructing escaped copies;
- validates Unicode before a potentially oversized string reaches encoder iteration;
- rejects circular structures;
- rejects non-finite numbers and integers above the deterministic 4,096-bit numeric ceiling;
- limits nesting depth to 128, structural nodes to 1,000,000, and items in any one container to 100,000;
- rejects shape or string content that already exceeds the configured persistence ceiling before encoder iteration.

The standard-library JSON encoder remains the sole formatting authority for punctuation, separators, indentation, ordering, and escaping. Its emitted chunks are counted incrementally in UTF-8, so the exact aggregate ceiling is enforced during capacity checking and again during writing. Structural punctuation may therefore be the final bytes that cross a ceiling without requiring a second JSON implementation.

## Canonical state

`StateStore.save()` no longer calls `AgentRunState.model_dump_json()` for the complete state. It exposes one declared state field at a time to Pydantic JSON-mode conversion and to the bounded serializer. This preserves the existing JSON representation while avoiding a second complete JSON-compatible object, complete text string, and complete UTF-8 copy of the state.

A failed save writes only to an owned temporary file. The previous durable `state.json` remains untouched unless the bounded write completes, the temporary file is flushed with `fsync`, ownership is rechecked, and atomic replacement succeeds.

## Evidence manifest

`EvidenceStore` keeps registered `EvidenceItem` and `ArtifactRecord` objects as references while calculating capacity and writing the manifest. Each registry model is converted one field at a time instead of first materializing a duplicate Python representation of the entire registry.

Before recursive redaction/sanitization, a new `EvidenceItem` must itself satisfy the persistence serialization boundary. This prevents an oversized or structurally hostile evidence record from reaching recursive sanitization and only discovering the manifest limit after additional copies have already been created.

Cumulative manifest capacity is checked before audit registration and durable manifest replacement. If a non-regulated evidence registration would exceed the manifest ceiling, the staged in-memory item is removed and the prior manifest remains authoritative. Regulated-mode recovery semantics remain stricter: once an audit record is durably appended, the corresponding live registry entry is retained if a later manifest write fails so the framework cannot pretend the audited event disappeared.

## Regulated audit log

The regulated audit path applies the same resource discipline before append:

1. the raw audit payload is shape/string/byte preflighted before `sanitize()` is allowed to recurse over it;
2. the event-core SHA-256 is computed incrementally from the same compact, sorted-key JSON representation historically used for audit event hashes;
3. the final record is dry-run sized with the terminating newline included in the 1,000,000-byte line ceiling;
4. the cumulative 64,000,000-byte log ceiling is checked against the already-open owned regular file before any append;
5. the final record is streamed through bounded descriptor writes that handle short writes and is flushed with `fsync` before in-memory audit sequence/hash authority advances;
6. if a caught append/flush failure occurs after bytes were written, the descriptor is truncated to its exact pre-append length and `fsync`ed before the store may continue;
7. if rollback cannot be durably proven, that `EvidenceStore` instance latches regulated audit writes closed rather than appending behind an uncertain tail.

For the same accepted record, event hash bytes and audit-line JSON formatting therefore remain compatible with the prior representation; the implementation changes allocation and failure-recovery behavior, not the audit-chain digest contract.

A process crash, power loss, or uncatchable termination can still interrupt the append before in-process rollback runs. On restart, strict bounded audit-chain verification rejects an incomplete or malformed tail. The application does not claim filesystem-level atomic append semantics that the host does not provide.

## Evidence content-hash recovery semantics

New regulated `evidence_registered` records declare the content-hash algorithm `sha256-canonical-json-sorted-keys`. The evidence content hash is computed incrementally from compact UTF-8 JSON with recursively sorted object keys. This makes the hash stable when the manifest's sorted-key persistence normalizes nested dictionary order during durable write/reopen.

Audit records created before this algorithm marker are verified through the bounded legacy order-sensitive representation so already-valid historical records remain supported when their original insertion order is reconstructible. If a historical manifest has already lost the insertion order required to reproduce such an unmarked legacy hash, the framework cannot safely infer that missing order and fails closed. It does not reinterpret or silently upgrade the historical digest.

Unknown future or malformed content-hash algorithm identifiers are rejected rather than treated as a known hash contract.

## Compatibility and authority

Canonical state and evidence-manifest JSON retain the existing indentation, key-ordering behavior, Unicode escaping behavior, and Pydantic field serialization semantics. Audit event-chain hashes and line formatting retain their prior representation. Restore paths remain strict, bounded, duplicate-key rejecting, and schema validated.

Persistence success does not make evidence true and cannot create `SUCCESS`. This boundary controls resource use, integrity, and durability mechanics; deterministic validation remains the sole terminal authority.

## What this does not claim

The bound begins when an already-created Python state/evidence object is submitted to the persistence layer. It cannot prevent an upstream caller from allocating an oversized object before `StateStore.save()` or `EvidenceStore.add()` is invoked.

An accepted individual field may still be large, up to the enclosing persistence ceiling. The invariant is bounded framework serialization work rather than zero-copy persistence. Filesystem quotas, process-memory limits, and host-level containment remain deployment responsibilities outside this application-level boundary.
