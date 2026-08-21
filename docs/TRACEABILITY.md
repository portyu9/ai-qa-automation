# Traceability and run attestation

The platform persists enough structured information to inspect a run without relying on chat history.

## Lineage graph

```bash
ai-qa lineage artifacts/run-<id>
ai-qa lineage artifacts/run-<id> --format dot
```

The graph connects the run to observed evidence, artifacts, hypotheses, validation gates, and bounded runtime-journal events. Validation-to-evidence references are checked while the graph is built; missing referenced evidence is surfaced as a warning.

The DOT output is intended for Graphviz or architecture/debugging workflows. It does not modify run state.

## Content-addressed attestation

```bash
ai-qa attest artifacts/run-<id>
```

The attestation hashes persisted `state.json`, `evidence-manifest.json`, `runtime.json`, and `journal.jsonl`, verifies the operational journal when present, records target/configuration/model/SDK provenance, and reports whether a mutation is still pending.

The resulting object is deliberately **unsigned**. Its `attestation_digest` makes the inspected statement content-addressable, but the repository does not pretend that a SHA-256 digest is an organizational signature, a compliance certification, or a test PASS. A deployment can wrap this object in an external signing system if trusted identity is required.
