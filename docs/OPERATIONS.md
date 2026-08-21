# Operations

## Local deterministic gate

```bash
make quality
make test
make eval
make security
```

`ai-qa doctor` reports locally observable capabilities. Missing optional packages, executables, or device infrastructure remain `NOT_VERIFIED`.

## Run artifacts and control records

Each run uses `artifacts/<run_id>/`. Evidence and artifacts are recorded in `evidence-manifest.json` with hashes and sanitization status. Canonical QA decisions are persisted in `state.json`.

Operational control data is separate:

- `runtime.json` — workspace fingerprint, execution-budget snapshot, tool-circuit state, pending mutation metadata, lease identity, and journal head;
- `journal.jsonl` — append-only hash-chained lifecycle/tool audit records;
- `rollback/` — temporary trusted mutation backups while a change revision is open.

With `AI_QA_REGULATED_MODE=true`, evidence/artifact registration also appends a hash-chained `audit-log.jsonl`; newly registered artifacts receive the `regulated` retention classification. The repository does not define an organization retention schedule.

## Live agent and workspace ownership

The trusted control root and target workspace must be disjoint. The runtime rejects a control root missing `CLAUDE.md` or `.claude/settings.json`, uses only the control-plane project settings, and treats target content as untrusted data.

A live run acquires an exclusive OS-backed lease for the target worktree. Autonomous writes require a Git-backed target and a repository fingerprint matching the baseline captured by the runtime. Concurrent or out-of-band changes block mutation.

Test mutations are transactional. The target file is snapshotted outside the SUT before a write. The backup is discarded only after patch safety, targeted pytest, and full regression close the change revision. Failed or unverified runs restore the prior content. If a process crashes with a mutation open, the next workspace lease can restore that transaction only when the current fingerprint still matches the crashed run; later operator changes make recovery block rather than overwrite them.

## Recovery

```bash
ai-qa recover artifacts/run-<id>
```

Recovery verifies `state.json`, the runtime journal hash chain, current revision closure, and pending mutation metadata. It reports whether a new model session can safely start from persisted evidence. It does not replay a previous Claude conversation.

## Change baseline and traceability

Set `AI_QA_BASE_REF=origin/main` (or another explicit trusted ref) when the run should analyze committed branch/PR changes relative to a baseline. The ref is validated and resolved to immutable baseline and merge-base SHAs. Bootstrap also records CODEOWNERS resolution, deterministic test-impact candidates, and changed OpenAPI/Swagger compatibility drift when applicable.

```bash
ai-qa lineage artifacts/run-<id>
ai-qa lineage artifacts/run-<id> --format dot
ai-qa attest artifacts/run-<id>
ai-qa contract-diff --baseline old-openapi.yaml --current new-openapi.yaml
```

The attestation is content-addressed but intentionally unsigned; it does not alter the run terminal status or claim compliance.

## Network behavior

External network access is disabled by default. Allowed hosts are explicit configuration. API probes are read-only unless mutating methods are separately enabled, and API/browser adapters do not inherit ambient proxy configuration. Browser HTTP(S)/WebSocket traffic and k6 targets pass through the runtime allowlist. For non-local k6 execution, `AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true` is also required as an explicit trusted assertion that infrastructure-level egress controls are present.

Runtime hooks separately cap network-capable tool attempts and open a per-tool circuit after repeated failures. External integration failure does not fabricate remote evidence and does not invalidate unrelated local deterministic evidence.

## GitHub Actions

The checked-in workflow is manual-only (`workflow_dispatch`) and has no push, pull-request, or scheduled trigger.
