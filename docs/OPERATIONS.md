# Operations

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

Operational guidance for the ƳƤ AI QA Automation Framework follows the same evidence rule as the runtime: **configured commands define execution paths; observed results and deterministic validation define outcomes**.

## Verification ladder

Use progressively more environment-dependent gates rather than mixing them together:

| Stage | Purpose | External credentials |
|---|---|---|
| 0. Capability inspection | Inspect locally visible packages/executables/control root | None |
| 1. Deterministic demo | Exercise a local evidence/classification scenario | None |
| 2. Routine repository verification | Quality, tests, primary evaluation, static security | None |
| 3. Holdout readiness | Execute separate H-series corpus intentionally | None |
| 4. Reference browser | Exercise Playwright against the deterministic local SUT | None, browser runtime required |
| 5. Live model | Exercise bounded Claude Agent SDK path | Anthropic key |
| 6. External integrations | Exercise GitHub/Atlassian MCP or real target systems | Provider/environment specific |

A later stage does not retroactively prove an earlier stage; inspect each applicable gate on its own evidence.

## Stage 0 — capability inspection

```bash
ai-qa doctor
```

`doctor` reports locally observable capabilities. It does not validate remote credentials or infer provider availability from local configuration.

## Stage 1 — deterministic local demonstration

```bash
ai-qa demo
```

This credential-free path demonstrates the evidence-first failure-analysis flow using repository-contained behavior.

## Stage 2 — routine repository-contained verification

The local targets are deliberately separated so a reviewer can see which class failed:

```bash
make quality   # compile, Ruff format/lint, Mypy
make test      # default deterministic pytest suite
make eval      # fixed 34-scenario primary evaluator
make security  # pip compatibility, Bandit, pip-audit, detect-secrets
```

The combined routine set is:

```bash
make verify-local
```

`make verify-local` intentionally excludes the holdout corpus so routine development does not tune directly against the holdout set.

## Stage 3 — explicit holdout readiness gate

```bash
make holdout
```

A holdout failure is a signal to investigate the implementation. Do not make the gate green by moving the case into the primary corpus, weakening its expected outcome, or relaxing a hard-safety threshold after seeing the result.

## Run artifacts and control records

Each live run uses:

```text
artifacts/<run_id>/
```

Key records include:

- `state.json` — canonical QA decision state;
- `evidence-manifest.json` — evidence/artifact metadata, hashes, and provenance;
- `runtime.json` — workspace fingerprint, execution budgets, tool circuits, pending mutation, lease identity, and journal head;
- `journal.jsonl` — append-only hash-chained lifecycle/tool records;
- `rollback/` — temporary trusted backups while a mutation transaction is open.

With `AI_QA_REGULATED_MODE=true`, evidence/artifact registration also appends a hash-chained `audit-log.jsonl`, and newly registered artifacts receive the `regulated` retention classification. Organization retention and compliance policy remain deployment concerns.

## Live agent and workspace ownership

The trusted control root and target workspace must be disjoint. The runtime requires trusted project markers, uses only control-plane project settings, and treats target content as untrusted data.

A live run acquires an exclusive OS-backed lease for the target worktree. Autonomous writes additionally require:

- a Git-backed target;
- a workspace fingerprint matching the runtime baseline;
- write policy explicitly enabled;
- an approved test path;
- no unresolved previous mutation transaction.

Mutation paths are resolved under the target workspace and reject absolute paths, `..` traversal, and symlink components so autonomous ownership cannot be redirected through an ambiguous alias.

Test mutations are transactional. The target file is snapshotted outside the SUT before a write. The rollback point is committed only after patch safety, targeted pytest, and full regression close the current change revision. Runs that do not close the mutation transaction restore prior content. Crash recovery refuses to overwrite later human/out-of-band edits.

See [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md).

## Recovery

```bash
ai-qa recover artifacts/run-<id>
```

Recovery verifies persisted state/journal integrity, the current revision's closure, and pending mutation metadata. It reports whether a **new model session** may safely start from persisted evidence.

Recovery does not replay a previous Claude conversation or reconstruct hidden model reasoning.

## Change baseline and traceability

Set an explicit trusted base ref when a feature branch/PR should be evaluated relative to its baseline:

```bash
export AI_QA_BASE_REF=origin/main
```

Bootstrap validates the ref and resolves immutable baseline/merge-base SHAs before recording committed plus dirty/untracked changes, CODEOWNERS, test-impact candidates, and changed OpenAPI/Swagger drift where applicable.

Useful inspection commands include:

```bash
ai-qa lineage artifacts/run-<id>
ai-qa lineage artifacts/run-<id> --format dot
ai-qa attest artifacts/run-<id>
ai-qa contract-diff --baseline old-openapi.yaml --current new-openapi.yaml
```

The attestation is content-addressed but intentionally unsigned; it neither signs the run nor changes its terminal outcome.

## Network behavior

External network access is disabled by default. Allowed hosts are explicit configuration. API probes are read-only unless mutating methods are separately enabled, and API/browser adapters avoid ambient proxy inheritance.

Network-capable tool calls consume their own execution budget rather than sharing only the total tool-call limit. Browser HTTP(S)/WebSocket traffic and k6 targets pass through runtime allowlists. Performance-target policy rejects explicit production environments and production-like DNS labels even if a caller supplies a contradictory non-production label. Non-local k6 additionally requires `AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true` as an explicit trusted assertion that infrastructure-level egress controls exist.

## GitHub Actions

`.github/workflows/ci.yml` is intentionally manual-only (`workflow_dispatch`). It has no `push`, `pull_request`, or scheduled trigger.

The workflow separates:

- quality on supported Python versions;
- primary deterministic evaluations;
- optional H-series holdout;
- optional security gates;
- optional Playwright reference-SUT gate;
- optional credentialed model smoke.

The live model gate defaults off and uses the `ANTHROPIC_API_KEY` repository secret only when explicitly selected.

## Pre-run checklist

Before intentionally running the live agent or an external integration, confirm:

1. the control root is the trusted ƳƤ AI QA Automation Framework repository;
2. the target is an isolated Git-backed worktree;
3. artifacts are outside the target worktree;
4. secrets are injected through the environment/secret manager, never committed;
5. network hosts are restricted to the intended non-production systems;
6. mutation/API-write flags are disabled unless the objective genuinely requires them;
7. budgets are appropriate for the objective and have not been broadened casually;
8. any k6 target is explicitly non-production and infrastructure egress controls are independently established;
9. external MCP permissions are least-privilege;
10. evidence/artifacts are handled under approved data-retention and access controls.

## Setup boundary

For exact environment variables and credential prerequisites, see [`SETUP.md`](SETUP.md). For readiness and evidence semantics, see [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) and [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
