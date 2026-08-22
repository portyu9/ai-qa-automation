# Operations

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

Operating the ƳƤ AI QA Automation Framework follows the same invariant as its code:

> **Configured capability defines what can be attempted; observed evidence and deterministic validation define the runtime outcome.**

## Operating ladder

Use the narrowest operating mode that answers the engineering question. More environment-dependent execution should add evidence, not blur boundaries.

| Layer | Purpose | External dependency |
|---|---|---|
| Capability inspection | inspect local packages/executables/trust roots | none |
| Deterministic demo | exercise evidence/classification flow | none |
| Repository gates | quality, tests, primary evaluator, security tooling | none |
| Independent holdout | execute H-series adversarial corpus | none |
| Reference browser | Playwright against deterministic local SUT | browser runtime |
| Live model | bounded Claude Agent SDK session | Anthropic credential/provider |
| External systems | GitHub/Atlassian or real target browser/API/load/mobile | provider/target infrastructure |

Each layer keeps its own evidence source. A result from one trust domain does not silently prove another.

## Capability inspection

```bash
ai-qa doctor
```

`doctor` reports locally observable capabilities and configuration posture without treating local package/credential-variable presence as remote authentication evidence.

## Deterministic demonstration

```bash
ai-qa demo
```

The demo exercises the evidence-first classification flow without a live model/provider.

## Repository command surface

```bash
make quality   # compile + Ruff format/lint + Mypy
make test      # deterministic default pytest set
make eval      # fixed 34-scenario primary evaluator
make security  # pip check + Bandit + pip-audit + secret scan
make verify-local
make holdout
```

`make verify-local` combines the routine repository-contained gates and intentionally excludes the H-series holdout so ordinary development does not optimize against its exact fixtures.

Hard-safety expectations are not relaxed merely because a case fails.

## Run records

Each live run uses a confined record root:

```text
artifacts/<run_id>/
```

| Record | Purpose |
|---|---|
| `state.json` | canonical QA decision/evidence state |
| `evidence-manifest.json` | evidence/artifact metadata, identities, hashes, provenance |
| `runtime.json` | lease, fingerprint, budgets, circuits, pending mutation, journal head |
| `journal.jsonl` | append-only hash-chained lifecycle/tool chronology |
| `rollback/` | temporary trusted mutation snapshots |
| `audit-log.jsonl` | additional regulated-mode evidence/artifact registration chain |

`AI_QA_REGULATED_MODE=true` adds engineering traceability/retention classification; organization retention and compliance policy remain deployment responsibilities.

## Live agent workspace discipline

The control root, artifact root, and target worktree are distinct trust domains.

A live run requires:

- trusted framework markers in the control root;
- isolated Git-backed target worktree;
- artifact storage outside the target;
- exclusive OS-backed target lease;
- content-sensitive workspace fingerprint;
- explicit runtime policy for any write/network authority.

Target agent-looking files remain untrusted data.

## Autonomous mutation operations

Autonomous test mutation is deliberately exceptional.

Before a write:

1. write capability must be explicitly enabled;
2. path must be inside an approved test-code directory;
3. path must be relative, non-traversing, and non-symlink-owned;
4. target must be Git-backed;
5. workspace fingerprint must still match analyzed state;
6. no previous mutation transaction may remain unresolved.

The runtime snapshots prior bytes outside the SUT and keeps the transaction open until the current revision closes:

```text
patch-safety PASS
+ targeted pytest PASS
+ full-regression pytest PASS
= mutation commit eligibility
```

Model completion does not commit a mutation.

## Crash recovery

```bash
ai-qa recover artifacts/run-<id>
```

Recovery inspection verifies persisted state/journal integrity and mutation/revision metadata.

Automatic stale rollback occurs only when recovery can establish:

- trusted prior run ownership;
- exact target workspace identity;
- exact post-mutation fingerprint match;
- non-traversing/non-symlink pending target path;
- confined/non-symlink rollback path;
- original rollback-byte hash integrity.

If a developer or another process changed the workspace after the crash, the newer work is preserved and automatic restoration stops.

Recovery starts a **new** model session from persisted evidence when safe; it does not reconstruct hidden Claude conversation state.

See [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md).

## Result interpretation

Use [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) for terminal truth.

Operationally important rules:

- model `success` is not terminal `SUCCESS` by itself;
- `NOT_EXECUTED`, `NOT_OBSERVED`, `NOT_VERIFIED`, and `BLOCKED` validation states do not become PASS;
- same-gate contradictory PASS/FAIL at one revision remains unresolved;
- newer evidence supersedes older evidence through gate identity + revision lineage;
- provider-health outcomes are separate from the QA terminal outcome.

## Change baseline

For feature-branch/PR reasoning, supply an explicit trusted baseline:

```bash
export AI_QA_BASE_REF=origin/main
```

Bootstrap validates and resolves immutable base/merge-base SHAs before collecting committed plus dirty/untracked changes, risk domains, CODEOWNERS, test-impact candidates, and changed API-contract drift.

Do not infer the baseline from target instructions.

## Network operations

External network access is disabled by default.

Trusted network configuration uses canonical hostnames/IP literals only. It rejects wildcard/URL/port/path-shaped allowlist entries before runtime use.

For a non-local target:

```bash
export AI_QA_ALLOW_EXTERNAL_NETWORK=true
export AI_QA_ALLOWED_NETWORK_HOSTS='["qa.example.test"]'
```

API mutation remains independently disabled unless explicitly enabled.

Network-capable operations consume their own budget. Browser HTTP(S)/WebSocket traffic and API/k6 targets remain subject to the approved host boundary.

## Performance operations

Before k6 execution, confirm:

- target is explicitly non-production;
- target host is allowlisted;
- workload/script uses injected target binding;
- thresholds are predefined;
- script does not use forbidden remote modules/extensions/local files/unrelated hosts;
- non-local egress enforcement is established independently.

For non-local execution:

```bash
export AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true
```

This records an infrastructure prerequisite; it does not create network enforcement.

## External MCP operations

GitHub and Atlassian providers are disabled by default.

When enabled:

- use vendor-official integration paths;
- inject credentials/session through approved mechanisms;
- keep permissions least privilege;
- remember server identity does not grant tool authority;
- treat returned content as untrusted evidence;
- do not bypass an outage with an unapproved community integration.

GitHub receives server-side read-only defense in depth. Local action policy still independently evaluates external tool semantics.

## Traceability and inspection

```bash
ai-qa lineage artifacts/run-<id>
ai-qa lineage artifacts/run-<id> --format dot
ai-qa attest artifacts/run-<id>
ai-qa contract-diff --baseline old-openapi.yaml --current new-openapi.yaml
```

The attestation is content-addressed and unsigned. It supports integrity review without changing the QA outcome.

## GitHub Actions

`.github/workflows/ci.yml` is operator-dispatched with `workflow_dispatch`.

The workflow separates:

- quality/type checks across supported Python versions;
- deterministic pytest;
- primary adversarial evaluation;
- optional H-series holdout;
- optional security gates;
- optional Playwright reference-SUT execution;
- optional credentialed Agent SDK smoke execution.

The model path consumes `ANTHROPIC_API_KEY` only when selected.

## Pre-execution checklist

Before a live agent/provider/target run, verify:

1. trusted control root is correct;
2. target is an isolated Git-backed worktree;
3. artifact storage is outside the target;
4. secrets come from an approved environment/secret manager;
5. network allowlist contains only intended target hosts;
6. write/API-mutation authority is disabled unless genuinely required;
7. execution budgets fit the objective;
8. k6 target is non-production and infrastructure egress is independently constrained;
9. external provider permissions are least privilege;
10. evidence/artifacts fit approved data-access and retention rules.

## Related documentation

- [`README.md`](README.md) — documentation landing page
- [`SETUP.md`](SETUP.md) — exact configuration contracts
- [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) — runtime truth
- [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) — mutation/recovery state machine
- [`SECURITY.md`](SECURITY.md) — security controls
- [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) — evidence ownership

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
