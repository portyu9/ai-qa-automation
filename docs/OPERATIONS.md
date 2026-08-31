# Operations

> [!IMPORTANT]
> **Configured capability defines what can be attempted. Observed evidence and deterministic validation define what the runtime can claim.**

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Setup](SETUP.md) · [Runtime control](RUNTIME_CONTROL.md) · [Troubleshooting](TROUBLESHOOTING.md)

---

## Operating ladder

Use the narrowest operating mode that answers the engineering question. More environment-dependent execution should add evidence—not blur boundaries.

| Layer | Purpose | External dependency |
|---|---|---|
| **Capability inspection** | inspect local packages/executables/trust roots | none |
| **Deterministic demo** | exercise evidence/classification flow | none |
| **Repository gates** | quality, tests, primary evaluator, security tooling | none |
| **Sequestered readiness** | repository-visible H-series cases separated from routine primary execution | none |
| **Reference browser** | Playwright against deterministic local SUT | browser runtime |
| **Live model** | bounded Claude Agent SDK session | Anthropic provider/credential |
| **External systems** | GitHub/Atlassian or real browser/API/load/mobile targets | provider/target infrastructure |

---

## Local inspection and demo

```bash
ai-qa doctor
ai-qa demo
```

`doctor` reports locally observable capability/configuration posture without treating local package or credential-variable presence as remote provider evidence.

`demo` exercises the deterministic evidence-first flow without a live model/provider.

---

## Repository command surface

```bash
make quality       # compile + Ruff format/lint + Mypy
make test          # deterministic default pytest set
make eval          # fixed 34-case primary deterministic control evaluator
make security      # dependency/static/secret security tooling
make verify-local  # routine local deterministic aggregate
make holdout       # repository-visible sequestered H-series readiness evaluator
```

The legacy holdout command remains separate from the routine aggregate so routine primary execution does not directly include its exact readiness fixtures. Because those fixtures are committed in the repository, separation does not make them blind, unseen, or independent evidence.

> [!NOTE]
> These commands define the operating surface. A command's existence is not a claim about a different revision/environment where it has not been executed.

---

## Run record anatomy

Each live run uses a confined root:

```text
artifacts/<run_id>/
```

| Record | Purpose |
|---|---|
| `state.json` | canonical QA decision/evidence state |
| `runtime.json` | lease, fingerprint, budgets, circuits, pending mutation, journal head |
| `evidence-manifest.json` | evidence/artifact identities, hashes, provenance |
| `journal.jsonl` | append-only hash-chained lifecycle/tool chronology |
| `rollback/` | temporary trusted mutation snapshots while a transaction is open |
| `audit-log.jsonl` | regulated-mode evidence/artifact registration chain |

`AI_QA_REGULATED_MODE=true` adds engineering traceability/retention classification. Organization policy still owns legal/compliance retention and access controls.

---

## Observability and correlation

Observability is deliberately downstream of runtime truth. Structured logs, traces, and metrics can describe execution; they cannot authorize an action, create evidence, close a validation gate, commit a mutation, or promote a terminal outcome.

The framework provides:

- sanitized JSON lifecycle logging through `emit_event`;
- optional OpenTelemetry spans through the global tracer provider;
- optional OpenTelemetry metrics through the global meter provider;
- `run_id` / `session_id` correlation in canonical state and structured run records;
- durable tool/lifecycle correlation through the hash-chained run journal;
- evidence/artifact correlation through IDs, manifests, hashes, and validation lineage.

No exporter or telemetry backend is hard-coded. Deployment may configure an OpenTelemetry SDK/exporter using its normal environment or bootstrap policy; absence or failure of telemetry collection never changes deterministic QA truth.

### Metric instruments

| Instrument | Kind | Meaning |
|---|---|---|
| `ai_qa.agent.runs` | counter | completed live-agent run reports grouped by deterministic terminal outcome |
| `ai_qa.agent.duration` | histogram | terminal live-agent wall-clock duration in seconds |
| `ai_qa.agent.tool_calls` | histogram | controlled tool-call count at terminal run reporting |
| `ai_qa.tool.events` | counter | requested/completed/failed/denied lifecycle events by coarse tool surface |
| `ai_qa.policy.denials` | counter | fail-closed denial events by bounded runtime/policy category |
| `ai_qa.mcp.outcomes` | counter | observed GitHub/Atlassian provider success/failure outcome family |

Metric attributes are intentionally low-cardinality. They may contain bounded values such as terminal outcome, coarse tool surface, policy category, approved provider, and normalized provider outcome. They **do not** contain run IDs, objectives, file paths, selectors, URLs, raw tool arguments, provider payloads, credentials, or external text.

The journal remains authoritative lifecycle provenance: metrics are projected only after a journal event is durably appended, and instrumentation failure is fail-soft. A telemetry outage therefore cannot erase the journal event or turn a denied/failed action into a successful one.

> [!NOTE]
> `run_id` is appropriate for logs, traces, state, evidence, and artifacts where direct correlation is required. It is intentionally excluded from metric labels to prevent unbounded cardinality.

---

## Live workspace discipline

A live run requires:

- trusted framework markers in the control root;
- isolated Git-backed target worktree;
- artifact storage outside the target;
- exclusive OS-backed workspace lease;
- content-sensitive workspace fingerprint;
- explicit runtime policy for any write/network authority.

Target agent-looking files remain untrusted data.

### Trust-domain shape

```text
trusted framework   ─┐
trusted artifacts    ├─ must not overlap the SUT
isolated SUT         ─┘
```

---

## Autonomous mutation operations

Autonomous mutation is exceptional and transaction-backed.

Before a write, the runtime requires:

1. explicit write enablement;
2. a policy-approved **Python** path under `tests/` or `generated_tests/`;
3. relative, non-traversing, non-symlink ownership;
4. a Git-backed isolated target;
5. a fingerprint still matching analyzed state;
6. no unresolved prior mutation transaction.

Commit eligibility is intentionally subject-bound:

```text
patch-safety PASS for changed path
+ targeted pytest PASS selecting that exact path
+ full-regression pytest PASS
= current revision may commit
```

A `-k`-only run or targeted test of a different file is diagnostic evidence, not mutation closure.

Model completion does not commit a mutation.

Live rollback is also coordinated across the two durable authority records. If a mutation advanced `change_revision`, `state.json` receives a current-revision `NOT_VERIFIED` rollback gate **before** target bytes may be restored or `runtime.json.pending_mutation` may be cleared. Runtime closure then restores/removes the target and clears pending authority; a final state checkpoint reconciles modified-file accounting. A pre-close state-save failure therefore leaves the candidate bytes and pending recovery authority untouched, while a post-close state-save failure still leaves durable `NOT_VERIFIED` lineage rather than stale SUCCESS.

---

## Crash recovery

```bash
ai-qa recover artifacts/run-<id>
```

Recovery inspection evaluates persisted state/journal ownership plus current mutation/revision closure.

Automatic stale rollback requires:

- trusted prior run ownership;
- exact target workspace identity;
- exact post-mutation fingerprint match;
- non-traversing, non-symlink pending target path;
- owned non-symlink rollback directory/path;
- original rollback-byte hash integrity;
- pending mutation revision provenance that is coherent with canonical `state.json` lineage.

For a mutation that advanced canonical state, persisted `change_revision` must be exactly one greater than the pending transaction's `change_revision_before`. A larger or otherwise impossible gap is blocked before recovery writes. Once all ownership, fingerprint, backup, and revision checks pass, stale recovery may restore/remove target bytes **while durable `runtime.json.pending_mutation` and rollback backup authority remain intact**. It then persists the prior run's current-revision `NOT_VERIFIED`/rolled-back lineage and only after that durable state checkpoint may it clear pending runtime authority.

If a human or another process changed the workspace after the crash, newer work is preserved and automatic restoration stops. If canonical rollback-lineage persistence fails after restoration, recovery closure stops: restored bytes coexist with retained pending runtime/backup authority, so the prior run cannot be represented as clean or closed.

Recovery inspection uses the same exact-path targeted-validation standard as terminal truth. It starts a **new** model session from persisted evidence when appropriate; it does not reconstruct hidden Claude conversation state.

---

## Result interpretation

Use [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) as the canonical outcome contract.

Operationally important rules:

- model `success` is not terminal `SUCCESS` by itself;
- `NOT_EXECUTED`, `NOT_OBSERVED`, `NOT_VERIFIED`, and `BLOCKED` validations are never promoted to PASS;
- same-gate contradictory PASS/FAIL at one revision remains unresolved;
- newer evidence supersedes older evidence through gate identity + revision lineage;
- provider-health outcomes are independent from QA terminal truth;
- integrity verification is independent from test correctness.

---

## Change baseline

For feature-branch/PR reasoning:

```bash
export AI_QA_BASE_REF=origin/main
```

Bootstrap validates the configured baseline and merge base before collecting:

- committed changes;
- dirty/untracked changes;
- risk domains;
- CODEOWNERS context;
- test-impact candidates;
- changed API-contract drift.

A clean worktree is not interpreted as “no feature-branch change.”

---

## Network operations

External network access is disabled by default.

```bash
export AI_QA_ALLOW_EXTERNAL_NETWORK=true
export AI_QA_ALLOWED_NETWORK_HOSTS='["qa.example.test"]'
```

Trusted network configuration uses exact canonical hostnames/IPs only. API mutation remains independently disabled unless explicitly enabled.

Network-capable operations consume a dedicated network budget in addition to total tool budget.

---

## Performance operations

Before **any** k6 execution, establish all of the following:

- explicit non-production target classification;
- allowlisted target host;
- injected target binding;
- predefined thresholds;
- script/import restrictions satisfied;
- deployment-level egress containment independently established.

```bash
export AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true
```

> [!WARNING]
> The flag records the prerequisite; it does not enforce the network. The deployment must supply the firewall/proxy/container/network policy.

The prerequisite applies to localhost too because arbitrary JavaScript can construct destinations dynamically.

---

## External MCP operations

GitHub and Atlassian providers are disabled by default.

When deliberately enabled:

- use vendor-official paths;
- inject credentials/session through approved mechanisms;
- keep permissions least privilege;
- remember provider identity does not grant action authority;
- treat returned content as untrusted evidence;
- do not bypass an outage with an unapproved fallback provider.

GitHub receives server-side read-only defense in depth; local deterministic policy still evaluates every external action name.

---

## Traceability and inspection

```bash
ai-qa lineage artifacts/run-<id>
ai-qa lineage artifacts/run-<id> --format dot
ai-qa attest artifacts/run-<id>
ai-qa contract-diff --baseline old-openapi.yaml --current new-openapi.yaml
```

The unsigned attestation verifies persisted integrity properties—including registered artifact bytes—without changing terminal QA truth.

See [`TRACEABILITY.md`](TRACEABILITY.md).

---

## GitHub Actions

`.github/workflows/ci.yml` keeps automatic `pull_request` feedback and the fixed owner `repository_dispatch` event `trusted-pr-validation`. Ordinary PR validation is read-only, secret-free, exact-subject development evidence. It can be used continuously without being treated as the protected merge oracle.

The trusted dispatch path executes the prospective merge subject from the default-branch workflow definition. It verifies the exact merge/base/head tuple and requires an exact bounded base/subject Git-object manifest for any changed protected control-plane root before repository scripts execute.

The trusted validation domains cover:

- exact CPython 3.11.16 full-quality validation and exact CPython 3.14.7 deterministic compatibility validation; the 3.11 lane owns Ruff, strict Mypy, full deterministic pytest, and coverage, while the 3.14 lane runs compile plus full deterministic compatibility pytest without duplicating lint/type/coverage authority;
- the fixed 34-case primary deterministic control evaluation;
- security scanning;
- supply-chain verification, runtime dependency audit, SBOM/repeatability/container evidence;
- deterministic Playwright reference-SUT execution.

`Required PR Gate` executes with `if: always()` and fails unless every validation prerequisite succeeds. It is deterministic aggregate evidence, not protected merge authority.

Terminal `Trusted PR Gate` publication is intentionally a different identity boundary. Job `trusted-status` is owner/default-branch/repository-dispatch only, enters Environment `trusted-pr-gate`, keeps its native GitHub Actions token read-only, mints a short-lived least-privilege dedicated GitHub App installation token, and publishes only after `scripts/trusted_pr_control.py` revalidates the live PR/head/base/merge-ref subject.

The independent-identity design becomes active merge authority only after the external GitHub App installation/permissions, Environment trusted-ref restriction, App client ID/private-key configuration, Actions Policy, and `Protect Main` required-status binding to the dedicated App integration have been independently observed. Repository source cannot certify those platform facts. Historical `Trusted PR Gate` evidence from GitHub Actions integration ID `15368` belongs to the earlier control plane and does not prove the new App boundary.

`.github/workflows/manual-validation.yml` is `workflow_dispatch` only and remains outside protected merge evidence. H-series/model evidence is separate; the optional model smoke consumes `ANTHROPIC_API_KEY` only when explicitly selected and available.

The workflow contract is deterministically checked by `scripts/verify_ci_contract.py`. See [CI/CD and Repository Governance](CI_CD.md) and [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md).

---

## Pre-execution checklist

Before a live provider/target run:

- [ ] trusted control root is correct;
- [ ] target is an isolated Git-backed worktree;
- [ ] artifact root is outside the target;
- [ ] credentials come from an approved environment/secret manager;
- [ ] host allowlist contains only intended targets;
- [ ] write/API-mutation authority is disabled unless required;
- [ ] execution budgets match the objective;
- [ ] any k6 run has actual deployment egress containment;
- [ ] external provider permissions are least privilege;
- [ ] evidence/artifacts fit approved data-access and retention policy.

For protected PR operation after the independent-status migration, also require the dedicated App installation, `trusted-pr-gate` Environment restriction, required-status App binding, strict/up-to-date branch protection, and current exact-subject trusted-dispatch evidence to be independently observed.

---

## Failure operating rule

When a run is blocked or fails, do **not** make the system greener by bypassing the control that exposed the problem.

Prefer this order:

```text
classify the failure
→ identify the evidence owner
→ repair the environment/configuration/code at that layer
→ rerun the same deterministic gate
```

See [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for symptom-oriented guidance.

---

## Related documentation

- [CI/CD and repository governance](CI_CD.md)
- [Setup](SETUP.md)
- [Runtime control and recovery](RUNTIME_CONTROL.md)
- [Runtime result contract](RESULT_CONTRACT.md)
- [Security architecture](SECURITY.md)
- [Verification boundaries](VERIFICATION_BOUNDARIES.md)
- [Troubleshooting](TROUBLESHOOTING.md)

---

[← Setup](SETUP.md) · [Troubleshooting →](TROUBLESHOOTING.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
