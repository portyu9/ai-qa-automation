# Production Readiness Matrix

This document is the authoritative truth table for the build contract.

AI QA Automation is intentionally **production-shaped**: it contains real runtime boundaries, deterministic validation, security policy, recovery controls, evaluation architecture, and operational documentation. It must not be represented as production-ready merely because those controls exist in source.

> **Implementation is not execution evidence. A model response is not test evidence. A workflow definition is not a workflow result.**

## Status vocabulary

| Status | Meaning |
|---|---|
| `IMPLEMENTED` | The capability/control exists in source or trusted configuration. |
| `PREVIOUSLY_VERIFIED` | An earlier repository state was exercised successfully; useful history, but not a current-head release certificate. |
| `NOT_VERIFIED` | Applicable current-head execution has not occurred, is incomplete, or its result is unavailable. |
| `ENVIRONMENT_REQUIRED` | Verification requires credentials, provider services, devices, browsers, target systems, network enforcement, or organization infrastructure outside this repository. |
| `MANUAL_ONLY` | The gate is deliberately operator-triggered rather than automatic. |
| `NOT_CONFIGURED` | An optional integration is intentionally absent until an approved use case/configuration exists. |
| `BLOCKED` | A deterministic safety/integrity prerequisite prevented the action from proceeding. |

These terms are intentionally narrower than words such as “ready,” “works,” or “secure.”

## Current release statement

**Current production-release status: `NOT_VERIFIED`.**

The current development line is a production-shaped agentic quality engineering system. A pre-execution static architecture, code/configuration, documentation, and contract-completeness review has been performed, and material inconsistencies discovered during that review were corrected.

That static review is **not** a substitute for current-head Ruff, Mypy, pytest, evaluation, security, browser, or model execution. Those gates remain `NOT_VERIFIED` until deliberately run and inspected.

The checked-in GitHub Actions workflow remains manual-only. Its existence is implementation evidence only.

## Architecture and trust model

| Contract requirement | Implementation | Verification status |
|---|---|---|
| Real Agent SDK loop | `src/ai_qa_automation/agent.py` uses the official Claude Agent SDK | `IMPLEMENTED`; live credentialed behavior `ENVIRONMENT_REQUIRED` / `NOT_VERIFIED` |
| Probabilistic reasoning separated from deterministic authority | model reasoning + controlled tools + independent validation/result rules | `IMPLEMENTED` |
| Canonical state outside conversation history | `AgentRunState`, `StateStore`, persisted `state.json` | `IMPLEMENTED` |
| Process-control state separated from QA state | `runtime.json`, journal, lease/budget/mutation metadata | `IMPLEMENTED` |
| Evidence provenance | typed evidence, run-scoped manifest, hashed artifacts | `IMPLEMENTED` |
| Trusted control plane separated from SUT | disjoint control/artifact/target roots; project-only Agent SDK settings | `IMPLEMENTED`; deployment isolation `ENVIRONMENT_REQUIRED` |
| Untrusted target instructions/config | target `CLAUDE.md`, `.claude/`, `.mcp.json`, DOM/log/API/source treated as data | `IMPLEMENTED` |
| Bounded execution | independent turn/tool/network/mutation/repetition/time/cost limits + circuits | `IMPLEMENTED`; current-head execution `NOT_VERIFIED` |

## Runtime security

| Requirement | Implementation | Verification status |
|---|---|---|
| Explicit Agent SDK setting source | trusted project source only | `IMPLEMENTED` |
| Restricted base tool surface | no generic runtime Bash/Edit/Write/Web authority; narrow QA tools | `IMPLEMENTED` |
| Fail-closed authorization | policy callback + universal runtime hooks | `IMPLEMENTED` |
| Strict MCP configuration | explicit trusted server registry/config | `IMPLEMENTED` |
| Governance protection | policy/settings/hooks/threshold paths protected from autonomous mutation | `IMPLEMENTED` |
| Workspace ownership | OS-backed lease outside target repository | `IMPLEMENTED`; dedicated tests present, current head `NOT_VERIFIED` |
| Workspace drift protection | content-sensitive Git/worktree fingerprint before mutation | `IMPLEMENTED` |
| Transactional mutation | trusted rollback snapshot until revision closure | `IMPLEMENTED`; dedicated tests present, current head `NOT_VERIFIED` |
| Human-edit protection after crash | stale rollback only when persisted fingerprint still matches | `IMPLEMENTED`; dedicated tests present, current head `NOT_VERIFIED` |
| Restricted egress | application host/method/browser/k6 controls | `IMPLEMENTED` at application layer; infrastructure enforcement `ENVIRONMENT_REQUIRED` |

## Core QA automation

| Capability | Implementation | Verification status |
|---|---|---|
| pytest | bounded deterministic runner, targeted/regression scopes, evidence capture | `IMPLEMENTED`; current-head full suite `NOT_VERIFIED` |
| Playwright | browser evidence, locator verification, HTTP(S)/WebSocket policy | `IMPLEMENTED`; reference/external runtime execution remains applicable `NOT_VERIFIED` / `ENVIRONMENT_REQUIRED` |
| API | `httpx` probing, auth/headers/status/schema support, read-only default | `IMPLEMENTED`; real external target `ENVIRONMENT_REQUIRED` |
| Regression selection | deterministic prioritizer + mandatory preservation + uncertainty broadening | `IMPLEMENTED`; current-head gate `NOT_VERIFIED` |
| Performance | controlled k6 target/script policy + deterministic threshold assessment | `IMPLEMENTED`; real approved workload `ENVIRONMENT_REQUIRED` |
| Mobile | Appium runtime/capability inspection | `IMPLEMENTED` capability boundary; real app/device execution `ENVIRONMENT_REQUIRED` |
| CI failure analysis | normalized CI evidence analysis | `IMPLEMENTED`; provider-specific live inputs `ENVIRONMENT_REQUIRED` when used |

## AI quality features

| Feature | Deterministic protection | Verification status |
|---|---|---|
| Failure classification | evidence-weighted taxonomy; interpretation alone cannot prove class | `IMPLEMENTED`; primary/holdout fixtures present; current-head execution `NOT_VERIFIED` |
| Safe self-healing | browser-observed uniqueness, semantic ranking, hash/evidence binding, locator-only mutation | `IMPLEMENTED`; real browser repair path `ENVIRONMENT_REQUIRED` where external |
| Test generation | observed coverage → evidence-bound plan → guarded creation | `IMPLEMENTED`; current-head deterministic gate `NOT_VERIFIED` |
| Test-quality review | meaningful-assertion and unsafe-shortcut checks | `IMPLEMENTED` |
| Regression prioritization | mandatory/security/safety/regulatory preservation; low confidence broadens | `IMPLEMENTED` |
| Prompt-injection resistance | target/remote content treated as untrusted data; policy outside model | `IMPLEMENTED`; adversarial scenarios present |

## Change intelligence

| Capability | Implementation | Verification status |
|---|---|---|
| Merge-base change set | trusted base-ref validation; immutable baseline/merge-base; committed + dirty union | `IMPLEMENTED` |
| Risk-domain classification | deterministic path/domain mapping and recommendations | `IMPLEMENTED`; dedicated tests present |
| Repository profiling | bounded languages/test/API/data/container/IaC/mobile/CI discovery | `IMPLEMENTED`; dedicated tests present |
| Dependency inventory | bounded manifest paths/sizes/content hashes without executing target code | `IMPLEMENTED` |
| CODEOWNERS | precedence/last-match resolver; unsupported patterns surfaced | `IMPLEMENTED`; dedicated tests present |
| Test-impact mapping | bounded explainable path/component/reference scoring; advisory only | `IMPLEMENTED`; dedicated tests present |
| OpenAPI/Swagger drift | conservative `BREAKING`/`RISKY`/`NON_BREAKING`/`NOT_ANALYZED` analysis | `IMPLEMENTED`; dedicated tests present |
| Incomplete-map behavior | low confidence/truncation broadens; never proves omission safe | `IMPLEMENTED` |

## Reliability and interrupted-run safety

| Capability | Implementation | Verification status |
|---|---|---|
| Concurrent-run isolation | OS-backed workspace lease | `IMPLEMENTED`; current-head suite `NOT_VERIFIED` |
| Independent execution budgets | separate tool/network/mutation/repetition/wall/model dimensions | `IMPLEMENTED`; configuration/runtime tests present; current-head `NOT_VERIFIED` |
| Tool circuit breaker | repeated tool failures open a scoped circuit without widening authority | `IMPLEMENTED`; dedicated tests present |
| Transactional autonomous mutation | snapshot, pending transaction, validation closure, commit/rollback | `IMPLEMENTED`; dedicated tests present |
| Crash recovery | stale mutation restoration only on exact fingerprint match | `IMPLEMENTED`; dedicated tests present |
| Human change preservation | fingerprint mismatch blocks automatic stale rollback | `IMPLEMENTED`; dedicated tests present |
| Recovery inspection | persisted state/journal/revision/mutation review without claiming chat replay | `IMPLEMENTED`; dedicated tests present |
| Cancellation/cleanup | bounded runtime/finally rollback paths | `IMPLEMENTED`; process/platform edge behavior current-head `NOT_VERIFIED` |

## Evidence, traceability, and observability

| Capability | Implementation | Verification status |
|---|---|---|
| Run/session IDs | typed state | `IMPLEMENTED` |
| Structured runtime events | telemetry + journal | `IMPLEMENTED` |
| Evidence manifest | run-scoped evidence/artifact metadata + hashes | `IMPLEMENTED` |
| Hash-chained operational journal | `journal.jsonl` | `IMPLEMENTED`; tamper tests present |
| Optional regulated audit chain | additional evidence/artifact registration chain | `IMPLEMENTED`; not a compliance certification |
| Lineage graph | run → evidence/artifacts/hypotheses/validations/runtime events | `IMPLEMENTED`; dedicated tests present |
| Unsigned integrity attestation | content hashes + journal verification; explicitly not a signature | `IMPLEMENTED`; dedicated tests present |
| Metrics model | run/tool/classification/healing/regression/security/cost dimensions | `IMPLEMENTED` |
| OpenTelemetry compatibility | optional observability dependency/integration | `IMPLEMENTED`; backend export `ENVIRONMENT_REQUIRED` |
| Model/config provenance | model/SDK/config fingerprint and target provenance | `IMPLEMENTED` |
| Token/cost reporting | captured when observed from live model result | `IMPLEMENTED`; live values `ENVIRONMENT_REQUIRED` |

## MCP and external systems

| Requirement | Implementation | Verification status |
|---|---|---|
| Approved official MCP only | explicit GitHub/Atlassian provider policy | `IMPLEMENTED` |
| GitHub official MCP | `github/github-mcp-server` `v1.0.5`, read-only container configuration | configuration `IMPLEMENTED`; authenticated runtime `ENVIRONMENT_REQUIRED` / `NOT_VERIFIED` |
| Atlassian Rovo MCP | official `/v1/mcp/authv2` endpoint | configuration `IMPLEMENTED`; authenticated runtime `ENVIRONMENT_REQUIRED` / `NOT_VERIFIED` |
| Tool-level least privilege | read/write/destructive/unknown external action handling | `IMPLEMENTED` |
| Health normalization | not-configured/auth/rate-limit/unavailable/invalid/failed states | `IMPLEMENTED`; deterministic fixtures present |
| Remote prompt injection | sanitized untrusted evidence; cannot redefine control plane | `IMPLEMENTED`; adversarial scenarios present |
| Non-official fallback | unofficial community MCP not substituted automatically | `IMPLEMENTED` policy |

## Evaluation architecture

| Gate | Current state |
|---|---|
| Unit/integration/policy/security tests | repository suite present, including newest runtime/change/traceability coverage |
| Fixed primary corpus | exactly 34 primary scenarios under `evals/scenarios/` (`holdout: false`) |
| Separate holdout corpus | H-series under `evals/holdout/` (`holdout: true`) |
| Primary runner | `python evals/runner.py` / `make eval` |
| Holdout runner | `python evals/holdout_runner.py` / `make holdout` |
| Hard-safety threshold | predefined zero known failures |
| Routine local aggregate | `make verify-local` = quality + pytest + primary eval + security; excludes holdout |
| Earlier deterministic baseline | `PREVIOUSLY_VERIFIED` before newest hardening/change-intelligence/traceability/config/doc work |
| Current-head deterministic suite | `NOT_VERIFIED` until deliberately executed |
| Current-head holdout | `NOT_VERIFIED` until deliberately executed |
| Model-backed smoke | `ENVIRONMENT_REQUIRED`; opt-in only |

A holdout failure is a release/readiness signal. Do not reclassify it, weaken its expected outcome, or relax a hard-safety threshold to manufacture green status.

## Security red-team questions

The implementation should continue to answer these with deterministic controls/evidence rather than model reassurance:

- Can a failed test become a false-positive product defect?
- Can a model interpretation become “observed” without evidence?
- Can self-healing select a nearby but wrong element or change test intent?
- Can generated tests pass while asserting nothing meaningful?
- Can regression selection omit mandatory/security/safety/regulatory coverage?
- Can DOM/API/GitHub/Jira/target-source content override trusted policy?
- Can target `CLAUDE.md`, `.claude/`, or `.mcp.json` alter runtime authority?
- Can developer-local settings or unofficial MCP leak into live configuration?
- Can an approved MCP receive excessive authority as its tool surface evolves?
- Can secrets enter prompts, logs, subprocess environments, or artifacts?
- Can concurrent/crashed runs overwrite developer work?
- Can retries hide flakiness or contradictory validation?
- Can external outages become fabricated evidence?
- Can the loop exceed turn/tool/network/mutation/time/cost bounds?
- Can a model/SDK/MCP upgrade silently change behavior without provenance/review?
- Can k6 reach production or escape approved network boundaries?
- Can an integrity hash be mistaken for a trusted signature or test PASS?

A material weakness should produce a deterministic control, safer tool contract, test/evaluation, or explicit environment boundary before it is considered addressed.

## Manual CI release gate

`.github/workflows/ci.yml` is intentionally `workflow_dispatch`-only during the current bootstrap constraint. It must not acquire `push`, `pull_request`, or scheduled triggers without deliberate operator review.

The workflow defines quality, primary evaluation, optional holdout, security, browser-reference, and optional live-model jobs. Workflow definition does not constitute execution evidence.

Until an authorized run completes and its evidence is inspected, current-head CI remains `NOT_VERIFIED`.

## Documentation/readiness controls

The repository separates:

- [`SETUP.md`](SETUP.md) — exact credentials/configuration by mode;
- [`OPERATIONS.md`](OPERATIONS.md) — staged execution ladder;
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — authority/trust design;
- [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) — transaction/recovery mechanics;
- [`EVALUATION.md`](EVALUATION.md) — primary/holdout governance;
- [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) — repository versus environment evidence;
- [`TECHNICAL_WALKTHROUGH.md`](TECHNICAL_WALKTHROUGH.md) — end-to-end code-path review.

Documentation is part of the safety boundary: it must not teach an operator or reviewer to interpret unexecuted capability as PASS.

## License

The repository is licensed under the MIT License. See root `LICENSE`:

`Copyright (c) 2026 Yunior Portal`

## Definition of done for a true production release

A deployment may be called production-ready only after all applicable **current-head** gates have actual evidence, including:

1. quality/static/type checks;
2. deterministic unit/integration/policy/security tests;
3. primary adversarial evaluation;
4. intentional holdout evaluation;
5. dependency/static/security/secret gates;
6. browser/reference or external browser gates required by the deployment;
7. live model validation if Claude is part of the deployment;
8. authenticated external integrations actually required by the deployment;
9. approved performance/device testing where applicable;
10. infrastructure isolation/egress/identity/secret/retention controls required by the organization;
11. final red-team review of material authority/evidence changes.

Any intentionally excluded capability must remain explicitly `NOT_VERIFIED`, `NOT_CONFIGURED`, or `ENVIRONMENT_REQUIRED` rather than being implied by nearby green gates.
