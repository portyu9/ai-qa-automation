# Production Readiness Matrix

This document is the truth table for the build contract.

The repository is intentionally **production-shaped**, but it must not be represented as production-ready until every applicable release gate has actually been executed in the target environment. A code path, test definition, workflow, or model response is not evidence that a gate passed.

## Status vocabulary

| Status | Meaning |
|---|---|
| `IMPLEMENTED` | The capability/control exists in source/configuration. |
| `PREVIOUSLY_VERIFIED` | An earlier repository state was exercised successfully; this is useful historical evidence but is not a current-head release certificate. |
| `NOT_VERIFIED` | The applicable current-head execution has not occurred or its result is unavailable. |
| `ENVIRONMENT_REQUIRED` | Verification requires credentials, services, devices, browsers, network enforcement, or organization infrastructure not contained in this repository. |
| `MANUAL_ONLY` | The gate is deliberately operator-triggered and has not been dispatched automatically. |
| `NOT_CONFIGURED` | The integration is intentionally absent until an approved production requirement/configuration exists. |

## Current release statement

**Current status: `NOT_VERIFIED` for production release.**

The implementation is suitable as a production-shaped engineering portfolio/reference system. The current feature branch contains deterministic safety controls, a fixed primary evaluation corpus, a separate holdout corpus, manual CI release gates, and explicit environment boundaries. The complete current-head quality gate has not been executed through GitHub Actions, by design.

The manual workflow must remain undispatched until the operator explicitly authorizes it.

## Architecture

| Contract requirement | Implementation | Verification status |
|---|---|---|
| Real Agent SDK loop | `src/ai_qa_automation/agent.py` uses the official Claude Agent SDK | `IMPLEMENTED`; credentialed live execution `ENVIRONMENT_REQUIRED` / `NOT_VERIFIED` |
| Probabilistic reasoning separated from deterministic validation | Agent orchestration + typed decisions; independent policy/test/schema/performance validation | `IMPLEMENTED` |
| Canonical state outside conversation history | `AgentRunState`, `StateStore`, `state.json` | `IMPLEMENTED` |
| Evidence provenance | `EvidenceItem`, `EvidenceStore`, hashed manifest/artifact references | `IMPLEMENTED` |
| Bounded execution | turn/repeat limits plus wall/tool/network/mutation budgets and circuits | `IMPLEMENTED`; current-head suite `NOT_VERIFIED` |
| Control plane separated from SUT | disjoint control root/target workspace plus trusted project setting source | `IMPLEMENTED`; infrastructure deployment boundary `ENVIRONMENT_REQUIRED` |

## Runtime security

| Contract requirement | Implementation | Verification status |
|---|---|---|
| Explicit setting source policy | trusted project source only | `IMPLEMENTED` |
| Restricted runtime tool set | no generic runtime Bash/Edit/Write/Web; narrow QA tools | `IMPLEMENTED` |
| Fail-closed permissions | policy callback + runtime hooks | `IMPLEMENTED` |
| Strict MCP configuration | explicit trusted MCP configuration | `IMPLEMENTED` |
| Protected governance files | policy + Claude Code hook protections | `IMPLEMENTED` |
| Isolated target workspace | disjoint workspace + OS-backed lease + fingerprint checks | `IMPLEMENTED`; hardened container/VM enforcement `ENVIRONMENT_REQUIRED` |
| Restricted egress | application-level allowlists and k6 precondition | `IMPLEMENTED` at application layer; high-assurance infrastructure egress `ENVIRONMENT_REQUIRED` |

## Core quality automation

| Capability | Implementation | Verification status |
|---|---|---|
| pytest | bounded deterministic runner, evidence capture, targeted/regression scopes | `IMPLEMENTED`; current-head full gate `NOT_VERIFIED` |
| Playwright | browser evidence, semantic locator verification, request/WebSocket policy | `IMPLEMENTED`; browser runtime `ENVIRONMENT_REQUIRED` / `NOT_VERIFIED` on current head |
| API | `httpx` probing, auth/headers/status/schema support, mutating-method policy | `IMPLEMENTED`; external target execution `ENVIRONMENT_REQUIRED` |
| Regression | deterministic prioritizer, mandatory preservation, uncertainty broadening, test-impact candidates | `IMPLEMENTED`; current-head full gate `NOT_VERIFIED` |
| Performance | controlled k6 invocation + p50/p90/p95/p99/error/throughput assessment | `IMPLEMENTED`; real approved staging workload `ENVIRONMENT_REQUIRED` |
| Mobile | Appium capability/runtime inspection | `IMPLEMENTED` as capability boundary; actual device/app validation `ENVIRONMENT_REQUIRED` |

## AI quality features

| Feature | Deterministic protection | Verification status |
|---|---|---|
| Failure classification | evidence-weighted taxonomy; interpretation-only input cannot prove a class | primary + holdout fixtures implemented; current-head execution `NOT_VERIFIED` |
| Safe self-healing | semantic candidate ranking, Playwright-observed uniqueness, policy-gated locator-only mutation | `IMPLEMENTED`; live/browser repair path `ENVIRONMENT_REQUIRED` |
| Test generation | observed coverage search → evidence-bound plan → guarded creation | `IMPLEMENTED`; current-head gate `NOT_VERIFIED` |
| Regression prioritization | mandatory/security/safety/regulatory preservation; low confidence broadens | `IMPLEMENTED`; primary + holdout fixtures present |
| Automated test quality review | meaningful-assertion and unsafe-shortcut validation | `IMPLEMENTED` |
| CI failure analysis | normalized CI evidence analysis | `IMPLEMENTED`; provider-specific live evidence `ENVIRONMENT_REQUIRED` |

## Change intelligence

| Capability | Implementation | Verification status |
|---|---|---|
| Merge-base change set | trusted base-ref validation, baseline SHA, merge-base, committed + dirty union | `IMPLEMENTED` |
| Risk-domain classification | deterministic changed-path risk/layer/tag mapping | `IMPLEMENTED`; dedicated unit tests added |
| CODEOWNERS | bounded last-match-wins resolver with unsupported-pattern reporting | `IMPLEMENTED`; dedicated unit tests added |
| Test-impact mapping | bounded path/component/reference scoring; advisory only | `IMPLEMENTED`; dedicated unit tests added |
| OpenAPI drift | JSON/YAML structural comparison; `BREAKING`/`RISKY`/`NON_BREAKING`/`NOT_ANALYZED` | `IMPLEMENTED`; dedicated unit tests added |
| Incomplete-map behavior | low confidence/truncation must broaden, never justify omission | `IMPLEMENTED` |

## Reliability and interrupted-run safety

| Capability | Implementation | Verification status |
|---|---|---|
| Concurrent-run isolation | OS-backed workspace lease outside target repository | `IMPLEMENTED`; dedicated unit tests added |
| Workspace drift detection | content-sensitive Git/worktree fingerprint | `IMPLEMENTED` |
| Transactional mutation | trusted rollback snapshot until validation closure | `IMPLEMENTED`; dedicated unit tests added |
| Crash recovery | stale mutation restored only when fingerprint still matches | `IMPLEMENTED`; dedicated unit tests added |
| Human-edit protection | changed post-crash workspace blocks automatic rollback | `IMPLEMENTED`; dedicated unit tests added |
| Tool circuit breaker | repeatedly failing tool becomes unavailable without widening authority | `IMPLEMENTED`; dedicated unit tests added |
| Recovery inspection | `ai-qa recover` evaluates persisted state/journal without claiming conversation replay | `IMPLEMENTED`; dedicated unit tests added |
| Cancellation/cleanup | bounded agent/runtime paths and rollback cleanup | `IMPLEMENTED`; environment-specific process interruption behavior remains `NOT_VERIFIED` on current head |

## Traceability and observability

| Capability | Implementation | Verification status |
|---|---|---|
| Run/session IDs | typed state | `IMPLEMENTED` |
| Structured logs/events | runtime telemetry + journal | `IMPLEMENTED` |
| Evidence manifest | hashed evidence/artifact records | `IMPLEMENTED` |
| Hash-chained operational journal | `journal.jsonl` | `IMPLEMENTED`; tamper tests added |
| Lineage graph | run → evidence/artifact/hypothesis/validation/runtime events | `IMPLEMENTED`; dedicated tests added |
| Unsigned integrity attestation | content hashes + journal verification; explicitly not a signature | `IMPLEMENTED`; dedicated tests added |
| Metrics | run/tool/classification/healing/regression/security/cost metrics model | `IMPLEMENTED` |
| OpenTelemetry compatibility | optional observability dependency/integration | `IMPLEMENTED`; backend export `ENVIRONMENT_REQUIRED` |
| Model/config provenance | model/SDK/policy/tool/config versions and config fingerprint | `IMPLEMENTED` |
| Token/cost reporting | captured when observed from model runtime | `IMPLEMENTED`; live values `ENVIRONMENT_REQUIRED` |

## MCP and external systems

| Requirement | Implementation | Verification status |
|---|---|---|
| Only approved official external MCP | explicit GitHub/Atlassian registry/policy | `IMPLEMENTED` |
| GitHub official MCP | pinned official `github/github-mcp-server`, read-only mode | configuration `IMPLEMENTED`; authenticated runtime `ENVIRONMENT_REQUIRED` / `NOT_VERIFIED` |
| Atlassian official Rovo MCP | official endpoint integration | configuration `IMPLEMENTED`; authenticated runtime `ENVIRONMENT_REQUIRED` / `NOT_VERIFIED` |
| Tool-level least privilege | read/write/destructive classification and fail-closed unattended policy | `IMPLEMENTED` |
| MCP failure normalization | available/not configured/unauthorized/rate limited/unavailable/invalid/failed | `IMPLEMENTED`; primary/holdout fixtures present |
| MCP prompt injection | untrusted external content cannot redefine policy | `IMPLEMENTED`; adversarial scenarios present |
| Non-official fallback | community MCP forbidden; vendor API adapter or `NOT_CONFIGURED` | `IMPLEMENTED` policy |

## Evaluation

| Gate | Current state |
|---|---|
| Fixed 34-scenario deterministic corpus | present under `evals/scenarios/`; all entries are primary (`holdout: false`) |
| Separate holdout corpus | H-series present under `evals/holdout/`; all entries are `holdout: true` |
| Primary runner | `python evals/runner.py` |
| Holdout runner | `python evals/holdout_runner.py` |
| Hard-safety threshold | zero known failures, predefined in `evals/thresholds.json` |
| Earlier baseline deterministic suite | `PREVIOUSLY_VERIFIED` before the newest hardening/change-intelligence/traceability test additions |
| Current-head deterministic suite | `NOT_VERIFIED` until deliberately executed |
| Current-head holdout suite | `NOT_VERIFIED` until deliberately executed |
| Model-backed smoke | `ENVIRONMENT_REQUIRED`; opt-in only |

A holdout failure is a release signal. Do not reclassify the failing scenario as non-holdout, weaken its expected result, or relax a hard-safety threshold to manufacture a green gate.

## Security red-team questions

The implementation must continue to answer these with deterministic controls/evidence, not model reassurance:

- Can a failed test become a false-positive product defect?
- Can self-healing change test intent or select the wrong nearby element?
- Can a generated test pass while asserting nothing meaningful?
- Can regression selection omit mandatory, security, safety, or regulatory coverage?
- Can DOM/API/GitHub/Jira content override trusted policy?
- Can target `CLAUDE.md`, `.claude/`, or `.mcp.json` alter runtime authority?
- Can developer-local Claude settings/MCP leak into production runtime configuration?
- Can an unofficial MCP server be introduced accidentally?
- Can an approved MCP server receive excessive privileges?
- Can the agent weaken its own hooks/settings/policy/evaluation thresholds?
- Can secrets enter prompts, logs, or artifacts?
- Can concurrent or crashed runs overwrite human work?
- Can retries hide flakiness or contradictory validation?
- Can outages be converted into fabricated external evidence?
- Can the loop run indefinitely or exceed tool/network/mutation/cost bounds?
- Can a model/config upgrade silently remove provenance or reduce quality?
- Can k6 generate production load without explicit authorization and infrastructure controls?

Any newly discovered material weakness requires a deterministic control, policy, or evaluation followed by the applicable verification gate.

## Manual CI release gate

`.github/workflows/ci.yml` is intentionally manual-only. It must have no `push`, `pull_request`, or scheduled trigger while this bootstrap constraint is active.

The workflow defines the repository quality/security/evaluation/browser/model gates, but a workflow definition is not an execution result. Until a run is explicitly authorized and completed, current-head CI status remains `NOT_VERIFIED`.

## License

The repository is licensed under the MIT License. See the root `LICENSE` file:

`Copyright (c) 2026 Yunior Portal`

## Definition of done for a true production release

A future production release may be called ready only after all applicable current-head gates are actually green, including quality/lint/type/unit/integration/policy/security evaluations, the intentional holdout gate, and every environment-dependent integration required by the deployment. Any excluded capability must remain explicitly `NOT_VERIFIED`, `NOT_CONFIGURED`, or `ENVIRONMENT_REQUIRED` rather than being implied by code presence.
