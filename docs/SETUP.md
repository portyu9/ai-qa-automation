# Setup and Configuration

> [!IMPORTANT]
> Setup is part of the trust model. The **control plane**, **target workspace**, **artifact storage**, **credentials**, **provider sessions**, and **deployment infrastructure** should remain separate concerns rather than one ambient environment.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Operations](OPERATIONS.md) · [Security](SECURITY.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Operating modes

| Mode | Purpose | Credentials / infrastructure |
|---|---|---|
| **Deterministic local tooling** | CLI inspection, demo, repository tests/evaluations/security tooling | none |
| **H-series readiness** | repository-visible deterministic cases sequestered from routine primary execution | none |
| **Live Claude agent** | bounded Agent SDK session against isolated target worktree | Anthropic credential |
| **GitHub MCP** | optional vendor-official repository context | GitHub credential + Docker |
| **Atlassian MCP** | optional Jira/Confluence context | Atlassian-supported auth/session |
| **Browser / API / load / mobile** | target-specific validation | approved target environment/infrastructure |

Each mode has its own evidence source. Local configuration does not stand in for provider or target observations.

---

## Install

Project metadata requires Python **3.11+**. The repository-owned development environments are currently locked and continuously exercised on exact **CPython 3.11.16** and **3.13.15**; use one of those interpreters when reproducing repository validation.

Dependency installation is intentionally lock-bound. Do not replace the commands below with an editable `.[dev]` install or a live resolver upgrade when the goal is to reproduce repository-controlled verification.

### macOS / Linux

```bash
python3.11 -m venv .venv
source .venv/bin/activate
make install
```

`make install` selects the committed `requirements/dev-py311.lock` or `requirements/dev-py313.lock` from the active interpreter, installs it with `--require-hashes`, installs the local project non-editably with `--no-deps --no-build-isolation`, and runs `pip check`.

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
$lockSuffix = python -c "import sys; print(f'{sys.version_info.major}{sys.version_info.minor}')"
python -m pip install --require-hashes -r "requirements/dev-py$lockSuffix.lock"
python -m pip install --no-deps --no-build-isolation .
python -m pip check
```

If the active interpreter has no matching committed development lock, installation should stop rather than silently resolve a new dependency graph. Deliberate dependency/lock updates follow [`SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md).

The development locks install repository-contained Python tooling. Docker, k6, browser executables, Appium drivers, emulators, and devices remain runtime/deployment components. The initial interpreter and bootstrap `pip` still belong to the local/hosted environment trust boundary; package hashes do not attest those bootstrap bytes.

---

## Inspect the local environment

```bash
ai-qa doctor
```

`doctor` inspects locally observable packages, executables, trusted-root markers, browser/Appium visibility, and configuration posture. It does **not** translate package presence or a credential-shaped environment variable into provider availability.

A credential-free deterministic demonstration is available with:

```bash
ai-qa demo
```

---

## Configuration source

`.env.example` is reference documentation only. Runtime settings use `env_file=None`; the framework does not silently load a repository `.env` into trusted authority.

Inject configuration through:

- the shell;
- CI/runner secret storage;
- container/orchestrator secret mechanisms; or
- another approved secret manager.

> [!CAUTION]
> Never commit populated `.env` files, model/provider credentials, customer credentials, production data, or sensitive run artifacts.

---

## Core configuration

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | unset | live Claude Agent SDK authentication |
| `AI_QA_MODEL` | `claude-sonnet-5` | live agent model identifier |
| `AI_QA_CONTROL_ROOT` | current working directory | trusted framework root containing `CLAUDE.md` + `.claude/settings.json` |
| `AI_QA_ARTIFACT_ROOT` | `<control-root>/artifacts` | trusted state/evidence/journal/rollback/artifact root |
| `AI_QA_BASE_REF` | unset | explicit Git comparison baseline, e.g. `origin/main` |
| `AI_QA_REGULATED_MODE` | `false` | additional audit chaining / retention classification |

### Safety configuration

| Variable | Default | Security meaning |
|---|---|---|
| `AI_QA_ALLOW_EXTERNAL_NETWORK` | `false` | non-local target access disabled until explicitly enabled |
| `AI_QA_ALLOWED_NETWORK_HOSTS` | `["127.0.0.1","localhost"]` | canonical exact host/IP allowlist |
| `AI_QA_ALLOW_TEST_WRITES` | `false` | enables only policy-eligible live autonomous Python test writes |
| `AI_QA_ALLOW_MUTATING_API_METHODS` | `false` | enables policy-eligible API mutation; read-only remains default |
| `AI_QA_K6_EXTERNAL_EGRESS_ENFORCED` | `false` | asserts deployment-level egress containment for k6; necessary but not sufficient for process execution |

The live MCP configuration currently exposes the k6 egress prerequisite only. The controlled runner additionally requires separate trusted **process/filesystem isolation** and **executable module-loading isolation** assertions before process spawn. Because neither additional assertion is wired through live MCP configuration, live `run_k6` remains intentionally fail-closed rather than treating static JavaScript inspection, a validated snapshot, or the egress flag as an execution/module sandbox.

---

## Network allowlist syntax

`AI_QA_ALLOWED_NETWORK_HOSTS` is a JSON list of **hostnames or IP literals**—never URLs.

```bash
export AI_QA_ALLOWED_NETWORK_HOSTS='["localhost","127.0.0.1","qa.example.test","::1"]'
```

Rejected examples include:

```text
*
*.example.test
https://qa.example.test
qa.example.test:443
user@qa.example.test
qa.example.test/path
fe80::1%eth0
999.2.3.4
```

The parser also rejects URL/query/fragment ambiguity, malformed DNS labels, scoped IPv6 zone identifiers, and malformed dotted IPv4-looking values.

A target **URL** belongs to the individual API/browser/k6 operation. The trusted allowlist contains only the network identity policy may authorize.

---

## Independent execution budgets and SDK recovery

| Variable | Default | Bound |
|---|---:|---|
| `AI_QA_MAX_TURNS` | 12 | Agent SDK turns |
| `AI_QA_MAX_TOOL_CALLS` | 30 | controlled tool attempts |
| `AI_QA_MAX_NETWORK_CALLS` | 12 | network-capable attempts |
| `AI_QA_MAX_MUTATIONS` | 3 | autonomous mutation attempts |
| `AI_QA_MAX_REPEATED_ACTION` | 3 | identical action/input repetition |
| `AI_QA_MAX_SDK_RETRIES` | 2 | transient Agent SDK session-start retries before provider query submission; 2 means at most 3 startup attempts |
| `AI_QA_SDK_RETRY_BACKOFF_SECONDS` | 1.0 | deterministic initial retry delay |
| `AI_QA_SDK_RETRY_MAX_BACKOFF_SECONDS` | 4.0 | exponential-backoff cap |
| `AI_QA_TOOL_TIMEOUT_SECONDS` | 120 | bounded adapter execution |
| `AI_QA_GLOBAL_TIMEOUT_SECONDS` | 600 | whole-run wall time, including SDK retry delays |
| `AI_QA_MAX_COST_USD` | 5.0 | Agent SDK model-cost ceiling per active SDK session |

These dimensions are intentionally independent. Increasing one does not widen another.

Transient SDK recovery is deliberately narrower than a generic replay mechanism. A fresh Agent SDK session may be attempted only when session startup itself fails transiently **before provider query submission begins**. Authentication, authorization, configuration, schema, and local executable errors are not retried even when transport-wrapped. Once provider query submission starts, replay is refused even if no response message or controlled tool call is observed, because provider-side work, cost, or other effects can no longer be proven absent.

All retry attempts remain inside the original `AI_QA_GLOBAL_TIMEOUT_SECONDS`, workspace lease, evidence store, journal, policy, and framework budgets. Retry count is persisted in canonical run state and retry scheduling is journaled using only coarse error type/category metadata. Retries do not reset tool, network, mutation, time, or provenance budgets.

> [!NOTE]
> Provider-reported token/cost data remains authoritative when supplied rather than being guessed. The startup-only retry boundary prevents the framework from replaying a query merely because provider work or cost was not yet observable locally.

---

## Trust-root layout

Recommended layout:

```text
/work/ai-qa-automation/          # trusted framework / control plane
/work/ai-qa-artifacts/           # trusted evidence + process records
/work/target-app-agent-run/      # isolated Git-backed SUT worktree
```

The live agent rejects overlapping control/target or artifact/target roots.

Target `CLAUDE.md`, `.claude/`, `.mcp.json`, source comments, tests, logs, DOM, and API content remain untrusted evidence even when they resemble framework instructions.

---

## Live Claude Agent SDK session

```bash
export ANTHROPIC_API_KEY='...'
export AI_QA_CONTROL_ROOT='/work/ai-qa-automation'
export AI_QA_ARTIFACT_ROOT='/work/ai-qa-artifacts'
export AI_QA_BASE_REF='origin/main'

ai-qa agent \
  --control-root "$AI_QA_CONTROL_ROOT" \
  --workspace /work/target-app-agent-run \
  'Investigate the failing checkout test. Do not modify tests unless evidence proves a test defect.'
```

A successful model response does not directly become terminal `SUCCESS`; [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) governs runtime truth.

---

## Optional GitHub MCP

The framework uses the vendor-official GitHub MCP path and adds server-side read-only mode as defense in depth.

Prerequisites:

- Docker available to the control process;
- `GITHUB_PERSONAL_ACCESS_TOKEN` injected through the environment;
- `AI_QA_ENABLE_GITHUB_MCP=true`;
- least-privilege provider permissions appropriate to intended reads.

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN='...'
export AI_QA_ENABLE_GITHUB_MCP=true
```

Provider configuration and action authority remain separate. `AVAILABLE` requires an observed successful provider interaction.

---

## Optional Atlassian Rovo MCP

```bash
export AI_QA_ENABLE_ATLASSIAN_MCP=true
```

The framework uses Atlassian's supported MCP path and does not persist Atlassian credentials in repository configuration. Authentication/session establishment follows the approved Atlassian/organization mechanism.

Jira/Confluence content remains untrusted evidence.

---

## Target API / browser access

A non-local target requires both:

1. explicit external-network enablement; and
2. the target hostname in the canonical allowlist.

```bash
export AI_QA_ALLOW_EXTERNAL_NETWORK=true
export AI_QA_ALLOWED_NETWORK_HOSTS='["qa.checkout.example"]'
```

API mutation remains independently disabled unless `AI_QA_ALLOW_MUTATING_API_METHODS=true` is deliberately set.

---

## Autonomous test writes

```bash
export AI_QA_ALLOW_TEST_WRITES=true
```

That flag does **not** authorize arbitrary filesystem mutation. Live autonomous commit still requires:

- an approved Python path under `tests/` or `generated_tests/`;
- a Git-backed isolated workspace;
- a matching workspace fingerprint;
- non-traversing, non-symlink path ownership;
- no unresolved transaction;
- patch-safety PASS;
- targeted pytest PASS bound to the exact changed path; and
- full-regression PASS at the same revision.

Reusable patch/generation components may understand other syntaxes without widening this live authority boundary.

---

## Controlled k6 execution

Every k6 execution requires three independent deployment-level facts: **outbound-egress containment**, **process/filesystem isolation**, and **executable module-loading isolation**. Repository configuration currently exposes only the egress prerequisite:

```bash
export AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true
```

> [!WARNING]
> This variable is a trusted prerequisite assertion. It does not create a firewall, process sandbox, filesystem namespace, container boundary, or module-loader sandbox. Process execution must remain fail-closed until the deployment independently enforces all three prerequisites.

The controlled runner additionally applies defense-in-depth before an eventual authorized spawn:

- validates a bounded static ESM root/local-import graph through descriptor-relative no-follow reads;
- rejects CommonJS `require`, dynamic `import()`, remote static imports, unapproved extension/builtin imports, unapproved literal hosts, `open()` use, path escape, and symlink-traversing module subjects;
- disables k6 automatic extension resolution with `K6_AUTO_EXTENSION_RESOLUTION=false`;
- snapshots the exact validated UTF-8 static module bytes into a fresh temporary execution tree; and
- executes only that snapshot when all three infrastructure prerequisites are asserted, so later workspace mutation cannot change the statically validated code.

These static checks do **not** prove runtime module confinement. The separate module-loading-isolation prerequisite exists because a JavaScript runtime can otherwise acquire executable code through loader behavior that static source inspection cannot comprehensively authorize.

The k6 target must additionally satisfy:

- exact host allowlisting;
- recognized non-production environment classification;
- production-like hostname denial;
- injected target binding;
- script/import restrictions; and
- predefined threshold assessment.

The egress prerequisite applies to localhost targets too because JavaScript can construct destinations dynamically. The live MCP `run_k6` path currently remains intentionally blocked even when the egress flag is true because its separate trusted process/filesystem-isolation and module-loading-isolation assertions have not been plumbed into runtime configuration.

---

## Repository command surface

```bash
make quality
make test
make eval
make security
make verify-local
make holdout
```

The legacy `holdout` command stays separate from the routine aggregate to preserve execution separation; its committed H-series fixtures are repository-visible, not blind or independent.

---

## GitHub Actions configuration

`.github/workflows/ci.yml` defines ordinary GitHub events plus the fixed `repository_dispatch` event `trusted-pr-validation`. Under the observed active external Actions Policy, only the owner-authorized trusted dispatch is executable for the protected identity. Its read-only, secret-free validation jobs bind execution to the exact prospective merge subject; `Required PR Gate` is an internal deterministic aggregate and `Trusted PR Gate` is the protected merge status.

`.github/workflows/manual-validation.yml` remains `workflow_dispatch` only. It keeps the repository-visible H-series readiness corpus separated from protected merge validation and contains the optional credentialed Claude Agent SDK smoke path. The observed `repository_dispatch`-only policy prevents that workflow from executing under the same protected identity; when a separately trusted execution mechanism exists, `ANTHROPIC_API_KEY` remains scoped only to the explicitly selected model job.

Repository workflow source cannot self-attest the external Actions Policy, protected ruleset, or their future administrative state. See [CI/CD and Repository Governance](CI_CD.md).

Never place credentials directly in workflow YAML, non-secret repository variables, committed fixtures, logs, or artifacts.

---

## Environment-owned evidence

The operating environment owns observations such as:

- live Anthropic provider behavior;
- authenticated GitHub/Atlassian behavior;
- external application browser/API behavior;
- approved k6 workload behavior, egress enforcement, process/filesystem isolation, and executable module-loading isolation;
- Appium app/device/emulator/cloud behavior;
- process/container isolation;
- firewall/proxy policy;
- organization identity, secret management, retention, and compliance controls.

See [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) and [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).

---

## Related documentation

- [Architecture](ARCHITECTURE.md)
- [CI/CD and repository governance](CI_CD.md)
- [Operations](OPERATIONS.md)
- [Security architecture](SECURITY.md)
- [Runtime result contract](RESULT_CONTRACT.md)
- [Troubleshooting](TROUBLESHOOTING.md)

---

[← Documentation home](README.md) · [Operations →](OPERATIONS.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
