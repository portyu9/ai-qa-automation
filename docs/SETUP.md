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
| **H-series holdout** | independent deterministic adversarial corpus | none |
| **Live Claude agent** | bounded Agent SDK session against isolated target worktree | Anthropic credential |
| **GitHub MCP** | optional vendor-official repository context | GitHub credential + Docker |
| **Atlassian MCP** | optional Jira/Confluence context | Atlassian-supported auth/session |
| **Browser / API / load / mobile** | target-specific validation | approved target environment/infrastructure |

Each mode has its own evidence source. Local configuration does not stand in for provider or target observations.

---

## Install

Python **3.11+** is required.

### macOS / Linux

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

The `dev` extra installs repository-contained Python tooling. Docker, k6, browser executables, Appium drivers, emulators, and devices remain runtime/deployment components.

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
| `AI_QA_K6_EXTERNAL_EGRESS_ENFORCED` | `false` | asserts deployment-level egress containment for k6; required for every k6 run |

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
| `AI_QA_MAX_SDK_RETRIES` | 2 | transient pre-activity Agent SDK retries; 2 means at most 3 startup attempts |
| `AI_QA_SDK_RETRY_BACKOFF_SECONDS` | 1.0 | deterministic initial retry delay |
| `AI_QA_SDK_RETRY_MAX_BACKOFF_SECONDS` | 4.0 | exponential-backoff cap |
| `AI_QA_TOOL_TIMEOUT_SECONDS` | 120 | bounded adapter execution |
| `AI_QA_GLOBAL_TIMEOUT_SECONDS` | 600 | whole-run wall time, including SDK retry delays |
| `AI_QA_MAX_COST_USD` | 5.0 | Agent SDK model-cost ceiling per active SDK session |

These dimensions are intentionally independent. Increasing one does not widen another.

Transient SDK recovery is deliberately narrower than a generic replay mechanism. A new Agent SDK transport/session may be attempted only when the failed attempt is classified as transient **and** no SDK response message, controlled tool call, file modification, or pending mutation transaction exists. Authentication, authorization, configuration, schema, and local executable errors are not retried. Once observable agent/tool activity occurs, the framework preserves that run history and fails closed rather than risk duplicating a side effect.

All retry attempts remain inside the original `AI_QA_GLOBAL_TIMEOUT_SECONDS`, workspace lease, evidence store, journal, policy, and framework budgets. Retry count is persisted in canonical run state and retry scheduling is journaled using only coarse error type/category metadata.

> [!NOTE]
> The Agent SDK/provider may incur work before an exception becomes observable to the application. The framework therefore keeps retries bounded and pre-activity only; provider-reported token/cost data remains authoritative when supplied rather than being guessed.

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

Every k6 run requires deployment-level egress containment to be independently established:

```bash
export AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true
```

> [!WARNING]
> This variable is a trusted prerequisite assertion. It does not create a firewall. The operating environment must actually enforce outbound network policy.

The k6 target must additionally satisfy:

- exact host allowlisting;
- recognized non-production environment classification;
- production-like hostname denial;
- injected target binding;
- script/import restrictions; and
- predefined threshold assessment.

The egress prerequisite applies to localhost targets too because JavaScript can construct destinations dynamically.

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

The H-series holdout is separate from the routine aggregate so its independent evaluation role remains clear.

---

## GitHub Actions configuration

`.github/workflows/ci.yml` is operator-dispatched through `workflow_dispatch`.

Its optional live-model path consumes the GitHub `ANTHROPIC_API_KEY` secret only when deliberately selected. Deterministic repository jobs do not require that provider secret.

Never place credentials directly in workflow YAML, non-secret repository variables, committed fixtures, logs, or artifacts.

---

## Environment-owned evidence

The operating environment owns observations such as:

- live Anthropic provider behavior;
- authenticated GitHub/Atlassian behavior;
- external application browser/API behavior;
- approved k6 workload behavior and egress enforcement;
- Appium app/device/emulator/cloud behavior;
- process/container isolation;
- firewall/proxy policy;
- organization identity, secret management, retention, and compliance controls.

See [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) and [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).

---

## Related documentation

- [Architecture](ARCHITECTURE.md)
- [Operations](OPERATIONS.md)
- [Security architecture](SECURITY.md)
- [Runtime result contract](RESULT_CONTRACT.md)
- [Troubleshooting](TROUBLESHOOTING.md)

---

[← Documentation home](README.md) · [Operations →](OPERATIONS.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).