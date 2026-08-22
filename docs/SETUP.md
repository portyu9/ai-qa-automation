# Setup and Configuration

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

Setup is part of the framework's trust model. The control plane, target workspace, artifact storage, credentials, provider sessions, and deployment infrastructure are deliberately configured as separate concerns rather than collapsed into one ambient environment.

## Operating modes

| Mode | Purpose | Credentials / infrastructure |
|---|---|---|
| Deterministic local tooling | CLI inspection, local demo, repository tests/evaluations/security tooling | none |
| H-series holdout | independent deterministic adversarial corpus | none |
| Live Claude agent | bounded Agent SDK session against an isolated target worktree | `ANTHROPIC_API_KEY` |
| GitHub MCP | optional vendor-official GitHub context | GitHub token + Docker |
| Atlassian MCP | optional Jira/Confluence context | Atlassian-supported authentication |
| External browser/API/load/mobile | target-specific validation | target environment / infrastructure |

Each mode has its own evidence source. Local configuration does not stand in for provider or target observations.

## Install

Python 3.11 or newer is required.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

The `dev` extra installs repository-contained Python tooling. System/runtime components such as Docker, k6, a Playwright browser executable, Appium drivers, emulators, or devices remain operating-environment components.

## Inspect local capabilities

```bash
ai-qa doctor
```

`doctor` inspects locally observable packages, executables, browser/Appium visibility, configuration posture, and trusted-root markers without converting local presence into remote authentication evidence.

A credential-free deterministic demonstration is available with:

```bash
ai-qa demo
```

## Configuration source

`.env.example` is a reference template only. Runtime `Settings` uses `env_file=None`; the framework does not silently load a repository `.env` file into trusted runtime authority.

Inject configuration through the shell, CI secret store, container/orchestrator secret mechanism, or another approved secret manager.

Never commit:

- populated `.env` files;
- model/provider credentials;
- customer credentials;
- private production data;
- sensitive run artifacts.

## Core configuration

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | unset | live Claude Agent SDK authentication |
| `AI_QA_MODEL` | `claude-sonnet-5` | model identifier used by live agent orchestration |
| `AI_QA_CONTROL_ROOT` | current working directory | trusted framework root containing `CLAUDE.md` and `.claude/settings.json` |
| `AI_QA_ARTIFACT_ROOT` | `<control-root>/artifacts` | trusted state/evidence/journal/rollback/artifact root |
| `AI_QA_BASE_REF` | unset | explicit Git comparison baseline such as `origin/main` |
| `AI_QA_REGULATED_MODE` | `false` | additional engineering audit chaining / retention classification |

## Runtime safety configuration

| Variable | Default | Security meaning |
|---|---|---|
| `AI_QA_ALLOW_EXTERNAL_NETWORK` | `false` | non-local target access remains disabled until explicitly enabled |
| `AI_QA_ALLOWED_NETWORK_HOSTS` | `["127.0.0.1","localhost"]` | explicit host/IP allowlist for network-capable QA adapters |
| `AI_QA_ALLOW_TEST_WRITES` | `false` | enables policy-eligible autonomous writes only inside approved test directories |
| `AI_QA_ALLOW_MUTATING_API_METHODS` | `false` | enables policy-eligible API mutation; read-only remains default |
| `AI_QA_K6_EXTERNAL_EGRESS_ENFORCED` | `false` | prerequisite assertion for non-local k6 execution |

### Network allowlist syntax

`AI_QA_ALLOWED_NETWORK_HOSTS` is a JSON list of **hostnames or IP literals**, not URLs.

Valid examples:

```bash
export AI_QA_ALLOWED_NETWORK_HOSTS='["localhost","127.0.0.1","qa.example.test","::1"]'
```

The configuration layer canonicalizes DNS names/IPs and rejects ambiguous entries such as:

```text
*
*.example.test
https://qa.example.test
qa.example.test:443
user@qa.example.test
qa.example.test/path
```

A target URL is supplied to the individual API/browser/k6 tool; the trusted allowlist contains only the network identity that policy may authorize.

## Independent execution budgets

| Variable | Default | Bound |
|---|---:|---|
| `AI_QA_MAX_TURNS` | 12 | Agent SDK turns |
| `AI_QA_MAX_TOOL_CALLS` | 30 | controlled tool attempts |
| `AI_QA_MAX_NETWORK_CALLS` | 12 | network-capable attempts |
| `AI_QA_MAX_MUTATIONS` | 3 | autonomous mutation attempts |
| `AI_QA_MAX_REPEATED_ACTION` | 3 | identical action/input repetition |
| `AI_QA_TOOL_TIMEOUT_SECONDS` | 120 | individual bounded adapter execution |
| `AI_QA_GLOBAL_TIMEOUT_SECONDS` | 600 | overall wall-clock runtime |
| `AI_QA_MAX_COST_USD` | 5.0 | Agent SDK model-cost ceiling |

These dimensions are intentionally independent. Increasing one budget does not silently widen another.

## Trust-root layout

The control root, artifact root, and target workspace must remain separate trust domains.

Recommended shape:

```text
/work/ai-qa-automation/          # trusted framework/control plane
/work/ai-qa-artifacts/           # trusted evidence/process records
/work/target-app-agent-run/      # isolated Git-backed SUT worktree
```

The live agent rejects overlapping control/target or artifact/target roots.

Target `CLAUDE.md`, `.claude/`, `.mcp.json`, source comments, tests, logs, DOM, and API content remain untrusted evidence even when they resemble framework instructions.

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

A successful model response does not directly become terminal `SUCCESS`. The runtime applies the deterministic result semantics in [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md).

## Optional GitHub MCP

The framework uses the vendor-official GitHub MCP server and adds server-side read-only mode as defense in depth.

Local integration prerequisites:

- Docker available to the control process;
- `GITHUB_PERSONAL_ACCESS_TOKEN` injected through the environment;
- `AI_QA_ENABLE_GITHUB_MCP=true`;
- least-privilege repository/resource permissions for the intended reads.

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN='...'
export AI_QA_ENABLE_GITHUB_MCP=true
```

Provider configuration and tool authority remain separate. The runtime records `AVAILABLE` only after an authorized successful provider interaction.

Do not grant a broad token merely because the server itself is approved.

## Optional Atlassian Rovo MCP

```bash
export AI_QA_ENABLE_ATLASSIAN_MCP=true
```

The framework uses Atlassian's supported MCP endpoint and does not persist Atlassian credentials in repository configuration. Authentication/session establishment follows the authorized Atlassian/organization path.

Jira/Confluence content remains untrusted evidence and cannot redefine the control plane.

## Target API/browser access

To authorize a non-local QA target, both conditions are required:

1. external network access is explicitly enabled; and
2. the target hostname is explicitly present in the canonical host allowlist.

Example:

```bash
export AI_QA_ALLOW_EXTERNAL_NETWORK=true
export AI_QA_ALLOWED_NETWORK_HOSTS='["qa.checkout.example"]'
```

API mutation remains independently disabled unless `AI_QA_ALLOW_MUTATING_API_METHODS=true` is deliberately set.

## Autonomous test writes

Autonomous mutation remains disabled unless explicitly enabled:

```bash
export AI_QA_ALLOW_TEST_WRITES=true
```

Enabling the flag does not authorize arbitrary filesystem writes. Runtime policy still requires an approved test-code path, Git-backed workspace ownership, a matching fingerprint, no unresolved mutation transaction, safe path ownership, and post-change deterministic closure.

## Controlled performance execution

A non-local k6 run additionally requires:

```bash
export AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true
```

This variable records a trusted prerequisite that infrastructure egress enforcement exists. It does not create a firewall or replace deployment network policy.

The k6 target still must satisfy host allowlisting, explicit non-production classification, target binding, script/import restrictions, and predefined threshold assessment.

## Repository commands

```bash
make quality
make test
make eval
make security
make verify-local
make holdout
```

The H-series holdout is separate from the routine aggregate so its independent evaluation purpose remains clear.

## GitHub Actions configuration

`.github/workflows/ci.yml` is operator-dispatched through `workflow_dispatch`.

The optional live-model job consumes the GitHub `ANTHROPIC_API_KEY` secret only when selected. Deterministic quality/evaluation/security/browser-reference jobs do not need that provider secret.

Never place credentials directly in workflow YAML, non-secret repository variables, committed fixtures, logs, or artifacts.

## Environment-owned evidence

The corresponding operating environment owns observations such as:

- live Anthropic request/response behavior;
- authenticated GitHub/Atlassian provider behavior;
- external application browser/API behavior;
- approved k6 workload behavior;
- Appium app/device/emulator/cloud behavior;
- process/container isolation;
- firewall/proxy policy;
- organization secret management, identity, retention, and compliance controls.

These boundaries are described further in [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) and [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).

## Related documentation

- [`README.md`](README.md) — documentation landing page
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — trust and authority model
- [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) — runtime truth semantics
- [`SECURITY.md`](SECURITY.md) — deterministic security controls
- [`OPERATIONS.md`](OPERATIONS.md) — operating guidance
- [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — diagnosis without weakening controls

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
