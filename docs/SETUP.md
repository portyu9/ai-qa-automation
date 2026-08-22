# Setup and Configuration

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

This guide separates repository-contained use of the ƳƤ AI QA Automation Framework from credentialed and target-environment operation. Each mode keeps its evidence source explicit.

## 1. Choose the operating mode

| Mode | What it is for | Credentials required |
|---|---|---|
| Deterministic local tooling | CLI inspection, local demo, unit/integration/policy tests, primary evaluations, static security checks | None |
| Holdout readiness gate | Separate H-series deterministic evaluation | None |
| Live Claude agent | One bounded Claude Agent SDK session against an isolated target worktree | `ANTHROPIC_API_KEY` |
| GitHub MCP | Optional read-only GitHub context through the vendor-official MCP server | GitHub token + Docker |
| Atlassian MCP | Optional Jira/Confluence context through Atlassian Rovo MCP | Atlassian-supported authentication |
| External browser/load/mobile targets | Target-specific application, load, and device validation | Target-specific environment/infrastructure |

Repository-contained, credentialed-provider, and target-environment evidence are intentionally distinct.

## 2. Install the repository

Python 3.11 or newer is required by the framework.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

On Windows PowerShell, activate the virtual environment with the corresponding `.venv\Scripts\Activate.ps1` command.

The `dev` extra installs repository-contained quality, evaluation, browser-reference, and security tooling. System executables such as Docker, k6, and mobile runtimes are installed separately by the operating environment.

## 3. Inspect local capability without contacting external services

```bash
ai-qa doctor
```

`doctor` reports locally observable packages, executables, browser runtime, Appium runtime visibility, and trusted-control-root markers. It does not treat a local package or variable as proof of remote authentication.

A deterministic demonstration that does not require Claude is available with:

```bash
ai-qa demo
```

## 4. Environment configuration is explicit

`.env.example` is a **reference template**, not an automatically loaded runtime configuration file. `Settings` deliberately uses `env_file=None`; export variables in the shell/runner or inject them with an approved secret-management mechanism.

Never commit a populated `.env`, API key, access token, customer credential, or production artifact.

### Core configuration

| Variable | Default | Purpose / when needed |
|---|---|---|
| `ANTHROPIC_API_KEY` | unset | Used for live Claude-backed execution through the Anthropic runtime/SDK environment |
| `AI_QA_MODEL` | `claude-sonnet-5` | Claude model identifier used by the live agent |
| `AI_QA_CONTROL_ROOT` | current working directory | Trusted ƳƤ framework repository root containing `CLAUDE.md` and `.claude/settings.json` |
| `AI_QA_ARTIFACT_ROOT` | `<control-root>/artifacts` | Trusted location for state, evidence, journal, rollback snapshots, and run artifacts |
| `AI_QA_BASE_REF` | unset | Optional trusted Git baseline such as `origin/main`; resolved to immutable baseline/merge-base SHAs during bootstrap |
| `AI_QA_REGULATED_MODE` | `false` | Enables additional hash-chained audit records and regulated artifact classification |

### Runtime safety configuration

| Variable | Default | Meaning |
|---|---|---|
| `AI_QA_ALLOW_EXTERNAL_NETWORK` | `false` | Keeps non-local external target access disabled unless explicitly enabled |
| `AI_QA_ALLOWED_NETWORK_HOSTS` | `["127.0.0.1","localhost"]` | Explicit host allowlist used by network-capable QA adapters |
| `AI_QA_ALLOW_TEST_WRITES` | `false` | Enables policy-eligible autonomous writes only inside approved test directories |
| `AI_QA_ALLOW_MUTATING_API_METHODS` | `false` | Enables policy-eligible mutating API methods; read methods remain the default |
| `AI_QA_K6_EXTERNAL_EGRESS_ENFORCED` | `false` | Trusted assertion used with application controls before non-local k6 execution |

### Independent execution budgets

| Variable | Default | Bound |
|---|---:|---|
| `AI_QA_MAX_TURNS` | 12 | Agent SDK turns |
| `AI_QA_MAX_TOOL_CALLS` | 30 | Total controlled tool attempts |
| `AI_QA_MAX_NETWORK_CALLS` | 12 | Network-capable tool attempts |
| `AI_QA_MAX_MUTATIONS` | 3 | Autonomous mutation attempts |
| `AI_QA_MAX_REPEATED_ACTION` | 3 | Repetition of the same action/input pattern |
| `AI_QA_TOOL_TIMEOUT_SECONDS` | 120 | Individual bounded test/tool execution |
| `AI_QA_GLOBAL_TIMEOUT_SECONDS` | 600 | Overall wall-clock runtime |
| `AI_QA_MAX_COST_USD` | 5.0 | Agent SDK model-cost ceiling |

These limits are deliberately separate. Raising one dimension does not silently raise the others.

## 5. Trusted control root and target worktree must be disjoint

The live agent rejects a target workspace that is the control root, contains the control root, or is contained by it. Runtime evidence/artifacts must also remain outside the target workspace.

A typical layout is:

```text
/work/ai-qa-automation/        # trusted control plane
/work/target-app-agent-run/    # isolated Git-backed SUT worktree
```

Target `CLAUDE.md`, `.claude/`, `.mcp.json`, source comments, tests, logs, DOM, and API content are treated as untrusted evidence and never accepted as runtime authority.

## 6. Live Claude Agent SDK configuration

```bash
export ANTHROPIC_API_KEY='...'
export AI_QA_CONTROL_ROOT='/work/ai-qa-automation'

ai-qa agent \
  --control-root /work/ai-qa-automation \
  --workspace /work/target-app-agent-run \
  'Investigate the failing checkout test. Do not modify tests unless evidence proves a test defect.'
```

A successful model response is not a successful QA result. Verified success is derived from the applicable deterministic validation lineage; otherwise the runtime returns the corresponding non-PASS outcome.

## 7. Optional GitHub MCP

The framework configures the vendor-official `github/github-mcp-server` container and keeps it read-only at the server layer.

Prerequisites for the local integration shape:

- Docker available to the control process;
- `GITHUB_PERSONAL_ACCESS_TOKEN` supplied through the environment;
- `AI_QA_ENABLE_GITHUB_MCP=true`;
- a least-privilege token scoped only to the repositories/resources the intended read operations need.

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN='...'
export AI_QA_ENABLE_GITHUB_MCP=true
```

The runtime records GitHub as `AVAILABLE` only after an observed successful MCP tool call. Authentication, authorization, rate limiting, transport failure, and invalid responses remain explicit health states.

The framework does not hard-code broad token scopes because the minimum permission set depends on the repositories and read operations an operator authorizes.

## 8. Optional Atlassian Rovo MCP

Enable the vendor-official Atlassian endpoint with:

```bash
export AI_QA_ENABLE_ATLASSIAN_MCP=true
```

The runtime uses Atlassian's supported MCP authentication path rather than storing Atlassian credentials in this repository. Interactive OAuth is the normal operator path; non-interactive/service credential options remain organization-admin and deployment decisions.

Jira/Confluence content remains untrusted evidence and cannot alter the control plane.

## 9. Repository-contained verification commands

```bash
make quality
make test
make eval
make security
```

For convenience, the routine repository-contained set is:

```bash
make verify-local
```

The H-series is intentionally excluded from `verify-local` so routine development does not consume the holdout corpus:

```bash
make holdout
```

## 10. GitHub Actions secrets and manual execution

`.github/workflows/ci.yml` is intentionally `workflow_dispatch`-only. The live model job is opt-in and defaults off.

`ANTHROPIC_API_KEY` is used as a GitHub repository secret only when `run_model=true`. Deterministic quality, evaluation, security, and browser-reference jobs do not need that secret.

Do not place API keys directly in workflow YAML, repository variables intended for non-secret data, committed `.env` files, test fixtures, logs, or artifacts.

## 11. Environment-owned evidence

The following evidence is produced by the corresponding operating environment rather than inferred from repository configuration:

- Anthropic request/response behavior;
- authenticated GitHub MCP behavior;
- authenticated Atlassian Rovo MCP behavior;
- Playwright against an external application;
- k6 against an approved workload with infrastructure egress enforcement;
- Appium against an application plus device/emulator/device cloud;
- organization secret management, identity, retention, compliance, container isolation, and network policy.

See [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) and [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) for the evidence model.

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
