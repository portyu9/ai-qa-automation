# Setup and Configuration

This guide separates **repository-contained use** from capabilities that require credentials or external infrastructure. The distinction is intentional: installing or configuring a capability is not evidence that it works in a particular environment.

## 1. Choose the operating mode

| Mode | What it is for | Credentials required |
|---|---|---|
| Deterministic local tooling | CLI inspection, local demo, unit/integration/policy tests, primary evaluations, static security checks | None |
| Holdout readiness gate | Separate H-series deterministic evaluation at an intentional checkpoint | None |
| Live Claude agent | One bounded Claude Agent SDK session against an isolated target worktree | `ANTHROPIC_API_KEY` |
| GitHub MCP | Optional read-only GitHub context through the vendor-official MCP server | GitHub token + Docker |
| Atlassian MCP | Optional Jira/Confluence context through Atlassian Rovo MCP | Atlassian-supported authentication |
| External browser/load/mobile targets | Real target validation outside the reference SUT | Target-specific environment/infrastructure |

Nothing in the credential-free modes should be described as proof that a credentialed or external integration works.

## 2. Install the repository

Python 3.11 or newer is required by this project.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

On Windows PowerShell, activate the virtual environment with the corresponding `.venv\Scripts\Activate.ps1` command.

The `dev` extra installs the repository-contained quality, evaluation, browser-reference, and security tooling. It does not install system executables such as Docker, k6, or a mobile device runtime.

## 3. Inspect local capability without contacting external services

```bash
ai-qa doctor
```

`doctor` reports locally observable packages, executables, browser runtime, Appium runtime visibility, and trusted-control-root markers. It is a capability inspection, not a remote credential test. A package being installed does not prove an API key, OAuth session, remote service, or external target is valid.

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
| `ANTHROPIC_API_KEY` | unset | Required only for live Claude-backed execution. Consumed by the Anthropic runtime/SDK environment. |
| `AI_QA_MODEL` | `claude-sonnet-5` | Claude model identifier used by the live agent. |
| `AI_QA_CONTROL_ROOT` | current working directory | Trusted AI-QA repository root containing `CLAUDE.md` and `.claude/settings.json`. |
| `AI_QA_ARTIFACT_ROOT` | `<control-root>/artifacts` | Trusted location for state, evidence, journal, rollback snapshots, and run artifacts. |
| `AI_QA_BASE_REF` | unset | Optional trusted Git baseline such as `origin/main`; resolved to immutable baseline/merge-base SHAs during bootstrap. |
| `AI_QA_REGULATED_MODE` | `false` | Enables additional hash-chained audit records and regulated artifact classification; does not claim compliance certification. |

### Runtime safety configuration

| Variable | Default | Meaning |
|---|---|---|
| `AI_QA_ALLOW_EXTERNAL_NETWORK` | `false` | Keeps non-local external target access disabled unless explicitly enabled. |
| `AI_QA_ALLOWED_NETWORK_HOSTS` | `["127.0.0.1","localhost"]` | Explicit host allowlist used by network-capable QA adapters. |
| `AI_QA_ALLOW_TEST_WRITES` | `false` | Enables policy-eligible autonomous writes only inside approved test directories. |
| `AI_QA_ALLOW_MUTATING_API_METHODS` | `false` | Enables policy-eligible mutating API methods; read methods remain the default. |
| `AI_QA_K6_EXTERNAL_EGRESS_ENFORCED` | `false` | Trusted assertion required in addition to application controls before non-local k6 execution. |

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

This matters because target `CLAUDE.md`, `.claude/`, `.mcp.json`, source comments, tests, logs, DOM, and API content are treated as untrusted evidence. They are never accepted as runtime authority.

## 6. Live Claude Agent SDK configuration

Only when live model execution is desired:

```bash
export ANTHROPIC_API_KEY='...'
export AI_QA_CONTROL_ROOT='/work/ai-qa-automation'

ai-qa agent \
  --control-root /work/ai-qa-automation \
  --workspace /work/target-app-agent-run \
  'Investigate the failing checkout test. Do not modify tests unless evidence proves a test defect.'
```

A successful model response is not a successful QA result. The runtime can return verified success only when the applicable deterministic validation lineage closes successfully; otherwise it reports an explicit non-PASS state such as `NOT_VERIFIED`, `BLOCKED`, or an infrastructure/policy failure.

## 7. Optional GitHub MCP

This project configures the vendor-official `github/github-mcp-server` container and keeps it read-only at the server layer.

Prerequisites for the current local integration shape:

- Docker available to the control process;
- `GITHUB_PERSONAL_ACCESS_TOKEN` supplied through the environment;
- `AI_QA_ENABLE_GITHUB_MCP=true`;
- a least-privilege token scoped only to the repositories/resources the intended read operations need.

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN='...'
export AI_QA_ENABLE_GITHUB_MCP=true
```

Do not infer MCP availability from configuration. The runtime records GitHub as `AVAILABLE` only after an observed successful MCP tool call. Authentication, authorization, rate limiting, transport failure, and invalid responses remain explicit health states.

The project does not hard-code broad token scopes because the minimum permission set depends on the repositories and read operations an operator actually authorizes.

## 8. Optional Atlassian Rovo MCP

Enable the vendor-official Atlassian endpoint with:

```bash
export AI_QA_ENABLE_ATLASSIAN_MCP=true
```

The runtime uses Atlassian's supported MCP authentication path rather than storing Atlassian credentials in this repository. Interactive OAuth is the normal operator path; any non-interactive/service credential option is an organization-admin and deployment decision outside this repository.

As with GitHub, configuration does not prove availability. Jira/Confluence content remains untrusted evidence and cannot alter the control plane.

## 9. Repository-contained verification commands

These commands require no Claude key or external MCP credentials:

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

The H-series is intentionally excluded from `verify-local` so routine development does not consume the holdout corpus. At an explicit readiness checkpoint:

```bash
make holdout
```

Defining these commands is not evidence that they passed on the current repository head. Record an execution result before changing a readiness status from `NOT_VERIFIED`.

## 10. GitHub Actions secrets and manual execution

`.github/workflows/ci.yml` is intentionally `workflow_dispatch`-only. The live model job is opt-in and defaults off.

The current workflow requires `ANTHROPIC_API_KEY` as a GitHub repository secret **only when** `run_model=true`. The deterministic quality/evaluation/security/browser-reference jobs do not need that secret. The current workflow does not perform authenticated GitHub or Atlassian MCP validation.

Do not place API keys directly in workflow YAML, repository variables intended for non-secret data, committed `.env` files, test fixtures, logs, or artifacts.

## 11. What still requires real environment evidence

The following cannot be promoted to verified merely by completing setup documentation:

- live Anthropic request/response behavior;
- authenticated GitHub MCP behavior;
- authenticated Atlassian Rovo MCP behavior;
- Playwright against a real external application;
- k6 against an explicitly approved real workload with infrastructure egress enforcement;
- Appium against a real app plus device/emulator/device cloud;
- organization secret management, identity, retention, compliance, container isolation, and network policy.

See [`VERIFICATION_BOUNDARIES.md`](VERIFICATION_BOUNDARIES.md) and [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) for the authoritative truth model.
