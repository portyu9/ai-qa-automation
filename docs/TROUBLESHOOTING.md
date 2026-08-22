# Troubleshooting

**ƳƤ AI QA Automation Framework**  
**Designed and engineered by Ƴunior Ƥortal (ƳƤ)**

Troubleshooting follows the same rule as test execution: **diagnose the failing layer before changing controls**. Do not weaken policy, widen network access, increase timeouts, disable validation, or rewrite a test merely because a command did not succeed.

A useful first distinction is:

| Class | Meaning |
|---|---|
| `CODE_DEFECT` | Repository implementation behaves incorrectly under otherwise valid inputs/environment. |
| `CONFIGURATION_DEFECT` | Required trusted configuration is missing, malformed, inconsistent, or points at the wrong target. |
| `AUTHENTICATION_FAILURE` | A credential/session is absent, expired, rejected, or lacks required authorization. |
| `RATE_LIMIT` | A provider is reachable but has throttled the request. |
| `NETWORK_FAILURE` | DNS, TLS, routing, proxy, firewall, socket, or connectivity prevented communication. |
| `PROVIDER_OUTAGE` | The external provider is plausibly degraded or unavailable. |
| `UNKNOWN` | Available evidence does not yet distinguish the cause safely. |

`UNKNOWN` is preferable to inventing a diagnosis.

## 1. Start with local capability inspection

```bash
ai-qa doctor
```

`doctor` performs **local inspection only**. It may report that a credential variable is present, but it never prints, hashes, partially reveals, or validates the credential value and does not contact Anthropic, GitHub, or Atlassian.

Useful doctor results include:

- `PASS` — a locally inspectable prerequisite was observed;
- `NOT_VERIFIED` — a local package/runtime prerequisite was not established;
- `NOT_CONFIGURED` — an optional prerequisite is intentionally absent;
- `DISABLED` — the integration is not enabled;
- `CONFIGURED_NOT_VERIFIED` — configuration/prerequisite presence was observed, but live provider behavior was not tested;
- `BLOCKED` — a required local prerequisite prevents the configured operation;
- `SAFE_DEFAULT` / `ELEVATED_EXPLICIT` — current write posture.

Do not interpret `CONFIGURED_NOT_VERIFIED` as a successful authentication test.

## 2. Installation or import failures

### `ai-qa` command not found

Confirm the intended virtual environment is active and install the project:

```bash
python -m pip install -e '.[dev]'
```

Then inspect:

```bash
python -m pip show ai-qa-automation
python -m pip check
```

Do not fix an import problem by adding arbitrary source directories to global `PYTHONPATH`; the runtime intentionally avoids relying on ambient path state.

### Dependency conflict

Use `python -m pip check` and inspect the installed versions. Do not loosen pins or upper bounds merely to silence the conflict. Version-sensitive dependencies such as the Claude Agent SDK, Ruff, Playwright, and external MCP components should be reconciled deliberately against current first-party documentation before changing the repository contract.

## 3. Trusted control-root errors

A live agent run requires the trusted control root to contain:

```text
CLAUDE.md
.claude/settings.json
```

It also requires the control root, artifact root, and target workspace to remain disjoint.

If the runtime reports an invalid control root:

1. confirm `--control-root` points to this ƳƤ framework repository, not the SUT;
2. confirm the trusted markers exist;
3. confirm the SUT is a separate clone/worktree;
4. confirm `AI_QA_ARTIFACT_ROOT`, if set, is outside the SUT.

Do not copy trusted governance files into an arbitrary SUT merely to bypass this check.

## 4. Workspace lease or drift blockers

### Workspace already leased

A second cooperating run cannot mutate the same target worktree while another lease is active. Treat this as `BLOCKED`, not as an application defect.

Confirm whether another agent process legitimately owns the target. Do not delete lease metadata while an active process may still be using the workspace.

### Workspace drift detected

Autonomous mutation requires the target fingerprint to match what the runtime inspected. Drift can be caused by a developer, IDE, formatter, Git operation, or another process.

Preserve the newer work. Re-inspect/re-bootstrap from the actual workspace state rather than disabling fingerprint validation.

## 5. Pending mutation, rollback, or stale recovery

A test mutation remains pending until the new revision closes:

1. patch-safety PASS;
2. targeted pytest PASS; and
3. full-regression pytest PASS.

If execution ends without that closure, the runtime attempts rollback.

After a crash, stale recovery is automatic only if the current workspace fingerprint exactly matches the persisted crashed state. If a human changed the workspace afterward, recovery blocks for manual review instead of overwriting newer work.

Inspect persisted state with:

```bash
ai-qa recover artifacts/run-<id>
```

If rollback integrity cannot be guaranteed, treat it as an infrastructure/integrity failure. Do not manually mark the run successful because the resulting file “looks okay.”

## 6. Model says success but run is `NOT_VERIFIED`

This is expected when deterministic validation lineage does not prove the current objective/revision.

Common reasons:

- no deterministic validation ran;
- a required gate is `NOT_EXECUTED`, `NOT_OBSERVED`, or `NOT_VERIFIED`;
- same-revision PASS and FAIL evidence conflict;
- a changed test lacks current-revision patch safety;
- a changed test lacks targeted pytest PASS;
- a changed test lacks full-regression pytest PASS.

The correct response is to obtain the missing deterministic evidence, not to promote the model result.

## 7. Budget or repetition termination

The runtime independently bounds:

- model turns;
- total tool attempts;
- network-capable tool attempts;
- mutation attempts;
- repeated identical actions;
- per-tool time;
- overall wall time;
- model cost.

If a budget is exhausted, determine why the objective needs more work. Increase a bound only when the objective and risk justify that specific dimension. Do not raise all budgets together by habit.

A per-tool circuit opening after repeated failures is also intentional. Diagnose the failing tool/provider rather than giving the model a broader alternative capability.

## 8. Playwright troubleshooting

`playwright` being installed does not prove Chromium is installed.

Check `ai-qa doctor`. If the package exists but `playwright_chromium` is not verified, install the compatible browser runtime in the intended environment before attempting browser-backed validation.

If browser navigation or a subresource/WebSocket is blocked, inspect the configured host allowlist. Add a host only when it is an explicitly authorized non-production target/resource. Do not turn on unrestricted external network access to make a test pass.

The local reference SUT is evidence for the reference path only; it does not prove an external application is reachable or correct.

## 9. API troubleshooting

API access is read-only by default. A rejected `POST`, `PUT`, `PATCH`, or `DELETE` may therefore be policy behavior rather than an HTTP/client defect.

Check:

- target host is explicitly allowlisted;
- the URL is the intended non-production endpoint;
- mutating methods are genuinely required and explicitly enabled if appropriate;
- authentication is provided through the approved target-specific mechanism;
- response-code/schema evidence points to application behavior rather than network/configuration failure.

Never enable mutating methods globally merely to bypass one denied request.

## 10. k6 troubleshooting

A performance run may be blocked because:

- k6 is not installed;
- the environment is production or unknown;
- the target host is not allowlisted;
- the script does not bind to injected `BASE_URL`/`TARGET_URL`;
- the script imports remote modules or `k6/x/*` extensions;
- local-file reads or unrelated hard-coded external hosts were detected;
- a non-local target lacks the trusted infrastructure-egress precondition.

`AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true` is an assertion that deployment infrastructure has separately established the needed egress control. It is not a switch that creates a firewall.

Never change thresholds after seeing results to make a performance gate green.

## 11. GitHub MCP troubleshooting

Current local integration prerequisites include:

- `AI_QA_ENABLE_GITHUB_MCP=true`;
- `GITHUB_PERSONAL_ACCESS_TOKEN` present in the environment;
- Docker available;
- least-privilege repository/resource permissions;
- provider connectivity.

Interpret failures by layer:

- disabled → configuration decision;
- enabled with no token → `NOT_CONFIGURED`;
- token present but Docker unavailable → local `BLOCKED` prerequisite;
- provider rejects token/permission → `AUTHENTICATION_FAILURE` / unauthorized state;
- throttling → `RATE_LIMIT`;
- provider unreachable → network/outage investigation.

Do not replace the official GitHub MCP server with a community server to bypass a temporary problem.

## 12. Atlassian Rovo MCP troubleshooting

The repository configures Atlassian's official MCP endpoint only when explicitly enabled. Authentication/session establishment is external to this repository.

If enabled but unavailable, distinguish:

- OAuth/token/session not established;
- organization policy disallows the selected authentication mode;
- insufficient Jira/Confluence permissions;
- rate limiting;
- network failure;
- provider outage.

Do not place Jira/Confluence credentials in repository files, and do not accept remote issue/page text as control-plane instructions.

## 13. Live Claude Agent SDK troubleshooting

A live model session requires `ANTHROPIC_API_KEY`. The deterministic local quality/tests/evaluations/security paths do not.

If live execution fails:

1. confirm the key variable is present without printing it;
2. distinguish authentication/authorization from network/provider errors;
3. confirm the configured model identifier is supported by the installed SDK/provider;
4. inspect runtime budget/cost/timeout termination separately from provider failure;
5. preserve the exact exception class/provider result and run provenance;
6. if provider outage is plausible and internet access is available, check Anthropic's official service-health page and documentation before implementing an architectural workaround.

Do not expose the key in debug logs or issue reports.

## 14. MCP/provider outage behavior

When a remote provider appears unavailable, temporary outage handling should not permanently widen architecture.

Where internet access exists, check the provider's official service-health source and current first-party documentation. Preserve valid local evidence and normalize the unavailable dependency explicitly. Do not fabricate remote evidence and do not switch to an unapproved integration merely to keep the workflow moving.

## 15. Corrupt state or journal

`ai-qa recover` verifies persisted state/journal integrity. A broken hash chain, unreadable state, or inconsistent pending mutation cannot be converted into a clean recovery by model reasoning.

Useful inspection surfaces:

```bash
ai-qa recover artifacts/run-<id>
ai-qa lineage artifacts/run-<id>
ai-qa attest artifacts/run-<id>
```

A valid hash chain proves only internal persisted-record integrity properties. It does not prove the software behavior was correct or the run passed.

## 16. Security scan findings

`make security` defines repository-contained checks for dependency compatibility, Bandit, dependency vulnerability auditing, and secret scanning.

If a secret-like finding appears:

- inspect whether it is a real credential or fixture/example false positive;
- if real, revoke/rotate it immediately at the provider;
- remove the secret from current content and assess history/artifact exposure;
- add the narrowest justified detector exclusion only for demonstrably non-secret fixture material.

Do not broadly disable secret scanning to remove noise.

## 17. What evidence to preserve when escalating

Prefer small, targeted evidence:

- exact command/action and objective;
- terminal/runtime outcome;
- sanitized exception class/message;
- run ID;
- relevant evidence/validation IDs;
- target Git SHA and base/merge-base provenance when relevant;
- tool/provider health state;
- the smallest relevant source/config snippet;
- artifact hashes/references rather than dumping large binary/log payloads;
- whether the behavior reproduces deterministically.

Do not paste entire repositories, huge traces, raw credentials, or private customer data into an issue merely because more context might help.

## 18. Escalation rule

If the only proposed “fix” requires weakening a deterministic safety invariant, stop and classify the blocker instead. Safety controls should change only through reviewed engineering work with corresponding deterministic regression coverage.

See [`SETUP.md`](SETUP.md), [`OPERATIONS.md`](OPERATIONS.md), [`SECURITY.md`](SECURITY.md), [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md), and [`LIMITATIONS.md`](LIMITATIONS.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
