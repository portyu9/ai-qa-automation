# Troubleshooting

**ƳƤ AI QA Automation Framework**  
**Designed and engineered by Ƴunior Ƥortal (ƳƤ)**

Troubleshooting follows the same rule as runtime execution:

> **Diagnose the failing layer before changing controls.**

Do not widen network access, weaken policy, increase every budget, disable validation, loosen a security threshold, or rewrite a test merely because an operation failed.

## Diagnose by layer

| Class | Meaning |
|---|---|
| `CODE_DEFECT` | framework/target implementation behaves incorrectly under otherwise valid inputs/environment |
| `CONFIGURATION_DEFECT` | trusted configuration is missing, malformed, inconsistent, or points at the wrong target |
| `AUTHENTICATION_FAILURE` | credential/session is absent, expired, rejected, or unauthorized |
| `RATE_LIMIT` | provider is reachable but throttled the operation |
| `NETWORK_FAILURE` | DNS/TLS/routing/proxy/firewall/socket/connectivity prevented communication |
| `PROVIDER_OUTAGE` | external provider is plausibly degraded/unavailable |
| `DATA_OR_TARGET_FAILURE` | target state/data violates the assumptions of the test objective |
| `INTEGRITY_FAILURE` | evidence/state/rollback/workspace ownership cannot be trusted safely |
| `UNKNOWN` | available evidence does not yet discriminate the cause |

`UNKNOWN` is preferable to an invented diagnosis.

## 1. Local capability inspection

```bash
ai-qa doctor
```

`doctor` performs local inspection. It may observe a credential variable but never prints, hashes, partially reveals, or validates its value and does not turn configuration presence into provider authentication evidence.

Useful doctor outcomes include:

- `PASS` — locally inspectable prerequisite observed;
- `NOT_VERIFIED` — local package/runtime prerequisite not established;
- `NOT_CONFIGURED` — optional integration/prerequisite absent;
- `DISABLED` — integration not enabled;
- `CONFIGURED_NOT_VERIFIED` — local configuration observed without provider proof;
- `BLOCKED` — local prerequisite prevents configured operation;
- `SAFE_DEFAULT` / `ELEVATED_EXPLICIT` — current write posture.

## 2. Installation/import failures

### `ai-qa` not found

```bash
python -m pip install -e '.[dev]'
python -m pip show ai-qa-automation
python -m pip check
```

Confirm the intended virtual environment is active.

Do not “fix” imports by globally injecting arbitrary source directories into `PYTHONPATH`; controlled subprocesses intentionally avoid relying on ambient project path state.

### Dependency conflict

Use `python -m pip check` and inspect the conflicting package versions. Do not loosen pins/upper bounds merely to silence incompatibility.

Version-sensitive contracts—Claude Agent SDK, Playwright, MCP components, Ruff, Pydantic—should be reconciled against current first-party documentation before changing the repository contract.

## 3. Configuration validation errors

Trusted configuration fails early when it is ambiguous or unsafe.

### Network host allowlist rejected

`AI_QA_ALLOWED_NETWORK_HOSTS` must be a JSON list of hostnames/IP literals:

```bash
export AI_QA_ALLOWED_NETWORK_HOSTS='["localhost","qa.example.test","127.0.0.1"]'
```

Do not use:

```text
*
*.example.test
https://qa.example.test
qa.example.test:443
qa.example.test/path
```

Supply the full URL to the API/browser/k6 operation; the allowlist contains only approved host identities.

### Budget setting rejected

Budget validators intentionally reject zero/negative or unbounded values. Change only the specific dimension the objective needs.

## 4. Trusted control-root errors

A live agent control root requires:

```text
CLAUDE.md
.claude/settings.json
```

The control root, artifact root, and target workspace must remain disjoint.

If validation fails:

1. confirm `--control-root` points to the ƳƤ framework repository;
2. confirm trusted markers exist;
3. confirm target is a separate clone/worktree;
4. confirm artifact root is outside the target;
5. do not copy governance files into the SUT merely to satisfy the check.

## 5. Workspace lease or drift blockers

### Workspace already leased

Another cooperating framework process owns mutation authority for the target. Treat this as `BLOCKED`, not an application defect.

Do not delete active lease metadata to bypass ownership.

### Workspace drift

A developer, IDE, formatter, Git operation, or another process changed target state after analysis.

Re-bootstrap from the real workspace state. Do not disable fingerprint validation.

## 6. Pending mutation / rollback / stale recovery

A changed test revision closes only with:

1. patch-safety PASS;
2. targeted pytest PASS;
3. full-regression pytest PASS.

Without closure, the transaction should revert when rollback integrity is available.

After a crash, stale recovery additionally requires exact workspace fingerprint and trusted target/backup ownership.

Common recovery blockers:

- newer human/out-of-band edit;
- prior run path traversal;
- symlinked pending target path;
- symlinked runtime metadata;
- rollback backup outside trusted rollback directory;
- symlinked backup;
- missing backup;
- backup SHA-256 mismatch.

Inspect:

```bash
ai-qa recover artifacts/run-<id>
```

If rollback integrity cannot be guaranteed, treat it as an integrity/infrastructure failure. A file “looking correct” is not enough to declare a clean transaction.

## 7. Model says success but runtime is `NOT_VERIFIED`

Use [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md).

Typical causes:

- no deterministic validation;
- required gate is `NOT_EXECUTED`, `NOT_OBSERVED`, `NOT_VERIFIED`, or `BLOCKED`;
- same-gate PASS and FAIL conflict at one revision;
- current revision lacks patch-safety;
- current revision lacks targeted pytest;
- current revision lacks full regression;
- historical passing evidence does not supersede the relevant active gate.

Obtain the missing deterministic evidence; do not promote the model result manually.

## 8. Self-healing proposal denied

A denied heal can be correct behavior.

Check whether:

- deterministic failure class supports locator repair;
- original locator fits the supported literal grammar;
- candidate syntax matches its declared strategy;
- Playwright observed candidate uniqueness in the same DOM;
- same-page screenshot/accessibility context exists;
- deterministic semantic overlap preserves original locator intent;
- candidate uses a sufficiently stable strategy;
- exact test file hash still matches proposal context;
- test writes are explicitly enabled.

A candidate can be unique and model-confident yet still be rejected because it represents the wrong business control.

Do not bypass this by increasing model semantic confidence or manually changing candidate stability metadata; those values are recomputed by deterministic policy.

## 9. Budget/repetition termination

The runtime independently bounds:

- model turns;
- total tool attempts;
- network attempts;
- mutation attempts;
- repeated identical actions;
- per-tool execution time;
- overall wall time;
- model cost.

If a budget is exhausted, determine which dimension genuinely needs adjustment. Do not raise all limits together by habit.

A per-tool circuit opening after repeated failure is also intentional. Diagnose that tool/provider instead of giving the model a broader alternative capability.

## 10. Playwright troubleshooting

The Python package being installed does not prove the compatible Chromium executable is installed.

Use `ai-qa doctor` and install the browser runtime in the intended environment when needed.

If navigation/subresource/WebSocket access is blocked:

- verify the hostname is an explicit allowlist entry;
- verify external networking is deliberately enabled for a non-local target;
- inspect redirects/final page URL;
- do not enable unrestricted network access merely to make the page load.

The local reference SUT proves only the reference scenario it exercises.

## 11. API troubleshooting

API access defaults to read-only.

A denied `POST`, `PUT`, `PATCH`, or `DELETE` can therefore be expected policy behavior.

Check:

- canonical target host is allowlisted;
- URL is the intended endpoint;
- external network access is enabled when non-local;
- mutating methods are explicitly enabled only when appropriate;
- target authentication is provided through approved target-specific means;
- response-code/schema evidence reflects application behavior rather than connectivity/configuration failure.

Do not globally enable mutating methods to bypass one denied request.

## 12. k6 troubleshooting

A performance run can be blocked because:

- k6 executable is absent;
- target environment is production/unknown;
- hostname looks production-like even if metadata says staging/QA;
- host is not allowlisted;
- script does not consume injected `BASE_URL`/`TARGET_URL`;
- script imports remote modules or `k6/x/*`;
- local file reads are present;
- unrelated literal network hosts are present;
- unsupported import syntax is detected;
- non-local target lacks infrastructure-egress prerequisite.

`AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true` records a deployment prerequisite; it does not create a firewall.

Do not change predefined thresholds after seeing measurements to make a gate green.

## 13. GitHub MCP troubleshooting

Local prerequisites include:

- `AI_QA_ENABLE_GITHUB_MCP=true`;
- `GITHUB_PERSONAL_ACCESS_TOKEN` in environment;
- Docker;
- least-privilege repository/resource permissions;
- provider connectivity.

Interpret by layer:

- disabled → configuration choice;
- enabled without token → `NOT_CONFIGURED`;
- token present but Docker unavailable → local blocker;
- provider rejects token/permission → unauthorized/authentication failure;
- explicit throttling → rate-limited;
- provider unreachable → network/outage investigation.

Do not replace the approved GitHub MCP server with a community server as an outage workaround.

## 14. Atlassian Rovo MCP troubleshooting

If enabled but unavailable, distinguish:

- OAuth/token/session not established;
- organization policy disallows chosen authentication mode;
- insufficient Jira/Confluence permissions;
- rate limiting;
- network failure;
- provider outage.

Do not store Atlassian credentials in repository files, and do not accept issue/page text as control-plane instructions.

## 15. Provider result normalization looks wrong

The MCP failure normalizer deliberately avoids treating arbitrary numeric business IDs as HTTP results.

Examples:

```text
issue 403 failed lookup        → not automatically HTTP 403
HTTP 403                       → authorization context
status code: 401               → authorization context
HTTP status 429                → rate-limit context
```

When diagnosing a provider adapter, preserve explicit transport metadata separately from application/business payload fields.

## 16. Live Claude Agent SDK troubleshooting

A live model session requires `ANTHROPIC_API_KEY`.

If provider execution fails:

1. confirm variable presence without printing it;
2. separate authentication/authorization from network/provider failure;
3. confirm model identifier is supported by the installed SDK/provider contract;
4. separate runtime budget/time/cost termination from provider failure;
5. preserve sanitized exception class/provider result and run provenance;
6. check official provider service health/documentation when outage is plausible.

Never expose the key in debugging output or issue reports.

## 17. Provider outage behavior

Temporary provider failure should not permanently widen architecture.

Preserve valid local evidence. Normalize the unavailable dependency explicitly. Do not fabricate remote evidence and do not switch to an unapproved integration merely to continue execution.

## 18. Corrupt state/journal/evidence

Inspection commands:

```bash
ai-qa recover artifacts/run-<id>
ai-qa lineage artifacts/run-<id>
ai-qa attest artifacts/run-<id>
```

A broken journal hash chain, unreadable state, duplicate/tampered evidence manifest, or inconsistent pending mutation cannot be converted into clean recovery by model reasoning.

A valid hash chain proves persisted-record integrity properties—not application correctness or PASS.

## 19. Security scan finding

`make security` defines dependency compatibility, Bandit, dependency vulnerability, and secret scanning gates.

For a secret-like finding:

- determine whether it is a real credential or controlled fixture false positive;
- if real, revoke/rotate immediately;
- remove current content and assess history/artifacts/forks/caches;
- fix the exposure path when appropriate;
- use only a narrow justified detector exclusion for demonstrably non-secret fixture material.

Do not broadly disable secret scanning.

## 20. Evidence to preserve when escalating

Prefer targeted evidence:

- exact objective/action;
- terminal/runtime outcome;
- sanitized exception type/message;
- run ID;
- evidence/validation IDs;
- target Git SHA and base/merge-base provenance when relevant;
- provider outcome;
- smallest relevant config/source snippet;
- artifact references/hashes;
- reproducibility conditions.

Do not paste whole repositories, huge traces, credentials, or private customer data into an issue merely to provide “more context.”

## 21. Escalation rule

If the only proposed fix requires weakening a deterministic safety invariant, classify the blocker and address the underlying design instead.

Safety controls should change through reviewed engineering work with corresponding deterministic regression coverage.

See [`README.md`](README.md), [`SETUP.md`](SETUP.md), [`OPERATIONS.md`](OPERATIONS.md), [`SECURITY.md`](SECURITY.md), [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md), [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md), and [`LIMITATIONS.md`](LIMITATIONS.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
