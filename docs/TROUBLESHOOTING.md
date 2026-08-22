# Troubleshooting

> [!IMPORTANT]
> **Diagnose the failing layer before changing controls.** Do not widen network access, weaken policy, raise every budget, disable validation, or rewrite a test merely because an operation failed.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Setup](SETUP.md) · [Operations](OPERATIONS.md) · [Result contract](RESULT_CONTRACT.md)

---

## Fast triage

| Symptom class | Typical meaning | First place to look |
|---|---|---|
| `CODE_DEFECT` | framework/target implementation behaves incorrectly under valid inputs/environment | evidence + failing deterministic gate |
| `CONFIGURATION_DEFECT` | trusted configuration missing/malformed/inconsistent | `ai-qa doctor`, environment, setup contract |
| `AUTHENTICATION_FAILURE` | credential/session absent, expired, rejected, unauthorized | provider auth layer |
| `RATE_LIMIT` | provider reachable but throttling | provider outcome + retry policy |
| `NETWORK_FAILURE` | DNS/TLS/routing/proxy/firewall/socket issue | host policy + deployment network |
| `PROVIDER_OUTAGE` | external provider plausibly degraded | provider health + first-party status/docs |
| `DATA_OR_TARGET_FAILURE` | target state/data violates objective assumptions | target evidence |
| `INTEGRITY_FAILURE` | state/evidence/rollback/workspace ownership cannot be trusted | runtime control + recovery records |
| `UNKNOWN` | evidence does not yet discriminate cause | gather the next high-value observation |

> [!NOTE]
> `UNKNOWN` is preferable to an invented diagnosis.

---

## Local capability inspection

```bash
ai-qa doctor
```

`doctor` inspects local capability/configuration without printing, hashing, partially revealing, or validating credential values.

Useful local outcomes include:

- `PASS` — locally inspectable prerequisite observed;
- `NOT_VERIFIED` — local runtime/package prerequisite not established;
- `NOT_CONFIGURED` — optional integration/prerequisite absent;
- `DISABLED` — integration deliberately disabled;
- `CONFIGURED_NOT_VERIFIED` — local configuration exists without provider proof;
- `BLOCKED` — local prerequisite prevents configured operation;
- `SAFE_DEFAULT` / `ELEVATED_EXPLICIT` — write posture.

---

## Installation and import failures

### `ai-qa` not found

```bash
python -m pip install -e '.[dev]'
python -m pip show ai-qa-automation
python -m pip check
```

Confirm the intended virtual environment is active.

Do not “fix” imports by globally injecting arbitrary source directories into `PYTHONPATH`; controlled subprocesses intentionally avoid ambient project-path authority.

### Dependency conflicts

Use `python -m pip check` and reconcile the actual conflicting versions. Do not loosen version constraints merely to silence incompatibility.

Version-sensitive contracts—Agent SDK, Playwright, MCP components, Ruff, Pydantic—should be reconciled against first-party documentation before changing the repository contract.

---

## Configuration validation

### Network allowlist rejected

Use a JSON list of hostnames/IP literals:

```bash
export AI_QA_ALLOWED_NETWORK_HOSTS='["localhost","qa.example.test","127.0.0.1"]'
```

Rejected forms include:

```text
*
*.example.test
https://qa.example.test
qa.example.test:443
qa.example.test/path
fe80::1%eth0
999.2.3.4
```

Supply the full URL to the actual API/browser/k6 operation; the allowlist contains only approved host identities.

### Budget setting rejected

Budget validators intentionally reject invalid/unbounded values. Change the **specific** dimension the objective needs rather than increasing all limits.

---

## Trusted control-root errors

A live control root requires:

```text
CLAUDE.md
.claude/settings.json
```

The control root, artifact root, and target workspace must remain disjoint.

If validation fails:

1. confirm `--control-root` points to the framework repository;
2. confirm trusted markers exist;
3. confirm target is a separate clone/worktree;
4. confirm artifact storage is outside the target;
5. do **not** copy governance files into the SUT just to satisfy the check.

---

## Workspace lease or drift blockers

### Workspace already leased

Another cooperating framework process owns mutation authority for the target. Treat this as `BLOCKED`, not as an application defect.

Do not delete active lease metadata to bypass ownership.

If lease-path ownership itself is suspicious—for example a symlink substitution under trusted artifact storage—treat that as an integrity problem rather than forcing the lock open.

### Workspace drift

A developer, IDE, formatter, Git operation, or another process changed target state after analysis.

Re-bootstrap from the real state. Do not disable fingerprint validation.

---

## Pending mutation / rollback / stale recovery

A live autonomous changed revision closes only with:

```text
patch-safety PASS for changed path
+ targeted pytest PASS selecting the exact same path
+ full-regression pytest PASS
```

A targeted run against a different file—or a `-k`-only selector—does not certify the pending mutation.

### Common recovery blockers

- newer human/out-of-band edit;
- prior run path traversal;
- symlinked pending target path;
- symlinked `runtime.json` / journal / rollback root;
- rollback backup outside trusted rollback directory;
- symlinked backup;
- missing backup;
- backup SHA-256 mismatch;
- recovery validation lineage not bound to the changed path.

Inspect:

```bash
ai-qa recover artifacts/run-<id>
```

If rollback integrity cannot be guaranteed, treat it as integrity/infrastructure failure. A file “looking correct” is not enough.

---

## Model says success but runtime is `NOT_VERIFIED`

This usually means the model completed but deterministic closure did not.

Typical causes:

- no deterministic validation;
- required gate is `NOT_EXECUTED`, `NOT_OBSERVED`, `NOT_VERIFIED`, or `BLOCKED`;
- same-gate PASS/FAIL conflict at one revision;
- current revision lacks patch safety;
- targeted pytest did not select the changed path;
- current revision lacks full regression;
- historical passing evidence does not supersede the active gate.

Obtain the missing deterministic evidence. Do not manually promote the model result.

See [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md).

---

## Autonomous write denied for JavaScript / TypeScript

This can be intentional.

Reusable patch/generation components understand JS/TS syntax, but the **live autonomous commit** contract is deliberately limited to Python test paths because controlled deterministic closure is pytest-backed.

If JS/TS mutation is required in a future deployment, add a first-class controlled execution/closure adapter and corresponding safety tests rather than pretending pytest proved those bytes.

---

## Self-healing proposal denied

Check whether:

- deterministic failure class supports locator repair;
- original locator fits supported literal grammar;
- candidate syntax matches declared strategy;
- Playwright observed uniqueness in the same DOM;
- same-page screenshot/accessibility context exists;
- deterministic semantic overlap preserves original intent;
- candidate strategy is sufficiently stable;
- exact file hash still matches proposal context;
- writes are explicitly enabled and path fits live mutation contract.

A candidate can be unique and model-confident yet correctly denied because it represents the wrong business control.

Do not bypass denial by inflating model confidence or manually altering strategy stability; those values are recomputed by deterministic policy.

---

## Test generation produced “already covered” plan labels

Treat coverage labels as model interpretation unless same-run repository observation supports them.

Unsupported `already covered` claims cannot suppress deterministic candidate scenarios. If the plan seems too small:

1. inspect observed coverage evidence;
2. confirm the label is grounded in that same run;
3. keep unsupported candidates in the implementation/validation queue;
4. do not let model confidence shrink deterministic coverage.

---

## Budget or repetition termination

The runtime independently bounds:

- model turns;
- total tool attempts;
- network attempts;
- mutation attempts;
- repeated identical actions;
- per-tool execution time;
- whole-run wall time;
- model cost.

Diagnose the exhausted dimension. Do not raise all limits by habit.

A per-tool circuit opening after repeated failure is intentional; diagnose that tool/provider rather than granting the model a broader capability.

---

## Playwright troubleshooting

Package installation does not prove a compatible browser executable is installed.

If navigation/subresource/WebSocket access is blocked:

- verify the hostname is an exact allowlist entry;
- verify external network is deliberately enabled for non-local targets;
- inspect redirects/final URL;
- inspect service-worker assumptions;
- do not enable unrestricted networking just to make the page load.

The reference SUT proves only the reference behavior it exercises.

---

## API troubleshooting

API access defaults to read-only.

A denied `POST`, `PUT`, `PATCH`, or `DELETE` may therefore be expected policy behavior.

Check:

- target host allowlisting;
- exact URL;
- external network enablement when needed;
- explicit mutation-method enablement only when appropriate;
- target auth supplied through approved target-specific means;
- whether observed response/schema evidence represents application behavior or connectivity/configuration failure.

Do not globally enable mutating methods to bypass one denied call.

---

## k6 troubleshooting

A performance run can be blocked because:

- k6 executable is absent;
- target is production/unknown or production-like;
- host is not allowlisted;
- script does not consume injected `BASE_URL` / `TARGET_URL`;
- script imports remote modules or `k6/x/*`;
- local `open()` is present;
- unrelated literal hosts are present;
- unsupported imports are detected;
- deployment egress prerequisite is absent.

For **every** k6 run:

```bash
export AI_QA_K6_EXTERNAL_EGRESS_ENFORCED=true
```

> [!WARNING]
> The flag is not a firewall. If the deployment does not actually constrain outbound traffic, the prerequisite is false and the run should not be authorized.

Do not change predefined thresholds after seeing measurements just to make the gate green.

---

## GitHub MCP troubleshooting

Local prerequisites include:

- `AI_QA_ENABLE_GITHUB_MCP=true`;
- `GITHUB_PERSONAL_ACCESS_TOKEN` in environment;
- Docker;
- least-privilege permissions;
- provider connectivity.

Interpret by layer:

| Observation | Interpretation |
|---|---|
| disabled | deliberate configuration choice |
| enabled without token | `NOT_CONFIGURED` |
| token present, Docker unavailable | local blocker |
| provider rejects identity/permission | `UNAUTHORIZED` |
| explicit throttling | `RATE_LIMITED` |
| provider unreachable | network/outage investigation |

Do not replace the approved server with a community provider as an outage workaround.

---

## Atlassian Rovo MCP troubleshooting

Distinguish:

- authentication/session not established;
- organization policy disallows the auth mode;
- insufficient Jira/Confluence permissions;
- rate limiting;
- network failure;
- provider outage.

Do not persist Atlassian credentials in repository files, and do not treat issue/page text as control-plane instructions.

---

## Provider result normalization looks wrong

The normalizer deliberately avoids treating arbitrary numeric business IDs as HTTP results.

```text
issue 403 failed lookup   → not automatically HTTP 403
HTTP 403                  → authorization context
status code: 401          → authorization context
HTTP status 429           → rate-limit context
```

Preserve transport/status metadata separately from business payload values.

---

## Live Claude Agent SDK troubleshooting

A live model session requires `ANTHROPIC_API_KEY`.

If execution fails:

1. confirm variable presence without printing it;
2. distinguish authentication from network/provider failure;
3. confirm model identifier matches the installed SDK/provider contract;
4. distinguish budget/time/cost termination from provider failure;
5. preserve sanitized exception class and run provenance;
6. check first-party provider documentation/status when outage is plausible.

Never expose the key in logs or issue reports.

---

## Provider outage behavior

Temporary provider failure should not permanently widen architecture.

Preserve valid local evidence. Normalize the dependency failure. Do not fabricate remote evidence and do not switch to an unapproved integration just to continue.

---

## Corrupt state / journal / evidence / attestation

```bash
ai-qa recover artifacts/run-<id>
ai-qa lineage artifacts/run-<id>
ai-qa attest artifacts/run-<id>
```

A broken journal chain, unreadable state, duplicate/tampered manifest, symlinked owned subject, inconsistent pending mutation, or registered artifact hash mismatch cannot be converted into clean integrity by model reasoning.

A valid hash chain still proves only record-integrity properties—not application correctness.

---

## Security finding

`make security` defines dependency compatibility, Bandit, dependency vulnerability, and secret-scanning surfaces.

For a secret-like finding:

1. determine whether it is a real credential or controlled fixture false positive;
2. if real, revoke/rotate immediately;
3. remove current exposure and assess history/artifacts/forks/caches;
4. repair the exposure path;
5. use only narrow, justified detector exclusions for demonstrably non-secret fixtures.

Do not broadly disable secret scanning.

---

## Evidence to preserve when escalating

Prefer the smallest useful evidence package:

- exact objective/action;
- terminal/runtime outcome;
- sanitized exception type/message;
- run ID;
- evidence/validation IDs;
- target Git SHA + baseline/merge-base provenance when relevant;
- provider outcome;
- smallest relevant configuration/source snippet;
- artifact references/hashes;
- reproducibility conditions.

Do not paste entire repositories, huge traces, credentials, or private customer data just to provide “more context.”

---

## Escalation rule

> **If the only proposed fix requires weakening a deterministic safety invariant, stop and repair the underlying design instead.**

Safety controls should change through reviewed engineering work with matching deterministic regression/adversarial coverage.

---

## Related documentation

- [Setup](SETUP.md)
- [Operations](OPERATIONS.md)
- [Security architecture](SECURITY.md)
- [Runtime result contract](RESULT_CONTRACT.md)
- [Runtime control and recovery](RUNTIME_CONTROL.md)
- [Design boundaries](LIMITATIONS.md)

---

[← Operations](OPERATIONS.md) · [Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
