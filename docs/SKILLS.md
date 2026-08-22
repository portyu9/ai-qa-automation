# Claude Skills

The project uses five focused Claude Skills to load specialized QA procedures only when the objective needs them. Skills are **reasoning/playbook context**, not permission grants: deterministic runtime policy, hooks, controlled tools, evidence requirements, execution budgets, and validation remain authoritative regardless of what a Skill says.

The live Agent SDK configuration explicitly allowlists these five project Skills rather than exposing an open-ended catalog.

## Skill inventory

| Skill | Purpose | Key deterministic boundary |
|---|---|---|
| `investigate-test-failure` | Evidence-driven root-cause investigation and classification | Material classifications reference observed evidence; model interpretation alone cannot prove a defect class. |
| `self-heal-test` | Guarded semantic locator maintenance | Requires browser-observed candidate evidence, supported classification, bound file/hash/proposal, policy-authorized locator-only change, and current-revision validation. |
| `generate-test` | Coverage-aware test design and creation | Requires observed repository coverage plus same-run plan provenance before guarded test creation. |
| `prioritize-regression` | Risk-aware regression selection | Mandatory coverage is preserved; low confidence/incomplete dependency evidence broadens rather than shrinks execution. |
| `performance-test` | Controlled k6 performance assessment | Production/unknown targets are blocked; thresholds are predefined and real measured evidence is required. |

## Why Skills are separate

A large permanent system prompt makes context noisier and encourages instructions for unrelated tasks to remain active. The Skill design instead keeps the always-on runtime contract small while loading a specific procedure for a specific quality-engineering activity.

That separation also makes each workflow reviewable. A reviewer can answer:

- when is this procedure appropriate?
- what evidence must exist first?
- what may the model propose?
- which side effects are actually available?
- which shortcuts are prohibited?
- what deterministic validation is required before completion?
- when must the agent escalate or stop?

## `investigate-test-failure`

Path:

```text
.claude/skills/investigate-test-failure/SKILL.md
```

The Skill is used when a test failed but the cause is uncertain or contested. Its procedure favors discriminating evidence over repeated retries and considers competing hypotheses such as product, automation, locator/UI-contract, data, timing, environment, dependency, authentication, configuration, and performance causes.

Important boundary:

> A test failure alone is not evidence of a product defect.

The expected output cites evidence IDs and preserves unresolved ambiguity as insufficient evidence rather than forcing a classification.

## `self-heal-test`

Path:

```text
.claude/skills/self-heal-test/SKILL.md
```

This Skill is intentionally narrow. It is not a generic “repair any failing test” capability.

The workflow requires the expected product behavior to still exist, Playwright-observed original/candidate locator evidence, an appropriate deterministic failure classification, an exact authorized test path/hash, and explicit test-write permission.

The Skill prohibits model-declared uniqueness, arbitrary dynamic selectors, generic text replacement, assertion weakening/removal, skip/xfail, arbitrary sleeps, timeout inflation, and product-code mutation solely to make the test green.

Even an applied locator change remains incomplete until the current revision has patch-safety, targeted pytest, and full-regression PASS evidence.

## `generate-test`

Path:

```text
.claude/skills/generate-test/SKILL.md
```

Test generation begins with the expected behavior and observed repository coverage—not with a request to produce code immediately.

The provenance chain is:

```text
requirement/change
→ bounded coverage search
→ observed coverage evidence
→ same-run test plan
→ guarded test creation
→ deterministic quality/execution/regression validation
```

The Skill favors the lowest reliable test layer that proves the behavior and rejects assertion-free, plan-less, redundant, arbitrary-sleep, `.skip`/`.only`, timeout-inflated, or mock-only tests.

If expected behavior is unknown, generation should block/escalate rather than invent product intent.

## `prioritize-regression`

Path:

```text
.claude/skills/prioritize-regression/SKILL.md
```

This Skill optimizes **risk-adjusted recall before execution reduction**.

Inputs include changed files/modules/APIs, dependency/ownership signals, candidate tests, historical failures, runtime cost, and business/security/safety/regulatory criticality.

Mandatory coverage is independent of model preference. Low confidence, incomplete dependency mapping, conflicting evidence, or an incomplete candidate inventory causes the strategy to broaden.

A small selected suite is not success if it creates meaningful escaped-regression risk.

## `performance-test`

Path:

```text
.claude/skills/performance-test/SKILL.md
```

This Skill guides bounded k6 use only when a target is explicitly non-production, the workload is bounded, the host is authorized, the script satisfies the injected-target restrictions, and thresholds are defined before execution.

Non-local targets additionally require the trusted infrastructure-egress precondition. That precondition asserts an external control exists; it does not turn application code into a firewall.

PASS/FAIL comes from real k6 measurements plus deterministic threshold assessment. Missing executable, target access, or egress evidence remains blocked/not verified.

## Skills do not override the trust model

No Skill can:

- add a new runtime tool;
- enable Bash/Edit/Write/Web authority;
- change policy or protected paths;
- enable an external MCP provider;
- approve an external write;
- widen the network allowlist;
- increase runtime budgets;
- declare a model interpretation observed evidence;
- convert incomplete validation into PASS;
- change evaluation thresholds or holdout expectations.

Those decisions live in trusted deterministic configuration/code and reviewed engineering changes.

## Target Skills and prompt injection

A target repository may contain its own `CLAUDE.md`, `.claude/skills/`, or similar instruction-shaped content. The production runtime treats target content as untrusted data and does not accept those files as control-plane Skills.

The Agent SDK is configured from the trusted project root with an explicit Skill allowlist. This prevents a SUT from gaining authority simply by placing agent-looking configuration in its repository.

## Skill maintenance standard

A Skill change should be reviewed like an algorithm/procedure change, especially when it affects mutation, evidence sufficiency, escalation, or regression scope.

When changing a Skill:

1. preserve deterministic authority boundaries;
2. avoid duplicating rules already enforced more reliably in policy/tools;
3. keep evidence requirements explicit;
4. keep prohibited shortcuts explicit;
5. add/update deterministic tests or adversarial evaluation when the behavioral contract changes;
6. do not modify predefined safety thresholds merely because new Skill behavior performs poorly.

Source presence is not current-head execution evidence. Skill behavior remains `NOT_VERIFIED` on the current head until the applicable deterministic/model-backed gates are intentionally executed.

See [`ARCHITECTURE.md`](ARCHITECTURE.md), [`EVALUATION.md`](EVALUATION.md), [`SECURITY.md`](SECURITY.md), and [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).
