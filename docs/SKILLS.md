# Claude Skills

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

The ƳƤ AI QA Automation Framework uses five focused Claude Skills to load specialized QA procedures only when the objective needs them. Skills are **reasoning/playbook context, not permission grants**: deterministic runtime policy, hooks, controlled tools, evidence requirements, budgets, and validation remain authoritative regardless of Skill instructions.

The live Agent SDK configuration explicitly allowlists these five framework Skills rather than exposing an open-ended catalog.

## Skill inventory

| Skill | Purpose | Deterministic boundary |
|---|---|---|
| `investigate-test-failure` | Evidence-driven root-cause investigation | Material classification references observed evidence; model interpretation alone cannot prove a defect class |
| `self-heal-test` | Guarded semantic locator maintenance | Playwright proves uniqueness; deterministic locator semantics/stability constrain eligibility; file/hash/proposal and revision validation bind mutation |
| `generate-test` | Coverage-aware test design and creation | Observed coverage plus same-run plan provenance is required before guarded creation |
| `prioritize-regression` | Risk-aware regression selection | Mandatory coverage is preserved; low confidence broadens rather than shrinks execution |
| `performance-test` | Controlled k6 performance assessment | Production targets are denied; target/script policy and predefined measured thresholds govern outcome |

## Why Skills are separate

A monolithic permanent prompt mixes procedures that do not belong to every objective. Focused Skills keep the always-on runtime contract smaller while making each quality-engineering workflow independently reviewable.

For every Skill, a reviewer should be able to answer:

- when is this procedure appropriate?
- which evidence must exist first?
- what may the model interpret or propose?
- which side effects are actually available?
- which shortcuts are prohibited?
- which deterministic gates close the work?
- when must the workflow stop or escalate?

## `investigate-test-failure`

Path:

```text
.claude/skills/investigate-test-failure/SKILL.md
```

The procedure favors discriminating evidence over repeated retries and considers competing hypotheses such as application, automation, locator/UI-contract, data, timing, environment, dependency, authentication, configuration, and performance causes.

> **A test failure alone is not evidence of a product defect.**

The output cites evidence IDs and preserves unresolved ambiguity rather than forcing a convenient classification.

## `self-heal-test`

Path:

```text
.claude/skills/self-heal-test/SKILL.md
```

This Skill is deliberately narrower than “repair a failing test.” It governs semantic locator maintenance only.

The workflow requires:

- expected product behavior to remain present;
- same-DOM Playwright evidence for original and candidate locators;
- an appropriate deterministic failure classification;
- an original locator inside the supported literal locator grammar;
- exact authorized test path and file hash;
- explicit autonomous test-write enablement.

Critically, **model confidence does not authorize the repair**. The deterministic self-healing engine:

1. uses Playwright-observed match counts rather than model-declared uniqueness;
2. reparses original/candidate locator syntax;
3. recomputes semantic-intent overlap from the locator contracts;
4. replaces model-supplied stability with policy-owned strategy stability;
5. rejects positional/XPath-style or weak-semantic candidates;
6. requires locator-only patching and current-revision closure.

An applied locator change remains transactional until patch-safety, targeted pytest, and full-regression PASS close the new revision.

## `generate-test`

Path:

```text
.claude/skills/generate-test/SKILL.md
```

Generation begins with expected behavior and observed repository coverage—not an instruction to immediately produce code.

```text
requirement/change
→ bounded coverage search
→ observed coverage evidence
→ same-run test plan
→ guarded creation
→ deterministic quality/execution/regression validation
```

The procedure favors the lowest reliable layer that proves the behavior and rejects assertion-free, plan-less, arbitrary-sleep, `.skip`/`.only`, timeout-inflated, or otherwise intent-eroding tests.

Unknown product intent remains unknown; it is not invented to generate a test.

## `prioritize-regression`

Path:

```text
.claude/skills/prioritize-regression/SKILL.md
```

This Skill optimizes **risk-adjusted recall before execution reduction**.

Inputs can include changed components/APIs, dependency/ownership signals, candidate tests, historical failure behavior, runtime cost, and business/security/safety/regulatory criticality.

Mandatory coverage is independent of model preference. Low confidence, incomplete dependency mapping, conflicting evidence, or incomplete candidate inventory broadens the strategy.

## `performance-test`

Path:

```text
.claude/skills/performance-test/SKILL.md
```

This Skill guides bounded k6 use when a target is explicitly non-production, the workload is bounded, the host is authorized, the script satisfies target-binding/import restrictions, and thresholds are defined before execution.

Non-local targets additionally require the infrastructure-egress precondition. That precondition is an application-side prerequisite, not a simulated firewall.

PASS/FAIL comes from measured k6 evidence plus deterministic threshold assessment.

## Skills never override the trust model

No Skill can:

- add a runtime tool;
- enable Bash/Edit/Write/Web authority;
- change policy or protected paths;
- enable an external provider by itself;
- approve an external write;
- widen the network allowlist;
- increase runtime budgets;
- declare model interpretation to be observed fact;
- convert incomplete validation into PASS;
- change evaluation thresholds or holdout expectations.

Those decisions live in trusted deterministic code/configuration and reviewed engineering changes.

## Target Skills and prompt injection

A target repository may contain its own `CLAUDE.md`, `.claude/skills/`, or similar instruction-shaped content. The runtime treats those files as untrusted target data and does not accept them as control-plane Skills.

The Agent SDK is configured from the trusted framework root with an explicit Skill allowlist, preventing a SUT from acquiring authority merely by shipping agent-looking configuration.

## Skill maintenance standard

A Skill change is an algorithm/procedure change, especially when it affects mutation, evidence sufficiency, escalation, or regression scope.

A high-quality Skill change should:

1. preserve deterministic authority boundaries;
2. avoid duplicating controls enforced more reliably in code;
3. keep evidence requirements explicit;
4. keep prohibited shortcuts explicit;
5. add deterministic regression/adversarial coverage when behavior changes;
6. preserve predefined hard-safety expectations.

See [`README.md`](README.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md), [`EVALUATION.md`](EVALUATION.md), and [`SECURITY.md`](SECURITY.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
