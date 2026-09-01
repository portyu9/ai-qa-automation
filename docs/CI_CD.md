# CI/CD and Repository Governance

> [!IMPORTANT]
> **Workflow definition, workflow execution, validation subject, evidence admission, status identity, and merge enforcement are separate authorities.** Ordinary pull-request CI is development evidence. Routine source-only admission and protected-maintenance admission use different trust roots, and neither may let candidate-controlled bytes certify their own protected authority.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Supply chain](SUPPLY_CHAIN.md) · [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md) · [Operations](OPERATIONS.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Authority split

The repository and external control plane intentionally separate these surfaces:

| Surface | Trigger / wake-up | Authority | Intended role |
|---|---|---|---|
| `.github/workflows/ci.yml` | `pull_request`, `push` to `main`, `merge_group`; legacy exact owner dispatch remains source | read-only, secret-free validation jobs | ordinary deterministic development evidence and exact build/test artifacts |
| `.github/workflows/trusted-pr-auto.yml` | reviewed CI completion through `workflow_run` | trusted default-branch admission, then Environment-held App credential only in the terminal reporter | routine source-only authorization when protected roots have zero drift |
| external `scripts/trusted_gate_service/` deployment | GitHub App `workflow_run` webhook | independently deployed code, independently administered one-shot policy, durable external state, dedicated App credential | protected-maintenance authorization for exact reviewed protected-root transitions |
| `.github/workflows/trusted-pr-evidence.yml` and owner `repository_dispatch` maintenance paths | explicit owner dispatch | legacy/emergency repository maintenance authority | retained compatibility path; **not accepted normal protected-maintenance operation** |
| `.github/workflows/manual-validation.yml` | `workflow_dispatch` | `credentialed-validation` Environment for selected provider evidence | optional live/model evidence; never protected merge authority |

Candidate execution never receives the external protected-maintenance App private key or a terminal status-write token. Repository source cannot self-attest live GitHub App installation state, Environment restrictions, webhook configuration, external deployment identity, one-shot policy, ruleset binding, or later administrative drift.

## Ordinary CI subject and evidence

`ci.yml` binds automatic validation to one explicit subject:

```text
CI_SUBJECT_SHA = repository_dispatch ? client_payload.expected_merge_sha : github.sha
```

For ordinary GitHub events, `github.sha` is the event subject. Every automatic validation domain checks out that exact subject with persisted credentials disabled and verifies `git rev-parse HEAD == CI_SUBJECT_SHA` before project execution.

Ordinary CI produces deterministic evidence, including:

- exact Python compatibility results;
- the 34-case deterministic control evaluation;
- security/dependency/secret scans;
- Playwright reference-SUT evidence;
- supply-chain and build-authority verification;
- Mermaid/documentation checks;
- runtime SBOM data;
- byte-identical wheel reproduction;
- digest-pinned runtime-container inspection;
- a subject-bound `build-manifest.json`; and
- the deterministic `Required PR Gate` aggregate.

A green ordinary run is **not** protected merge authority. It proves only that the executed candidate subject satisfied the reviewed deterministic gates for that run.

## Certified Python lanes

The automatic quality matrix has two exact, independently hash-locked lanes:

- **Python 3.11.16** — primary full-quality authority: compile, Ruff formatting, Ruff lint, strict Mypy, full deterministic pytest, and branch-aware coverage;
- **Python 3.14.7** — compatibility authority: compile, `pip check`, and the full deterministic pytest suite, without duplicating Ruff, Mypy, or coverage work.

`requires-python >=3.11` remains package metadata. It does not imply that every intermediate interpreter version is independently certified by CI. Repository certification claims are limited to the exact patch versions that actually execute.

Before hash-locked dependency installation, `scripts/verify_build_authority.py` verifies the reviewed lock set and build authority. `scripts/verify_ci_contract.py` freezes the exact lane structure, immutable action identities, subject binding, install ordering, and aggregate behavior. Stale Python 3.13 lane authority is rejected by the reviewed CI contract.

## Routine source-only trusted path

For an eligible same-repository PR with no protected-root drift, a successful reviewed ordinary CI run may wake `.github/workflows/trusted-pr-auto.yml` through `workflow_run`.

The wake-up payload is not authorization. Trusted default-branch admission independently re-fetches the triggering run, current `main`, the live PR, the live prospective merge, ordered merge parents, and protected Git objects. Automatic admission requires exact identity and **zero protected authority-root drift**.

Before candidate scripts run, trusted workflow bytes independently verify the prospective-merge subject and protected-object guard. Validation remains read-only and secret-free. The terminal reporter re-runs admission before it may obtain the dedicated App credential and publish `Trusted PR Gate`.

Any API failure, ambiguity, fork, stale base, malformed/truncated response, parent mismatch, or protected-root change makes the routine path non-PASS.

## Protected-maintenance external path

A PR that changes a protected authority root is deliberately ineligible for routine source-only authorization. Normal protected maintenance uses the independently deployed external service described in [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md).

The authority chain is:

**ordinary PR CI completion → external App webhook ingress → exact live PR/head/base/merge resolution → independently administered one-shot protected-object policy → exact job/artifact/build-manifest verification → terminal live re-resolution → dedicated App status → strict protected-branch enforcement**

The external one-shot policy pins the exact repository identity, PR number, head SHA, current `main` base SHA, prospective merge SHA, complete protected-object transitions, and bounded validity window. Base/head/merge or object drift creates a different subject and requires new independent admission.

Only after policy admission may ordinary CI be used as execution evidence. The service independently verifies the exact reviewed run, required jobs, exactly two successful Python quality/compatibility lanes, supply-chain artifact identity/digest, bounded safe ZIP contents, and exact `build-manifest.json` subject/tree binding.

Immediately before publication it resolves the live subject again and re-runs the same policy. Publication intent is persisted before the irreversible status POST. Ambiguous publication outcomes are reconciled by read-back; the POST is not automatically replayed after durable publication intent.

Live bootstrap evidence has proven this external path can publish the required App-authored status for an exact protected subject. That observation is historical evidence for the proven revision only; every newer protected subject still requires fresh exact policy, CI evidence, App status, and pre-merge revalidation.

## Legacy repository-dispatch paths

The repository still contains owner `repository_dispatch` maintenance workflows and Environment-held reporter support from earlier control-plane generations. They are retained as legacy/emergency source while retirement is handled as its own protected revision.

They are **not accepted normal operator steps** for current protected-maintenance progress. A blocked or unavailable external gate must remain blocked; it must not be converted to PASS by falling back to an easier candidate-controlled or stale historical path.

Removing legacy dispatch/reporting authority is itself a protected control-plane change and requires full ordinary CI, independent protected-object admission, fresh App-authored status, adversarial review, and completion audit.

## Deterministic aggregate versus protected status

`Required PR Gate` is a deterministic aggregate inside ordinary CI. It uses `if: ${{ always() }}` and succeeds only when every required validation dependency succeeded. It is evidence, not merge authority.

`Trusted PR Gate` is the terminal protected context. The live `Protect Main` ruleset must bind that context to the dedicated GitHub App integration, not merely to the context string. A same-named status from another integration is not equivalent authority.

Strict/up-to-date enforcement matters because a base change can alter the prospective merge while leaving the head SHA unchanged. A prior status never certifies a new base/merge subject.

## Supply-chain and browser authority

Automatic dependency caching is forbidden where it could precede reviewed lock/build authority. Hash-required dependency installation is bracketed by exact build-authority checks, and project installation is revalidated against the same authority.

Supply-chain CI verifies the runtime dependency graph, CycloneDX SBOM, reproducible wheels, and the digest-pinned runtime-container definition. Persisted evidence remains subject-bound and cannot certify a newer revision.

Automatic browser validation does not install browsers or privileged OS packages. It requires the hosted Chrome runtime, records its version, starts the deterministic localhost reference SUT, and executes the reviewed Playwright evidence test. The hosted browser is an observed environment input, not a cryptographically attested repository asset.

## Credentialed manual validation

`manual-validation.yml` remains `workflow_dispatch`-only and outside protected merge evidence. Repository-visible readiness checks and credentialed Claude Agent SDK smoke evidence are separate evidence classes.

When the provider smoke is executable, `ANTHROPIC_API_KEY` is scoped to the selected credentialed job. The provider smoke validates the structured runtime contract directly; it does not grant candidate target code arbitrary subprocess pytest authority. Real target pytest execution remains a deployment-owned isolation boundary and must be reported as unavailable/blocked when that isolation is not proven.

Missing credentials, provider outage, Environment approval failure, or other external limitations remain blocked/unavailable rather than automatic PASS.

## Repository-owned workflow verification

Run:

```bash
python scripts/verify_ci_contract.py
python scripts/verify_docs.py
```

The CI-contract verifier fails closed on drift in the reviewed repository workflow authority, including immutable Action SHAs, exact Python patch versions, quality-lane split, exact checkouts, protected-root guards, read-only validation permissions, build/install ordering, evidence uploads, and deterministic aggregate structure.

The documentation verifier checks repository-owned structural and selected implementation-coupled claims. It does not turn external GitHub/AWS/provider facts into source-certified truth; those remain externally observed evidence.

## Merge-enforcement invariant

Before any protected merge, independently re-fetch and reconcile:

1. open/non-draft PR identity;
2. exact head SHA and current `main` base SHA;
3. live prospective merge SHA/tree and exactly ordered parents `(base, head)`;
4. exact protected-root transition set;
5. ordinary CI run/job/artifact identity for the same subject;
6. `Trusted PR Gate: success` from the dedicated App integration on the exact head;
7. active strict ruleset binding with no bypass actors;
8. review and review-thread state; and
9. external authorization/deployment state where applicable.

Merge only the exact validated head using the configured protected merge method. Any subject or authority drift invalidates earlier admission.

## Release and deployment non-authority

A green ordinary run, trusted validation run, or `Trusted PR Gate` is not a release signature, package publication, deployment approval, or proof that a production environment changed. Release/deployment authority requires its own controlled evidence and is outside these CI merge gates.

## Evidence semantics

- ordinary green = deterministic execution evidence for one exact subject;
- routine trusted green = exact zero-protected-drift admission plus deterministic execution and terminal App publication;
- external protected-maintenance green = exact independent policy admission plus exact execution/artifact evidence, terminal revalidation, and App publication;
- historical green = evidence for the older revision/control plane only;
- blocked, failed, missing, stale, wrong-integration, or unobserved evidence = non-PASS truth.

---

[← Supply chain](SUPPLY_CHAIN.md) · [Trusted PR control plane →](TRUSTED_PR_CONTROL_PLANE.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
