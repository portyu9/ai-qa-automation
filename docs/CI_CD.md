# CI/CD and Repository Governance

> [!IMPORTANT]
> **Workflow definition, workflow execution, validation subject, bot provenance, evidence admission, status identity, merge enforcement, and release preparation are separate authorities.** Ordinary pull-request CI is development evidence. Owner-routine admission, governed-bot admission, and external protected-maintenance admission use distinct deterministic policies, and none may let candidate-controlled bytes certify their own protected authority. Release-candidate evidence is separately non-publishing and cannot become publisher identity by carrying hashes or version metadata.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Supply chain](SUPPLY_CHAIN.md) · [Release candidate](RELEASE_CANDIDATE.md) · [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md) · [Operations](OPERATIONS.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Authority split

The repository and external control plane intentionally separate these surfaces:

| Surface | Trigger / wake-up | Authority | Intended role |
|---|---|---|---|
| `.github/workflows/ci.yml` | `pull_request`, `push` to `main`, `merge_group` | read-only, secret-free validation jobs | ordinary deterministic development evidence and exact build/test artifacts |
| `.github/workflows/trusted-pr-auto.yml` | reviewed CI/CodeQL completion through `workflow_run` for owner-routine wakes; serialized five-minute default-branch schedule for governed-bot reconciliation | trusted default-branch owner/bot admission; App credential only in the terminal reporter | owner-routine zero-drift authorization plus finite governed-bot exact-provenance authorization |
| external `scripts/trusted_gate_service/` deployment | GitHub App `workflow_run` webhook | independently deployed code, independently administered one-shot policy, durable external state, dedicated App credential | protected-maintenance authorization for exact reviewed protected-root transitions |
| `.github/workflows/release-candidate.yml` | explicit `workflow_dispatch` from `main` | read-only, secret-free, non-publishing package verification | exact-current-main/version/reproducible-wheel release-preparation evidence |
| `.github/workflows/manual-validation.yml` | `workflow_dispatch` | `credentialed-validation` Environment for selected provider evidence | optional live/model evidence; never protected merge authority |

There is no repository-owned `repository_dispatch` protected-maintenance authority. Candidate execution never receives the external protected-maintenance App private key or a terminal status-write token. Repository source cannot self-attest live GitHub App installation state, Environment restrictions, webhook configuration, external deployment identity, one-shot policy, ruleset binding, publisher identity, or later administrative drift.

## Ordinary CI subject and evidence

`ci.yml` binds automatic validation to one explicit subject:

```text
CI_SUBJECT_SHA = github.sha
```

For each supported GitHub event, `github.sha` is the event subject. Every automatic validation domain checks out that exact subject with persisted credentials disabled and verifies `git rev-parse HEAD == CI_SUBJECT_SHA` before project execution. No client payload may select another source or prospective-merge identity.

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

Before hash-locked dependency installation, `scripts/verify_build_authority.py` verifies the reviewed lock set and build authority. `scripts/verify_ci_contract.py` freezes the exact lane structure, immutable action identities, subject binding, install ordering, aggregate behavior, absence of repository-dispatch authority, the separate automatic trusted-workflow contract, and the separate non-publishing release-candidate contract. Stale Python 3.13 lane authority is rejected.

## Automatic Trusted PR Gate paths

`.github/workflows/trusted-pr-auto.yml` is the repository-owned automatic status authority. For owner-routine changes, a reviewed `workflow_run` event is only a wake-up signal. Governed bots instead use a serialized five-minute default-branch schedule that discovers a bounded same-repository candidate and fresh-GETs its live state. In both cases trusted default-branch bytes independently re-fetch current `main`, the PR, candidate head, prospective merge, and ordered merge parents before any App credential is available.

### Owner-routine path

For an owner-triggered same-repository PR, automatic admission requires exact reviewed pull-request CI identity and **zero protected authority-root drift**. The prospective merge is then executed through the full trusted validation graph. Candidate-executing jobs are read-only and secret-free.

### Governed-bot path

Three finite bot lanes are autonomous:

- canonical Dependabot GitHub Actions updates under the reviewed `dependabot/github_actions/...` namespace;
- GitHub Actions dependency-promotion PRs under `automation/dependency-promotion-...`;
- GitHub Actions CodeQL auto-heal PRs under `automation/codeql-autoheal-...`.

A bot login is never sufficient. The trusted-main scheduled reconciler admits only canonical bot numeric identity, reviewed branch grammar, same-repository ownership, definitive mergeability on exact current `main`, exact source lineage/marker/fingerprint, lane-specific changed-path semantics, and an exact prospective merge. Dependency promotions are deterministically regenerated under trusted interpreters. Security repairs are rebound to the live CodeQL alert, code-owned remediation strategy, generator, and bounded per-strategy attempt epoch; deterministic repairs must reproduce the code-owned bytes exactly. The full trusted validation graph then executes against the prospective merge. A separate bot-only CodeQL job analyzes the exact governed head ref/SHA, and the subject guard requires the governed head tree and prospective-merge tree to be byte-identical before that CodeQL result can support merge-subject authority.

The trusted workflow then runs the full supply-chain, quality, deterministic-evaluation, security, and Playwright suite against the prospective merge. Immediately before publication it re-runs live admission and terminal bot-policy proof. Only then does the terminal reporter enter Environment `trusted-pr-gate`, mint the dedicated App token, and publish `Trusted PR Gate`.

The App status target binds the exact PR number, base SHA, head SHA, and prospective merge SHA to the exact trusted-gate workflow run. Merge controllers have no App status-write credential: they independently re-read that App-authored binding, current PR/base/head/merge-ref/parents, and their lane policy before merging. After merge they require exact ordered `(base, head)` parents, a merge tree identical to the validated bot head tree, and the merge SHA to be current `main`; they do not manufacture post-merge green through nested workflow dispatch. Dependency governance and Security Auto-Heal also wake on completion of the Trusted PR Auto Gate so status publication has an event-driven convergence path.

Any API failure, ambiguity, fork, stale base, non-definitive mergeability, malformed/truncated response, parent/tree mismatch, bot/source provenance mismatch, failed trusted validation/CodeQL, or terminal subject drift is non-PASS truth.

## Unrecognized protected-maintenance external path

Protected changes that do not match one of the finite governed-bot policies remain deliberately ineligible for repository-hosted automatic authorization. They use the independently deployed external service described in [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md).

The break-glass authority chain is:

**ordinary PR CI completion → external App webhook ingress → exact live PR/head/base/merge resolution → independently administered one-shot protected-object policy → exact job/artifact/build-manifest verification → terminal live re-resolution → dedicated App status → strict protected-branch enforcement**

The external one-shot policy pins the exact repository identity, PR number, head SHA, current `main` base SHA, prospective merge SHA, complete protected-object transitions, and bounded validity window. Base/head/merge or object drift creates a different subject and requires new independent admission.

Only after policy admission may ordinary CI be used as execution evidence. The service independently verifies the exact reviewed run, required jobs, exactly two successful Python quality/compatibility lanes, supply-chain artifact identity/digest, bounded safe ZIP contents, exact `build-manifest.json` subject/tree binding, and candidate `CI_SUBJECT_SHA: ${{ github.sha }}` workflow authority.

Immediately before publication it resolves the live subject again and re-runs the same policy. Publication intent is persisted before the irreversible status POST. Ambiguous publication outcomes are reconciled by read-back; the POST is not automatically replayed after durable publication intent.

The external gate remains a separately administered break-glass trust root, not a normal dependency/security automation dependency.

## Repository-dispatch retirement

Earlier control-plane generations included owner `repository_dispatch` maintenance paths in `ci.yml` and a separate evidence-authorization workflow. They are retired from repository authority.

The current contract requires:

- no `repository_dispatch` trigger in ordinary CI;
- no client-payload subject selector;
- no repository-hosted protected-manifest admission block;
- no repository-hosted maintenance App reporter;
- no superseded `trusted-pr-evidence.yml` workflow or evidence verifier;
- no legacy owner-dispatch reporter CLI in `trusted_pr_control.py`; and
- fail-closed tests that reject reintroduction of those authorities.

A blocked or unavailable external protected-maintenance gate remains blocked. It must not be converted to PASS by restoring an easier candidate-controlled or stale historical path.

## Deterministic aggregate versus protected status

`Required PR Gate` is a deterministic aggregate inside ordinary CI. It uses `if: ${{ always() }}` and succeeds only when every required validation dependency succeeded. It is evidence, not merge authority.

`Trusted PR Gate` is the terminal protected context. The live `Protect Main` ruleset must bind that context to the dedicated GitHub App integration, not merely to the context string. A same-named status from another integration is not equivalent authority.

Strict/up-to-date enforcement matters because a base change can alter the prospective merge while leaving the head SHA unchanged. A prior status never certifies a new base/merge subject.

## Release-candidate evidence path

`release-candidate.yml` is an explicit, manual release-preparation workflow. It is deliberately not triggered by tag creation or push, has top-level `contents: read` only, receives no release/package/signing credential, and does not participate in `Trusted PR Gate`.

A release-candidate run must be dispatched from `refs/heads/main`. It binds `RELEASE_SUBJECT_SHA` to the workflow's exact `github.sha`, checks out that exact commit with persisted credentials disabled, and requires the requested stable `vMAJOR.MINOR.PATCH` label to equal `v` plus the static `pyproject.toml` project version. The verifier rejects dynamic version authority, wrong project identity, wrong ref/source, tracked/staged drift, malformed object IDs, symlink/special metadata inputs, and ambiguous wheel arguments.

Build authority is verified before the hash-locked build environment is installed. Two fresh archives are then produced from the exact source object through an isolated Git view with versioned attributes only. Each archive independently passes build-authority verification, produces exactly one expected wheel, and the two wheel byte streams must match exactly.

Release evidence is persisted under a fresh runner-owned `RUNNER_TEMP` directory rather than the repository checkout. Immediately before artifact upload, the workflow resolves live remote `refs/heads/main` and requires it still to equal `RELEASE_SUBJECT_SHA`. A stale run therefore fails rather than publishing release-candidate evidence for a no-longer-current `main`.

Only successful runs publish the single `release-candidate-evidence` artifact. Its manifest/checksums bind the exact source SHA/tree, static version label, `pyproject.toml` Git-blob identity, retained wheel filename/size/SHA-256, two-build reproducibility, and terminal observed `main` SHA. This remains integrity evidence only: it is not a real Git tag, release creation, package publication, publisher identity, signing/notarization, deployment approval, or production observation. See [Release Candidate Integrity](RELEASE_CANDIDATE.md).

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

The CI-contract verifier fails closed on drift in the reviewed repository workflow authority, including immutable Action SHAs, exact Python patch versions, quality-lane split, exact checkouts, absence of repository dispatch/client-payload authority, secret-free validation permissions with only the reviewed bot-CodeQL `security-events: write` exception, build/install ordering, evidence uploads, deterministic aggregate structure, automatic owner zero-protected-drift admission, governed-bot scheduled reconciliation, final App-credential isolation, and the release-candidate workflow's exact trigger/subject/build/reproducibility/live-main/no-write/no-secret boundaries.

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

A green ordinary run, trusted validation run, or `Trusted PR Gate` is not release-candidate evidence. A green release-candidate run is not a release signature, Git tag, GitHub Release, package publication, publisher identity, deployment approval, or proof that a production environment changed. Each stronger authority requires its own controlled evidence and must remain separately administered.

## Evidence semantics

- ordinary green = deterministic execution evidence for one exact subject;
- routine trusted green = exact zero-protected-drift admission plus deterministic execution and terminal App publication;
- external protected-maintenance green = exact independent policy admission plus exact execution/artifact evidence, terminal revalidation, and App publication;
- release-candidate green = exact-current-main/static-version/reproducible-package integrity evidence with no publishing authority;
- historical green = evidence for the older revision/control plane only;
- blocked, failed, missing, stale, wrong-integration, or unobserved evidence = non-PASS truth.

---

[← Supply chain](SUPPLY_CHAIN.md) · [Release candidate](RELEASE_CANDIDATE.md) · [Trusted PR control plane →](TRUSTED_PR_CONTROL_PLANE.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).