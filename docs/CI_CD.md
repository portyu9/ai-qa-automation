# CI/CD and Repository Governance

> [!IMPORTANT]
> **Workflow definition, workflow execution, validation subject, bot provenance, evidence admission, status identity, merge enforcement, and release preparation are separate authorities.** Ordinary pull-request CI is development evidence. Owner-routine admission, governed-bot admission, and accepted-main owner-protected maintenance use distinct deterministic policies, and none may let candidate-controlled bytes certify their own protected authority. Release-candidate evidence is separately non-publishing and cannot become publisher identity by carrying hashes or version metadata.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Supply chain](SUPPLY_CHAIN.md) · [Release candidate](RELEASE_CANDIDATE.md) · [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md) · [Operations](OPERATIONS.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Authority split

The repository and GitHub control plane intentionally separate these surfaces:

| Surface | Trigger / wake-up | Authority | Intended role |
|---|---|---|---|
| `.github/workflows/ci.yml` | `pull_request`, `push` to `main`, `merge_group`, reviewed `workflow_call`, explicit exact-subject `workflow_dispatch` | secret-free deterministic validation; exact-subject publication remains isolated to its reviewed generated-maintenance publisher | ordinary deterministic development evidence, reusable accepted-main validation, and exact build/test artifacts |
| `.github/workflows/codeql.yml` | `pull_request`, `push` to `main`, schedule, reviewed `workflow_call`, explicit exact-subject `workflow_dispatch` | `security-events: write` only in analysis jobs; generated-maintenance check publication is separately isolated | canonical Python CodeQL analysis, including reusable accepted-main post-merge SARIF publication |
| `.github/workflows/post-merge-ci.yml` | successful accepted-main `dependency-governance`, Security Auto-Heal, or Protected Security Remediation `workflow_run` lanes only | `contents: read` except the reusable CodeQL call's isolated `security-events: write`; no dispatch/merge/status/App-token/secret authority | lane-bind an exact controller-caused main merge, re-prove the signed merge, then require canonical reusable CI and CodeQL |
| `.github/workflows/trusted-pr-auto.yml` | reviewed CI/CodeQL/dependency-governance `workflow_run` wakes plus serialized five-minute schedule; protected-owner maintenance comments are durable authorization data discovered and revalidated by accepted-main reconciliation, not direct workflow triggers | trusted default-branch owner/bot admission; App credential only in the terminal reporter | owner-routine zero-drift, finite governed-bot, and explicit exact-subject owner-protected authorization |
| `.github/workflows/ruleset-reconciler.yml` | accepted-main push, six-hour convergence schedule, explicit main-only recovery dispatch | read-only native token produces only a non-authoritative predecessor/successor hint when GitHub redacts bypass actors; isolated `ruleset-admin-identity` dedicated App then re-proves the exact live state with repository Administration read/write authority before any mutation | one exact predecessor→successor `Protect Main` transition, non-replaying read-back recovery, durable non-secret receipt |
| `.github/workflows/ruleset-drift-sentinel.yml` | six-hour schedule or explicit main-only dispatch | native `contents: read` only; secret-free and environment-free | require the observable exact successor plus the reviewed full-state ruleset revision witness (repository/ruleset identity and revision timestamps), accepting only an exact timestamp instant or GitHub's documented whole-second UTC read-only projection so observable revision drift fails closed without giving the periodic observer mutation authority |
| `.github/workflows/dependency-governance-pr.yml` | `pull_request` only | `contents: read`, secret-free, mutation-free candidate evidence | compile/config/self-test the dependency controller without exposing privileged authority |
| `.github/workflows/dependency-governance.yml` | completed same-repository CodeQL `workflow_run` limited to `main`, `dependabot/github_actions/**`, `dependabot/pip/**`, or `automation/dependency-promotion-*`; serialized five-minute schedule | accepted-main reconciliation; independent promotion-author App only in the exact-current-main govern job | Dependabot qualification/recovery, independent-App promotion authoring, and scheduled exact-gate dependency convergence |
| `.github/workflows/dependency-trusted-merge.yml` | completed successful Trusted PR Auto Gate `workflow_run` bound to exact current accepted `main` | separate read-only resolver and owner-review job; isolated merge write ceiling; isolated consumed-promotion-ref cleanup write ceiling; reusable CI/CodeQL validation; terminal GitHub-Actions check publication only after exact first-attempt reproof | one-way post-certification dependency path through exact owner approval, guarded merge, exact cleanup, same-run CI/CodeQL, and durable `Dependency Post-Merge Gate` evidence |
| `.github/workflows/security-autoheal-pr.yml` | `pull_request` only | `contents: read`, secret-free, mutation-free candidate evidence | compile/config/self-test the security controller without exposing write-capable reconciliation |
| `.github/workflows/security-autoheal.yml` / `.github/workflows/protected-security-remediation.yml` | Security Auto-Heal: successful same-repository CodeQL or Trusted PR Auto `workflow_run` filtered to `main`, plus schedule/manual; protected remediation: successful same-repository Security Auto-Heal completion plus schedule | deterministic alert routing plus separately credentialed protected repair authoring | ordinary auto-heal and protected one-file remediation without executing candidate workflow bytes in privileged controllers |
| `.github/workflows/release-candidate.yml` | explicit `workflow_dispatch` from `main` | read-only, secret-free, non-publishing package verification | exact-current-main/version/reproducible-wheel release-preparation evidence |
| `.github/workflows/manual-validation.yml` | `workflow_dispatch` | `credentialed-validation` Environment for selected provider evidence | optional live/model evidence; never protected merge authority |

GitHub may redact `bypass_actors` from read-only ruleset responses. The drift sentinel therefore never treats a projected empty bypass list as sufficient authority: the checked-in full-state witness binds the ruleset object/revision that was independently certified with zero bypass actors after reconciliation. GitHub's read-only repository-ruleset representation may expose revision timestamps at whole-second UTC precision even when the privileged certification retained fractional seconds. The sentinel accepts only the exact certified instant or that exact whole-second `...Z` projection; a full-precision disagreement, a different observed second, visible policy drift, changed object identity, or unexpected bypass capability fails closed and requires a new privileged certification. Sub-second-only hidden edits that the read-only API does not expose are a platform observability boundary and are not claimed as independently detectable without granting the periodic observer write-capable ruleset authority. The periodic sentinel itself holds no App secret or repository-administration permission.

There is no repository-owned `repository_dispatch` protected-maintenance authority. Candidate execution must never receive the `trusted-pr-gate`, `ruleset-admin-identity`, or `protected-remediation-author` Environment credentials; those external Environment restrictions remain independently administered facts. The status-writing Trusted PR Gate App and the repository-ruleset Administration App are distinct identities and must never share credentials or permissions. Repository source defines the reviewed desired ruleset/transition contract but cannot self-attest live GitHub App installation state, Environment restrictions, live ruleset convergence, publisher identity, Actions policy, or later administrative drift.

## Ordinary CI subject and evidence

> [!NOTE]\n> Pull-request validation workflows are evidence-bearing only when the PR targets a branch selected by their `pull_request` filters. In this repository that validation target is `main`; a stacked PR targeting another feature branch must not be described as CI-validated merely because its head is mergeable. Retarget it to `main` (or otherwise create an explicitly reviewed validation path), then bind claims to workflow runs created for the exact candidate head.\n\n`ci.yml` binds automatic validation to one explicit subject:

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

Before hash-locked dependency installation, `scripts/verify_build_authority.py` verifies the reviewed lock set and build authority. `scripts/verify_ci_contract.py` freezes the exact lane structure, immutable action identities, subject binding, install ordering, aggregate behavior, dispatch-free dependency post-merge validation, same-run terminal evidence, the separate automatic trusted-workflow contract, and the separate non-publishing release-candidate contract. Stale Python 3.13 lane authority is rejected.

## Automatic Trusted PR Gate paths

`.github/workflows/trusted-pr-auto.yml` is the repository-owned terminal status authority. For owner-routine changes, a reviewed `workflow_run` event is only a wake-up signal. Exact Dependabot-authored Actions PRs may also use a successful live-refetched CI `workflow_run` only as a subject wake; dependency promotions use a reviewed dependency-governance completion wake after a neutral exact-subject qualification check. The serialized five-minute default-branch schedule remains a governed-bot liveness fallback rather than the sole Actions-bot selector. Once the policy is accepted on `main`, owner-protected maintenance uses an exact newly-created owner `issue_comment` authorization; that lane is deliberately unavailable to the PR that first introduces it. Every lane independently re-fetches current `main`, the PR, candidate head, prospective merge, and ordered merge parents before any App credential is available.

### Owner-routine path

For an owner-triggered same-repository PR, automatic admission requires exact reviewed pull-request CI identity and **zero protected authority-root drift**. The prospective merge is then executed through the full trusted validation graph. Candidate-executing jobs are read-only and secret-free.

### Governed-bot path

Four finite bot lanes are autonomous:

- canonical Dependabot GitHub Actions updates under the reviewed `dependabot/github_actions/...` namespace;
- exact dependency-promotion PRs under `automation/dependency-promotion-...`, newly authored by the reviewed independent non-certifying promotion App while legacy GitHub-Actions-authored subjects are cleanup-only;
- GitHub Actions CodeQL auto-heal PRs under `automation/codeql-autoheal-...`;
- exact dedicated-App protected security remediations under `automation/protected-security-remediation-...`.

App-authored generated subjects that must converge onto protected `main` do not rely on a direct PR-open event for unattended qualification. Dependency promotions and both security-remediation publishers use lane-owned temporary non-main staging bases, bind those refs to the exact accepted control SHA, prove the exact App/generated subject before retargeting the same PR to `main`, and delete staging only after exact read-back convergence. Ambiguous create/retarget outcomes are never blindly replayed: exact refs are retained for bounded later recovery, while cleanup requires unchanged SHA ownership and no open-PR claim. Staging evidence is liveness/provenance only and cannot satisfy `Trusted PR Gate`, owner approval, or merge authority.

A bot login is never sufficient. The trusted-main bot reconciler admits only canonical bot numeric identity, reviewed branch grammar, same-repository ownership, definitive mergeability on exact current `main`, exact source lineage/marker/fingerprint, lane-specific changed-path semantics, and an exact prospective merge. Dependency promotions are deterministically regenerated under trusted interpreters. Security repairs are rebound to the live CodeQL alert, code-owned remediation strategy, generator, and bounded per-strategy attempt epoch. A repair superseded only because `main` advanced is closed with exact `main-advanced` metadata and an unedited exact-identity `github-actions[bot]` supersession certificate bound to the PR/base/head and the exact Security Auto-Heal workflow id/run/attempt; only that certificate plus the final bot closure may exclude a future attempt from the strategy budget. Legacy exclusion is permitted only for the two code-owned historical stale repairs (#207 and #216), whose exact base/head/fingerprint/closure facts are pinned and additionally bounded by the fixed migration cutoff plus issue-timeline proof. Deterministic repairs must reproduce the code-owned bytes exactly. The full trusted validation graph then executes against the prospective merge. A separate bot-only CodeQL job analyzes the exact governed head ref/SHA, and the subject guard requires the governed head tree and prospective-merge tree to be byte-identical before that CodeQL result can support merge-subject authority.

The trusted workflow then runs the full supply-chain, quality, deterministic-evaluation, security, and Playwright suite against the prospective merge. Immediately before publication it re-runs live admission and terminal bot-policy proof. Only then does the terminal reporter enter Environment `trusted-pr-gate`, mint the dedicated App token, and publish `Trusted PR Gate`. Owner-routine admission intentionally skips the governed-bot authority job; every downstream candidate-validation, aggregate, and reporter job therefore uses `!cancelled()` plus explicit prerequisite-result checks so GitHub's transitive skipped-`needs` propagation cannot silently suppress validation, while cancellation still stops authority-bearing work.

The App status target binds the exact PR number, base SHA, head SHA, and prospective merge SHA to the exact trusted-gate workflow run. Merge controllers have no App status-write credential: they independently re-read that App-authored binding, current PR/base/head/merge-ref/parents, and their lane policy before merging. Dependency post-certification liveness is intentionally acyclic and does not trust a GitHub `status` event as a controller wake. Promotions may first use one neutral exact-run governance qualification wake, while exact Dependabot Actions PRs may enter Trusted PR Auto from their reviewed CI wake; after either lane passes the trusted graph, the dedicated App status remains terminal evidence. The five-minute accepted-main governance schedule can consume that evidence independently, and a successful completed Trusted PR Auto run may also wake `dependency-trusted-merge.yml`. That workflow physically separates three stages: a read-only resolver rebinds the exact trusted run/current main and accepts at most one live dependency subject whose App status points to that same run; an isolated `portyu9-review-identity` job re-resolves that subject, verifies the owner token's live identity, rejects a manual exact-head `CHANGES_REQUESTED` veto, and publishes or reuses exactly one durable gate-bound `APPROVE` review as `portyu9`; and a separate merge job with no owner-review credential requires that exact review before invoking the target-specific controller for final App-gate, control-revision, merge-ref/parent/tree, and SHA-guarded merge revalidation. The review body binds the exact PR, base/head, prospective merge, trusted run, and status id; wrong-author, wrong-state, wrong-head, duplicate exact owner reviews, malformed evidence, or a post-review subject change fails closed. Ambiguous review submission is accepted only when exactly one matching durable owner review can be re-read. The Environment and token are live platform authority and must be independently configured; repository source cannot attest their availability or effective GitHub permissions.

After a successful dependency merge, the trusted merger re-fetches the merged PR, live `main`, exact ordered parents, GitHub merge author/committer, and signature verification, then exports only the exact prior-control and accepted-main subject SHAs. A consumed promotion ref is deleted in a separate exact cleanup job only after independent-App head ownership, unchanged live `main`, exact ref SHA, and zero open-PR claims are re-proved. The same accepted-main `Dependency Trusted Merge` run then invokes canonical reusable CI and CodeQL against the exact merged-main SHA. Its first-attempt-only `Dependency Post-Merge Required Gate` requires CI and CodeQL success plus promotion cleanup success (or an exact skipped cleanup for a direct Dependabot Actions lane), re-proves the merged PR/current-main/ordered-parent/GitHub-signature tuple, and only then publishes a GitHub-Actions-owned `Dependency Post-Merge Gate` check whose external identity binds PR, prior control SHA, merged subject SHA, run id, and attempt. Before later dependency or security mutation, `dependency_recovery.py` accepts only canonical direct post-merge workflow evidence or that exact trusted-merge terminal check. The five-minute dependency-governance schedule remains a bounded recovery path: if exact current-main dependency validation is missing, the same scheduled run must execute canonical reusable CI and CodeQL successfully before mutation can continue; it emits no dispatch and cannot manufacture terminal history. `post-merge-ci.yml` no longer listens to Dependency Trusted Merge and exposes no repository/workflow dispatch path; it remains the workflow-run bridge for dependency-governance and security-controller merges. Trusted PR Auto does not listen to the dependency merger, so the dependency wake graph remains one-way.

Any API failure, ambiguity, fork, stale base, non-definitive mergeability, malformed/truncated response, parent/tree mismatch, bot/source provenance mismatch, failed trusted validation/CodeQL, or terminal subject drift is non-PASS truth.

## Owner-protected maintenance

Protected changes that do not match a finite governed-bot policy remain deliberately ineligible for automatic owner-routine authorization. After the reviewed policy is accepted on `main`, an owner-authored protected PR uses the exact-subject authorization-comment lane described in [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md). Accepted-`main` code re-fetches the immutable owner comment and exact PR/base/head/prospective-merge subject, executes the full trusted validation graph, and revalidates immediately before the dedicated App publishes terminal evidence.

There is no external cloud compatibility gate in the production architecture. The former `scripts/trusted_gate_service/` runtime is retired, its webhook path is not required, and CI fails if that runtime or GitHub Actions cloud-authentication authority is reintroduced. The **ƳƤ Trusted PR Gate** GitHub App remains installed because its identity is the ruleset-bound status authority; an active App webhook is not required for this path.

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

A blocked or unavailable GitHub-native protected-maintenance path remains blocked. It must not be converted to PASS by restoring an external, candidate-controlled, or stale historical path.

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

The CI-contract verifier fails closed on drift in the reviewed repository workflow authority, including immutable Action SHAs, exact Python patch versions, quality-lane split, exact checkouts, absence of repository dispatch/client-payload authority, secret-free validation permissions with only the reviewed bot-CodeQL `security-events: write` exception, build/install ordering, evidence uploads, deterministic aggregate structure, automatic owner zero-protected-drift admission, governed-bot event-driven admission plus scheduled fallback, final App-credential isolation, and the release-candidate workflow's exact trigger/subject/build/reproducibility/live-main/no-write/no-secret boundaries.

The documentation verifier checks repository-owned structural and selected implementation-coupled claims. It does not turn live GitHub platform or provider facts into source-certified truth; those remain externally observed evidence.

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
9. independently observed platform-owned authorization and deployment state where applicable.

Merge only the exact validated head using the configured protected merge method. Any subject or authority drift invalidates earlier admission.

## Release and deployment non-authority

A green ordinary run, trusted validation run, or `Trusted PR Gate` is not release-candidate evidence. A green release-candidate run is not a release signature, Git tag, GitHub Release, package publication, publisher identity, deployment approval, or proof that a production environment changed. Each stronger authority requires its own controlled evidence and must remain separately administered.

## Evidence semantics

- ordinary green = deterministic execution evidence for one exact subject;
- routine trusted green = exact zero-protected-drift admission plus deterministic execution and terminal App publication;
- accepted-main protected-owner green = exact owner/comment/current-main/subject authorization plus full trusted validation, terminal revalidation, and App publication;

- release-candidate green = exact-current-main/static-version/reproducible-package integrity evidence with no publishing authority;
- historical green = evidence for the older revision/control plane only;
- blocked, failed, missing, stale, wrong-integration, or unobserved evidence = non-PASS truth.

---

### CodeQL security-result gate

A successful CodeQL process proves that analysis executed; it does **not** by itself prove that the subject is security-clean. The repository therefore treats CodeQL SARIF as deterministic validation evidence:

- `.github/workflows/codeql.yml` emits SARIF for ordinary and exact-subject analyses and fails if the SARIF contains any CodeQL result.
- `.github/workflows/trusted-pr-auto.yml` applies the same zero-findings rule to the exact prospective-merge subject before `Trusted PR Gate` can be published.
- The trusted automatic controller materializes `scripts/verify_codeql_sarif.py` from the exact accepted-main control revision, not from candidate bytes, before evaluating candidate SARIF.
- Missing SARIF, malformed/duplicate-key JSON, unexpected scanner identity, symlink substitution, oversized evidence, or any finding fails closed.
- Post-merge CodeQL remains validation/closure evidence; it is not a substitute for the pre-merge zero-findings barrier.

This separation prevents a green CodeQL workflow conclusion from being misinterpreted as a clean security result.

[← Supply chain](SUPPLY_CHAIN.md) · [Release candidate](RELEASE_CANDIDATE.md) · [Trusted PR control plane →](TRUSTED_PR_CONTROL_PLANE.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
