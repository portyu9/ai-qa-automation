# CI/CD and Repository Governance

> [!IMPORTANT]
> **Workflow definition, workflow execution, validation subject, evidence admission, status identity, and merge enforcement are separate authorities.** Ordinary pull-request CI is development evidence. Protected merge authority requires a trusted default-branch control path, exact live PR/head/base/merge identity, deterministic evidence, terminal live revalidation, and `Trusted PR Gate` publication by the dedicated GitHub App identity required by branch protection. Repository source cannot self-attest the live App installation, Environment protection, Actions Policy, or ruleset binding.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Supply chain](SUPPLY_CHAIN.md) · [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md) · [Operations](OPERATIONS.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Authority split

The repository separates candidate validation, trusted orchestration, evidence admission, terminal reporting, and credentialed/manual workflows:

| Surface | Committed trigger | Repository-owned authority | Intended role |
|---|---|---|---|
| `.github/workflows/ci.yml` | `pull_request`, `push` to `main`, `merge_group`, fixed `repository_dispatch` type `trusted-pr-validation` | validation jobs are read-only and secret-free; owner dispatch can validate an exact prospective merge under the default-branch workflow definition | ordinary development feedback plus the retained full trusted-execution maintenance path |
| `.github/workflows/trusted-pr-auto.yml` | completed reviewed CI through `workflow_run` | default-branch admission is read-only; candidate execution is allowed only after exact live identity and zero protected-object drift | routine protected validation for eligible source-only changes |
| `.github/workflows/trusted-pr-evidence.yml` | owner `repository_dispatch` type `trusted-pr-evidence-authorization` | native token is read-only; candidate bytes are never executed by this workflow | protected-maintenance fallback that promotes only exact successful ordinary PR CI after independent evidence admission |
| trusted reporter jobs | only after the corresponding trusted admission succeeds | reporter enters Environment `trusted-pr-gate`, revalidates, then mints a narrowly scoped dedicated GitHub App installation token | terminal `Trusted PR Gate` publication |
| `.github/workflows/manual-validation.yml` | `workflow_dispatch` only | model step uses the `credentialed-validation` environment; provider credential is step-scoped | optional H-series/model evidence; never protected merge authority |

Persisted checkout credentials are disabled in trusted paths. Automatic validation is secret-free. Dependency caching is forbidden where it could precede reviewed lock/build authority.

Ordinary `pull_request` execution is useful but cannot certify merge by itself. A pull request controls candidate workflow and repository bytes, so green ordinary CI is **in-subject validation evidence**, not an independent trust root. The protected status identity is separated from native GitHub Actions: candidate execution never receives the GitHub App private key and cannot satisfy the required App-bound status merely by creating a same-named context.

---

## Validation subject selection

`ci.yml` defines one explicit validation subject:

```text
CI_SUBJECT_SHA = repository_dispatch ? client_payload.expected_merge_sha : github.sha
```

For ordinary GitHub events, `github.sha` is the event subject. For the retained `trusted-pr-validation` dispatch, the prospective merge SHA is untrusted subject data: it selects what read-only validation inspects, but it does not select reporter code, grant credential access, or authorize status publication.

Each deterministic validation domain checks out the selected subject with persisted credentials disabled and requires `git rev-parse HEAD == CI_SUBJECT_SHA` before project execution. Wheel archives, build-manifest source identity, SBOM lineage, and runtime-container context bind to that same exact subject.

The evidence-authorization workflow is intentionally different: it checks out only trusted default-branch bytes and **never checks out or executes candidate bytes**. It reasons over GitHub metadata, exact Git objects, ordinary CI job results, and persisted supply-chain evidence.

---

## Routine automatic trusted path

For a completed successful ordinary `pull_request` CI run, `trusted-pr-auto.yml` may wake from `workflow_run`. The wake-up payload is not authorization. Default-branch admission re-fetches the triggering run, current `main`, the live PR, the live prospective merge, ordered merge parents, and protected Git objects.

Automatic admission requires the exact reviewed CI identity, a same-repository owner PR targeting current `main`, exact head/base/merge identity, and **zero protected authority-root drift**. Any API failure, ambiguity, fork, stale base, malformed or truncated response, parent mismatch, or protected-object change fails closed.

Before candidate scripts run, trusted YAML independently verifies the prospective merge and protected-object guard. Validation remains read-only and secret-free. The reporter later re-runs admission from trusted default-branch bytes before it may mint the dedicated App token.

This path is for routine changes only. It must not auto-authorize a PR that changes its own workflow, tests, verifier, dependency/build authority, or other protected control-plane roots.

---

## Protected-maintenance paths

Protected changes require explicit owner authorization bound to the exact PR/head/base/prospective-merge tuple and exact protected-object transitions. Two reviewed maintenance mechanisms exist because they prove different things.

### Full trusted execution: `trusted-pr-validation`

The retained `ci.yml` owner dispatch executes deterministic validation against the prospective merge subject while the workflow definition itself comes from trusted `main`. Before repository scripts execute, the Supply Chain job requires:

- exact expected merge/head/base identity;
- `GITHUB_SHA == expected_base_sha`;
- exactly two ordered merge parents `(base, head)`;
- an exact bounded protected-root object manifest equal to the complete observed change set.

This path is appropriate when the trusted base workflow can execute the candidate's dependency/runtime contract without definition drift.

### Exact ordinary-CI evidence promotion: `trusted-pr-evidence-authorization`

Some legitimate control-plane transitions intentionally change the CI matrix or dependency authority itself. Re-executing the candidate under the old default-branch workflow graph can then fail for **definition drift** even when the candidate's own exact-subject ordinary CI already passed. The evidence-authorization workflow closes that transition class without granting candidate code privileged authority.

It runs only from the default branch on owner `repository_dispatch` and uses only `actions: read`, `contents: read`, and `pull-requests: read` native authority. It:

1. resolves the live PR and exact expected head/base/prospective merge;
2. requires the merge commit to have exactly ordered parents `(base, head)`;
3. compares the owner-supplied protected manifest with the complete live base/merge protected-object changes;
4. verifies the candidate `ci.yml` remains bound to `github.sha` for ordinary PR execution and still has the deterministic Required PR Gate;
5. selects a completed successful ordinary `pull_request` CI run bound to the exact PR/head/base identity;
6. requires successful supply-chain/CI-contract proof, exactly two successful quality lanes, security, browser, deterministic evals, and the deterministic Required PR Gate;
7. requires exactly one unexpired `supply-chain-evidence` artifact bound to that selected run;
8. verifies trusted artifact metadata, bounded ZIP structure, and digest-verified bytes;
9. requires `build-manifest.json` to record the exact authorized prospective merge SHA and a clean tracked worktree;
10. re-resolves the live subject after evidence admission;
11. repeats the entire evidence admission in the reporter before App-token minting; and
12. only then invokes the canonical live subject reporter with the dedicated App token.

The storage download never receives the GitHub API authorization header. Artifact and ZIP ingestion are bounded and reject unsafe entries, malformed identity, stale runs, wrong run/head binding, missing digest, or merge-manifest drift.

A green ordinary PR run is therefore still not self-authorizing. The owner dispatch, trusted default-branch evidence verifier, exact protected-object manifest, independently admitted GitHub job/artifact evidence, final revalidation, App identity, and strict branch protection remain separate authorities.

### Exact protected-object manifest

Both explicit maintenance paths bind authorization to exact protected-root transitions. Each supplied entry contains exactly:

```text
path
base_oid
subject_oid
```

The bounded manifest rejects unknown paths, duplicates, malformed object IDs, omitted changes, extra changes, or stale object identities. Missing paths use only the explicit `MISSING` sentinel. An empty manifest authorizes no protected-root change.

A manifest is owner authorization for exact object transitions. It is **not** proof that changed bytes are correct; exact-revision CI, adversarial review, artifact verification, and terminal subject revalidation remain required.

---

## Trusted reporter and independent status identity

Every terminal trusted reporter is a separate authority domain. Candidate validation and evidence admission keep native GitHub Actions authority read-only. The App client ID/private key is consumed only inside Environment `trusted-pr-gate`, after deterministic admission has succeeded and immediately before status publication.

The reporter mints a short-lived installation token requesting only repository contents read, pull requests read, and commit statuses write. `scripts/trusted_pr_control.py` revalidates the live open PR, exact head/base, live `refs/pull/<number>/merge`, merge type, and ordered parents. It repeats the live subject read immediately before publication to narrow the final TOCTOU window.

The dedicated App identity matters because `Protect Main` must bind `Trusted PR Gate` to that integration, not merely to the context string. A candidate workflow can create a same-named status, but it cannot satisfy an integration-bound required check unless it owns the dedicated App identity—which candidate jobs do not receive.

---

## Environment-owned activation requirements

Repository source defines the intended boundary but cannot prove the corresponding platform configuration is active. External observation must establish:

- the dedicated GitHub App exists and is installed only where intended;
- its installation permissions are no broader than required;
- Environment `trusted-pr-gate` exists and prevents candidate/feature refs from receiving its credentials;
- `TRUSTED_GATE_APP_CLIENT_ID` and `TRUSTED_GATE_APP_PRIVATE_KEY` identify the intended App and remain environment-owned;
- the repository ruleset requires `Trusted PR Gate` from that App integration;
- required-status semantics remain strict/up-to-date;
- no bypass actor silently circumvents the protected status; and
- Actions Policy admits only the intended ordinary feedback and trusted orchestration events.

Repository source cannot convert an unobserved environment fact into PASS.

---

## Deterministic validation domains

The ordinary/full trusted validation domains are:

- exact CPython 3.11.16 full-quality validation plus exact CPython 3.14.7 deterministic compatibility validation; Python 3.11 owns compile, Ruff, strict Mypy, full deterministic pytest, and coverage, while Python 3.14 runs compile plus the full deterministic compatibility pytest suite without duplicating lint/type/coverage authority;
- the fixed 34-case deterministic control evaluation;
- supply-chain, build-authority, documentation, Mermaid, runtime SBOM, reproducible-wheel, and container validation;
- Bandit, hash-locked dependency audit, and secret scanning; and
- deterministic Playwright reference-SUT validation against hosted Chrome.

Before automatic hash-locked dependency installation, `scripts/verify_build_authority.py` validates the reviewed lock-file set and bytes through bounded descriptor-relative no-follow ingestion. Dependency and project installs remain bracketed by build-authority checks.

Automatic browser validation does not install browsers or OS packages. It requires hosted `/usr/bin/google-chrome`, records its version, and runs only the deterministic localhost reference SUT. The hosted browser remains an environment input rather than a cryptographically attested repository asset.

`Required PR Gate` uses `if: ${{ always() }}` and succeeds only when every required validation dependency succeeded. It is deterministic aggregate evidence, never protected merge authority by itself.

---

## Exact workflow-definition verifier

Run:

```bash
python scripts/verify_ci_contract.py
```

The verifier fails closed unless the reviewed repository authority model remains intact. Among other invariants it requires:

- exactly the four reviewed workflow files: `ci.yml`, `manual-validation.yml`, `trusted-pr-auto.yml`, and `trusted-pr-evidence.yml`;
- complete reviewed Git-blob identities for the automatic workflow, trusted-auto workflow, trusted-auto verifier extension, trusted-evidence workflow, and trusted-evidence verifier script;
- bounded no-follow workflow ingestion;
- fixed ordinary, full trusted-dispatch, automatic `workflow_run`, manual, and evidence-authorization trigger contracts;
- no `pull_request_target`;
- read-only native authority before terminal App-token minting;
- no validation-domain secret use or write permissions;
- exact protected-manifest comparison structure;
- immutable reviewed Action SHAs and exact Python patch versions;
- the exact Python 3.11 full-quality / Python 3.14 compatibility lane split;
- merge-subject checkout binding and Mermaid subject binding in trusted execution;
- routine automatic zero-protected-drift admission;
- evidence-authorization candidate-nonexecution and reporter ordering;
- reviewed dependency/project-install authority brackets; and
- supply-chain, SBOM, reproducible-wheel, container-context, documentation, Mermaid, evidence-upload, and deterministic aggregate controls.

This is source self-consistency evidence. It cannot attest live GitHub administrative state.

---

## Historical activation evidence

Historical green from an older control plane proves only that older revision and identity arrangement. For example, probe PR #50 used the then-active GitHub Actions status identity and Python 3.13-era matrix. Those observations remain historical evidence and must not be presented as proof of the current dedicated-App, automatic-admission, evidence-authorization, Python 3.14, Environment, Actions Policy, or ruleset state.

Similarly, a successful bootstrap or transition run proves the exact revision it executed; newer source requires newer evidence.

---

## Normal operation

### Ordinary development feedback

1. `pull_request` starts ordinary CI.
2. The exact GitHub event subject runs under read-only, secret-free validation authority.
3. `Required PR Gate` may summarize deterministic validation.
4. This green is development evidence only.

### Routine protected validation

For an eligible same-repository PR with no protected-root drift, a successful ordinary run may wake `trusted-pr-auto.yml`. Default-branch admission re-resolves the exact subject, trusted YAML rechecks protected authority before candidate execution, all trusted validation domains must pass, admission is repeated, the App token is minted only at the end, and the App-backed reporter publishes only after final live subject revalidation.

### Protected maintenance

For a protected change:

1. read the current PR/head/base/live prospective merge;
2. verify exactly ordered merge parents;
3. derive the exact protected-root object manifest;
4. complete ordinary exact-head CI and adversarial review;
5. choose the reviewed owner maintenance path that fits the transition:
   - `trusted-pr-validation` when default-branch full trusted execution can validly execute the candidate; or
   - `trusted-pr-evidence-authorization` when a workflow/dependency authority transition would make the old trusted graph definition-stale;
6. require the corresponding trusted admission and reporter to succeed;
7. independently read `Trusted PR Gate: success` from the App integration required by the live ruleset;
8. re-read head/base/merge, ruleset, and review-thread state immediately before merge; and
9. merge only the exact validated head with the configured protected merge method.

Any head/base/merge-subject change invalidates earlier admission. No historical automatic green, artifact, or trusted status certifies newer bytes.

---

## Manual-only validation

`manual-validation.yml` remains `workflow_dispatch`-only and outside protected merge evidence. Repository-visible H-series readiness and credentialed Claude Agent SDK smoke evidence are separate evidence classes. Missing credentials, provider outage, Environment approval failure, or other external limitations remain blocked/unavailable rather than automatic PASS.

---

## Merge-enforcement invariant

The protected-branch contract is:

- pull requests required for `main`;
- strict/up-to-date required-status semantics;
- review-thread resolution and configured merge-method restrictions preserved;
- no persistent bypass actor; and
- `Trusted PR Gate` required from the intended dedicated GitHub App integration.

Strict/up-to-date enforcement is essential because a base update can change the prospective merge while leaving the PR head SHA unchanged. Re-fetch the ruleset and exact PR subject immediately before merge.

---

## Secrets and privileged authority

Automatic validation and trusted admission jobs remain read-only and do not own terminal status-write permission. Candidate execution never receives the reporter App private key. Commit-status write authority belongs to the short-lived dedicated App installation token, whose credential material is released only through Environment `trusted-pr-gate` after admission revalidation.

This control plane does not add package publishing, registry publication, deployment, production mutation, signing keys, or destructive infrastructure authority.

---

## Evidence semantics

A green ordinary PR run proves only the candidate's deterministic checks for that exact ordinary event subject.

A green full trusted-dispatch run proves the exact prospective merge passed the executed trusted deterministic gates only when its default-branch preflight admitted the exact tuple and manifest.

A green automatic trusted run proves the exact prospective merge passed the automatic gate only when zero-protected-drift admission and terminal revalidation remained identical.

A green evidence-authorization run proves the trusted default-branch verifier admitted exact successful ordinary CI, exact protected-object transitions, and digest-verified persisted build-manifest evidence for the authorized merge without executing candidate bytes under privileged authority.

None of those is terminal merge authority unless `Trusted PR Gate` was published by the dedicated App integration required by the live strict ruleset and the PR subject remains current.

Blocked, failed, missing, stale, historical-only, wrong-integration, or unobserved evidence remains non-PASS truth.

---

[← Supply chain](SUPPLY_CHAIN.md) · [Trusted PR control plane →](TRUSTED_PR_CONTROL_PLANE.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
