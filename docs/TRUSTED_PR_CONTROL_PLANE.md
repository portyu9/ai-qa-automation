# Trusted PR control plane

This document defines trusted pull-request validation and terminal merge-status authority for **ƳƤ AI QA Automation Framework**. The design separates automatic development feedback from the identity allowed to authorize merge.

Repository source defines the control-plane contract. GitHub App installation state, Environment protection, Actions Policy, and branch-ruleset configuration are external authorities and must be observed independently. Source must not report those controls as active merely because the workflow is designed to use them.

## Threat model

A stable check name is not a trust boundary when candidate-controlled workflow bytes can execute under the same integration identity that owns the required status. A same-repository pull request can change workflow YAML, including requested `GITHUB_TOKEN` permissions. Therefore allowing automatic `pull_request` CI is safe for merge governance only when its GitHub Actions identity is **not** the integration identity accepted for `Trusted PR Gate`.

The durable design uses two identities:

- **GitHub Actions** runs automatic, read-only, secret-free validation for development feedback.
- A dedicated **ƳƤ Trusted PR Gate GitHub App** owns the only status identity accepted by the `Protect Main` ruleset for context `Trusted PR Gate`.

A PR-controlled workflow may manufacture another status with the same text, but it cannot satisfy a required-status rule that is bound to the dedicated App integration.

Strict/up-to-date branch enforcement remains required because `Trusted PR Gate` is posted to the PR head while validation also binds the base and prospective merge object. Base drift must invalidate the previous merge subject.

## Authority flow

The intended authority chain is:

**PR head/base → exact prospective merge object → trusted default-branch dispatch definition → deterministic validation → live PR/merge-ref revalidation → dedicated App status publication → strict protected-branch enforcement**

The roles are separated deliberately:

1. Automatic `pull_request` CI may remain enabled continuously. It executes candidate-selected validation bytes and is development evidence only.
2. Owner-authorized `repository_dispatch` selects `ci.yml` from the default branch. Payload values are untrusted data, not authority.
3. `CI_SUBJECT_SHA` is the supplied prospective merge SHA for trusted dispatch and GitHub's event SHA for ordinary automatic execution.
4. The five validation domains check out that exact subject with persisted credentials disabled and verify the checkout revision before execution.
5. Validation jobs remain read-only and secret-free. They do not receive the trusted App private key and cannot publish through the dedicated App.
6. `Required PR Gate` deterministically aggregates the validation domains. It is evidence, not protected merge authority.
7. `Trusted PR Gate Reporter` is eligible only for owner `repository_dispatch` on `refs/heads/main` and references Environment `trusted-pr-gate`.
8. That Environment supplies `TRUSTED_GATE_APP_CLIENT_ID` and `TRUSTED_GATE_APP_PRIVATE_KEY`. The workflow mints a short-lived installation token restricted to the repository with `contents: read`, `pull_requests: read`, and `statuses: write`.
9. The GitHub Actions job token itself remains `contents: read`; it has no `statuses: write` authority.
10. `scripts/trusted_pr_control.py` revalidates the live open PR, exact head/base, `refs/pull/<number>/merge`, and ordered merge parents, then repeats the live reads immediately before publication.
11. Only an authorized successful aggregate may publish `Trusted PR Gate: success` using the dedicated App token. An authorized non-success publishes failure and exits nonzero. Diagnostic runs do not publish status.
12. `Protect Main` must require `Trusted PR Gate` from the dedicated App integration with strict/up-to-date semantics and no bypass.

Model output has no role in this authorization path.

## Protected-path maintenance manifest

Normal trusted validation does not need to mutate or trust new control-plane bytes. A maintenance PR, however, may legitimately change tests, workflows, build configuration, verification scripts, or other authority-bearing paths. Blanket rejection of every such change creates a maintenance deadlock.

The trusted dispatch preflight therefore uses an **exact protected-object manifest** rather than silently accepting or blanket-denying protected changes.

The protected roots are fixed in the trusted default-branch workflow. For each protected root, the preflight observes the Git object ID at the trusted base and at the prospective merge subject. Missing paths are represented only by the literal `MISSING` sentinel.

`client_payload.protected_manifest` must be a bounded JSON array. Every entry must contain exactly:

```json
{"path":"tests","base_oid":"<40-hex-or-MISSING>","subject_oid":"<40-hex-or-MISSING>"}
```

The workflow rejects the dispatch unless the normalized supplied manifest equals the complete observed set of protected-root changes exactly. Unknown paths, duplicates, malformed object IDs, omitted changes, extra changes, or stale object IDs fail closed.

An empty manifest therefore means **no protected-root changes are authorized**. A non-empty manifest is an explicit owner authorization for exactly those object transitions. It is not independent proof that changed tests or control-plane code are correct; the candidate still requires full validation and adversarial review.

## Trusted App and Environment contract

The dedicated GitHub App should be installed only on `ai-qa-automation` and granted only:

- Contents: read-only;
- Pull requests: read-only;
- Commit statuses: read and write;
- all other repository and organization permissions: no access unless a future reviewed requirement proves otherwise.

No webhook is required for this workflow design.

Environment `trusted-pr-gate` must contain:

- variable `TRUSTED_GATE_APP_CLIENT_ID`;
- secret `TRUSTED_GATE_APP_PRIVATE_KEY`.

The private key must be entered directly in GitHub Environment secrets and must not be pasted into source, issue text, PR text, logs, or chat.

The Environment deployment policy must select **`main` only**. If the repository tier exposes administrator-bypass controls for Environment protection, bypass should be disabled. A `refs/pull/.../merge` workflow must not be eligible to receive this credential.

The workflow mints a short-lived App installation token using hosted `openssl`, `curl`, and Python standard-library JSON parsing. The private key is written only to a mode-restricted runner temporary file, removed before API use continues, and the installation token is masked before being written to `GITHUB_OUTPUT`.

## Actions Policy

After the independent App identity and Environment/ruleset binding are activated, external Actions Policy may allow both:

- `pull_request` for normal automatic development feedback;
- `repository_dispatch` for the owner-authorized trusted path.

The trusted path still requires repository-owner actor admission in the workflow. If the platform policy can additionally restrict `repository_dispatch` to the owner, keep that restriction.

`pull_request` no longer needs to be repeatedly enabled and disabled because GitHub Actions is not the integration accepted for the protected status. Ordinary PR CI can remain permanently available without acquiring terminal merge authority.

`pull_request_target` remains forbidden. Credentialed, destructive, publishing, deployment, load/stress, and other privileged jobs remain manual/environment-protected.

## Merge-enforcement invariant

`Protect Main` must require:

- context: `Trusted PR Gate`;
- expected source/integration: the dedicated ƳƤ Trusted PR Gate GitHub App, **not GitHub Actions**;
- strict/up-to-date required-status semantics;
- no bypass actors;
- pull-request review-thread resolution;
- merge commits as the repository's selected merge method;
- deletion and non-fast-forward protection.

The integration binding is critical. Requiring only the context string would reintroduce status-spoofing ambiguity.

## Validation subject and live revalidation

GitHub's read-only `refs/pull/<number>/merge` ref represents the prospective merge object for the current head/base pair. Trusted dispatch supplies that exact SHA as subject data.

Terminal reporting requires:

- PR remains open and targets `main`;
- current PR number, head SHA, and base SHA equal the dispatched expected values;
- `refs/pull/<number>/merge` exists and points to the expected merge SHA;
- that merge commit has exactly two ordered parents `(base, head)`;
- PR identity and merge ref are fetched again immediately before publication;
- any API failure, malformed response, missing ref, parent mismatch, head/base drift, closed PR, or final-read drift fails closed.

There is no retry after status publication and no generic retry of authorization or schema failures.

## Normal protected-PR operation

For an ordinary PR with no protected-root changes:

1. let automatic `pull_request` CI provide fast development evidence;
2. read current PR number/head/base and live prospective merge SHA;
3. verify merge parents `(base, head)`;
4. issue owner `repository_dispatch` event `trusted-pr-validation` with the exact tuple, `authorized: true`, and `protected_manifest: []`;
5. require every deterministic validation domain and `Required PR Gate` to succeed;
6. require the trusted reporter to mint the dedicated App token and succeed;
7. independently read `Trusted PR Gate: success` from the dedicated App integration on the exact head;
8. re-read PR head/base/merge subject and ruleset binding immediately before merge.

Any subject change requires a new trusted dispatch.

For a maintenance PR that changes protected roots, perform the same procedure but supply the exact observed protected-object manifest. Recompute it after every candidate change or base drift.

## One-time migration bootstrap

Moving from the historical GitHub-Actions-owned `Trusted PR Gate` to the independent App identity is itself a control-plane change. The old trusted dispatch intentionally cannot authorize modified `.github`, `scripts`, `tests`, or equivalent protected roots, so one administrative bootstrap is unavoidable.

The bootstrap must be narrow and auditable:

1. validate the migration PR's exact prospective merge revision with ordinary CI while automatic execution is available;
2. run targeted and full deterministic tests, security/supply-chain checks, and adversarial review on that exact revision;
3. verify the diff contains only the intended authority migration and documentation/tests needed to enforce it;
4. perform the minimum temporary administrative transition needed to merge that exact reviewed revision—never create a persistent bypass;
5. immediately create/configure the dedicated GitHub App and `trusted-pr-gate` Environment;
6. bind `Protect Main` `Trusted PR Gate` to the dedicated App integration, strict/up-to-date, no bypass;
7. exercise a disposable trusted dispatch and independently read the status source/integration;
8. re-fetch Actions Policy, Environment-visible behavior, ruleset, `main` SHA, and trusted workflow bytes;
9. only then treat the independent control plane as activated.

Historical green runs under GitHub Actions integration ID `15368` remain evidence for the **previous** control plane only. They do not prove the dedicated App identity is active.

## Repository controls

`scripts/trusted_pr_control.py` remains standard-library-only and enforces bounded API ingestion, fixed repository/event/ref/owner admission, exact live PR identity, exact merge-ref/parent identity, final live re-read, diagnostic no-status behavior, exact-head status publication, and nonzero exit after authorized validation failure.

`scripts/verify_ci_contract.py` freezes the reviewed workflow bytes and structural authority model, including the main-only Environment reference, absence of native status-write authority, single private-key consumer, exact App-token permission request, and exact protected-manifest comparison. It cannot certify the live GitHub App installation, secret values, Environment branch policy, Actions Policy, or ruleset integration ID.

## Evidence semantics

A green automatic PR run proves the candidate's deterministic gates for that exact GitHub event subject. It is not merge authority.

A green trusted validation aggregate proves the dispatched prospective merge subject passed the deterministic repository gates under the trusted default-branch workflow definition. It is not terminal authority unless the reporter also revalidates the live subject and publishes through the dedicated App.

A `Trusted PR Gate` success is merge-authorizing evidence only when its source is the dedicated App integration currently required by the strict ruleset and the PR subject remains current.

Blocked, failed, missing, stale, wrong-integration, or unobserved evidence is non-PASS truth.

---

[← CI/CD](CI_CD.md) · [Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
