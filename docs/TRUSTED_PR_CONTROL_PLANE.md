# Trusted PR control-plane prototype

This document describes a **non-authoritative prototype** for closing the external workflow-provenance boundary identified during Phase 4 hardening. The prototype must not be interpreted as merge authority until the trusted workflow definition is bootstrapped onto the default branch, the required external GitHub repository policy capability is confirmed and active, the trusted path is exercised against an exact pull-request subject, and strict merge enforcement is revalidated against that trusted status.

## Problem

A required status check produced by a normal repository workflow is not an independent trust root when a pull request can edit workflow bytes that GitHub Actions may execute under the same integration identity. A stable check name does not make the workflow bytes that emitted it immutable. Repository-local self-verification can strongly reject accidental drift while still remaining inside the same PR-controlled trust domain.

This applies to more than the `pull_request` event. Denying only `pull_request` execution is insufficient if another allowed event can execute workflow bytes from a feature/PR-controlled ref. For example, a feature-branch `push` can execute workflow definitions from that branch; PR-controlled workflow code could then attempt to emit the same protected check name under the same GitHub Actions integration. Actor-only protection also does not separate those paths in this single-contributor repository because the repository owner can legitimately be the actor for both trusted administrative actions and feature-branch pushes.

A second external invariant follows from subject binding. The reporter validates the exact PR head, base, and prospective merge SHA, but the terminal status is necessarily published on the PR head commit. If the base branch advances after publication, the old head status must not be accepted for a now-different prospective merge. Trusted activation therefore also requires strict/up-to-date required-status enforcement so base drift forces a new merge subject and revalidation.

## Implemented dormant authority model

The prototype separates read-only validation from terminal merge-status authority:

1. Normal `pull_request`, `push`, and `merge_group` executions keep the existing non-privileged validation path while this prototype is being validated. Their five validation jobs select `CI_SUBJECT_SHA = github.sha`, disable persisted checkout credentials, and have no status-write authority.
2. The same reviewed `ci.yml` also declares one fixed `repository_dispatch` event type: `trusted-pr-validation`.
3. GitHub's `repository_dispatch` semantics select the workflow definition from the repository default branch. The dispatch payload carries the pull-request number plus expected head/base/prospective-merge SHAs only as untrusted data; `expected_merge_sha` becomes `CI_SUBJECT_SHA` for the read-only validation jobs.
4. Validation jobs execute that exact supplied prospective merge subject with read-only repository authority, no repository secrets, no status/check write permission, no deployment authority, and no dependency cache.
5. `Required PR Gate` remains the deterministic aggregate of the five validation domains. It does not itself become trusted merge authority merely because the same aggregate also feeds the reporter.
6. The separate `Trusted PR Gate Reporter` job is eligible only for `repository_dispatch`, `refs/heads/main`, and `github.actor == github.repository_owner`. It owns the workflow's sole `statuses: write` permission and sole GitHub Actions token consumer.
7. The reporter checks out and verifies the trusted workflow revision at `github.sha`, then passes the dispatch payload to `scripts/trusted_pr_control.py`.
8. The helper refuses any non-`repository_dispatch` event, non-`refs/heads/main` ref, or non-owner actor before GitHub API access. It then re-fetches the pull request, requires it to remain open, target `main`, and be definitively mergeable, and requires the live head/base/prospective-merge identities to exactly equal the dispatched subject.
9. Diagnostic dispatches never publish merge authority. An authorized successful validation publishes `Trusted PR Gate` to the exact current pull-request head. An authorized non-success publishes failure and makes the reporter job exit nonzero.
10. A later pull-request head update changes the head and prospective merge subject, so earlier exact-subject evidence/status cannot certify the newer revision. A later base update is handled by the separate required external invariant that merge enforcement remain strict/up-to-date before accepting the head-bound trusted status.

The repository owner/admin account remains an external administrative trust root because that identity can change repository policy itself. No second-person approval ceremony is introduced.

## Why `repository_dispatch`, not `workflow_dispatch`

The trusted path deliberately avoids a manual `workflow_dispatch` branch selector. A trusted job must not rely on an operator merely choosing `main`, because a selected feature ref can select feature-controlled workflow bytes. `repository_dispatch` is used instead because GitHub resolves that event against the default-branch workflow definition; the prospective merge SHA is passed as data and is never treated as the authority for the reporter implementation.

The in-workflow `github.ref == 'refs/heads/main'` and owner checks remain defense-in-depth conditions. The primary workflow-definition trust property comes from the default-branch event semantics plus the external execution-policy/bootstrap requirements, not from a condition that PR-editable workflow bytes could otherwise rewrite.

## Bootstrap and external-policy requirement

This architecture is deliberately **dormant on this draft branch**. `repository_dispatch` can provide trusted workflow-definition provenance only after the reviewed definition exists on the repository default branch. This PR therefore cannot use its own new reporter as evidence for itself.

Finding 13 also remains blocked until an independently controlled GitHub repository Actions Policy, or an equivalently strong external control, prevents **every workflow-execution path whose definition can come from a PR/feature-controlled ref** from supplying the protected GitHub Actions check identity. Denying `pull_request` alone is not sufficient.

GitHub currently documents workflow-execution protections as a public-preview capability with event and actor rules. The published documentation gives event examples but does not explicitly guarantee that `repository_dispatch` is selectable as an event-rule allow-list entry. Repository source therefore treats `repository_dispatch` policy support as an **unverified platform capability**, not an implemented fact. Activation must observe the actual repository policy surface and prove that the intended trusted event can be allowed while competing feature-ref-defined events are denied. If that capability is unavailable, this prototype must remain dormant and finding 13 requires a different independently trusted integration/check provider rather than a weaker policy assumption.

If the required platform capability exists, the intended active-policy invariant while `Trusted PR Gate` is protected is:

- allow only the fixed `repository_dispatch` trusted-control event class, whose workflow definition is selected from the default branch;
- deny `pull_request` workflow execution;
- deny feature/ref-defined `push` workflow execution rather than relying on actor identity;
- deny `merge_group` and ref-selectable `workflow_dispatch` execution under the same protected GitHub Actions identity; and
- deny any future event class that can select workflow bytes from a PR/feature-controlled revision unless an independently enforced platform rule proves equivalent default-branch workflow-definition provenance.

This is deliberately stronger than an event-specific `pull_request` deny. Under the intended active policy, ordinary automatic PR CI and the repository's current manual `workflow_dispatch` path become unavailable as GitHub Actions execution paths while `Trusted PR Gate` is the protected same-integration authority. Their current purpose is pre-activation repository validation evidence. Retaining those paths after activation would require a separately trusted integration/identity or an independently enforced mechanism that prevents their workflow definitions from being feature-ref controlled.

## Merge-enforcement invariant

`Trusted PR Gate` is posted to the exact current PR head only after exact head/base/prospective-merge revalidation. That status is safe merge evidence only while branch policy also requires the PR to be up to date with the protected base.

The current `Protect Main` ruleset has strict required-status checks enabled, but that observation does not prove the future transition will preserve the setting. Activation must therefore re-fetch the ruleset after replacing the protected context and require all of the following together:

- `Trusted PR Gate` is the required status from the intended trusted integration identity;
- strict/up-to-date required-status enforcement remains enabled;
- the previous PR-editable `Required PR Gate` is no longer accepted as protected merge authority; and
- no bypass configuration silently defeats the intended protected-branch contract.

Without strict/up-to-date enforcement, a base-branch change after status publication could change the prospective merge subject without changing the head SHA that carries the old success. That state is not acceptable trusted evidence.

## Activation sequence

The intended activation sequence is:

1. fully audit and validate this repository source as ordinary in-subject evidence;
2. bootstrap the reviewed trusted workflow/helper/verifier definition onto `main` through an explicitly audited revision;
3. inspect the actual GitHub Actions Policy surface and confirm it can enforce the required trusted event allow-list, including `repository_dispatch`; if not, stop activation and use a different independent trust mechanism;
4. configure and externally verify repository Actions Policy so the protected GitHub Actions identity is executable only through the default-branch-definition trusted path described above, not merely by denying `pull_request`;
5. issue the fixed `trusted-pr-validation` `repository_dispatch` for an exact current PR subject through an authenticated repository-administration path;
6. inspect that run, its exact validation subject, reporter subject revalidation, terminal status, and artifacts;
7. change merge enforcement to require `Trusted PR Gate`, preserve strict/up-to-date required-status semantics, remove the PR-editable protected context, and re-fetch the resulting ruleset before treating the transition as complete.

The currently connected GitHub tooling does not expose Actions Policy inspection/mutation or a `repository_dispatch` write action. Those prerequisites and the live trusted dispatch therefore remain environment-owned boundaries; repository code must not represent them as completed.

## Cache boundary

Trusted and credentialed workflows must not restore dependency caches that untrusted pull-request execution could poison. `setup-python` pip caching is absent from both automatic and manual validation, and `scripts/verify_ci_contract.py` rejects cache configuration in either workflow. Regression tests mutate both definitions and require deterministic rejection.

## Implemented repository controls

`scripts/trusted_pr_control.py` is standard-library-only and implements:

- fixed `repository_dispatch`/`refs/heads/main`/repository-owner admission before API access;
- bounded GitHub API response ingestion;
- fresh GitHub API resolution of the current open, `main`-targeting, definitively mergeable pull-request subject;
- exact head/base/prospective-merge subject revalidation before terminal reporting;
- diagnostic runs that never publish merge authority;
- exact-current-head `Trusted PR Gate` status publication for authorized success or failure;
- exact repository Actions-run target-URL validation; and
- nonzero reporter termination after an authorized validation failure.

`scripts/verify_ci_contract.py` independently freezes the complete `ci.yml` bytes to the reviewed Git blob identity and structurally requires the fixed `repository_dispatch` event type, `CI_SUBJECT_SHA` selector, five read-only validation checkouts, sole trusted `github.sha` reporter checkout, sole `statuses: write` permission, sole GitHub Actions token consumer, owner/default-branch reporter condition, exact client-payload arguments, cache denial, and the existing build/SBOM/container/evidence authority contracts. Its machine-readable limitations also record that default-branch-definition-only external execution policy, actual `repository_dispatch` policy support, and strict/up-to-date merge enforcement remain external prerequisites.

Adversarial tests cover event/ref/owner denial, stale or ambiguous PR subjects, diagnostic no-status behavior, terminal success/failure reporting, exact target URLs, nonzero failure exit, replacement of `repository_dispatch` with `workflow_dispatch`, arbitrary repository-dispatch event types, client-payload subject bypass, additional token consumers, missing owner/main guards, unbound validation/reporter checkouts, automatic/manual dependency-cache reintroduction, and the external-policy/merge-enforcement evidence contract.

## Evidence semantics

A green ordinary `pull_request` run of this draft proves only that the prototype source, verifier, tests, security gates, build evidence, and documentation are self-consistent for the exact PR event subject under the **existing pre-activation control plane**. It does not prove that the new default-branch trusted workflow executed, that GitHub Actions Policy supports or enforces the required trusted event allow-list, that strict `Trusted PR Gate` merge enforcement is active, or that this PR is merge-authorized.

Until those external/bootstrap steps are completed and observed, finding 13 remains blocked and PR #45 must remain a non-authoritative draft prototype.
