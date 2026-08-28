# Trusted PR control-plane prototype

This document describes a **non-authoritative prototype** for closing the external workflow-provenance boundary identified during Phase 4 hardening. The prototype must not be interpreted as merge authority until the trusted workflow definition is bootstrapped onto the default branch, the required external GitHub repository policy is active and observed, the trusted path is exercised against an exact pull-request subject, and merge enforcement is revalidated against that trusted status.

## Problem

A required status check produced by a normal `pull_request` workflow is not an independent trust root when the pull request can edit that workflow or its repository-local verifier. A stable check name does not make the workflow bytes that emitted it immutable. Repository-local self-verification can strongly reject accidental drift while still remaining inside the same PR-controlled trust domain.

## Implemented dormant authority model

The prototype separates read-only validation from terminal merge-status authority:

1. Normal `pull_request`, `push`, and `merge_group` executions keep the existing non-privileged validation path. Their five validation jobs select `CI_SUBJECT_SHA = github.sha`, disable persisted checkout credentials, and have no status-write authority.
2. The same reviewed `ci.yml` also declares one fixed `repository_dispatch` event type: `trusted-pr-validation`.
3. GitHub's `repository_dispatch` semantics select the workflow definition from the repository default branch. The dispatch payload carries the pull-request number plus expected head/base/prospective-merge SHAs only as untrusted data; `expected_merge_sha` becomes `CI_SUBJECT_SHA` for the read-only validation jobs.
4. Validation jobs execute that exact supplied prospective merge subject with read-only repository authority, no repository secrets, no status/check write permission, no deployment authority, and no dependency cache.
5. `Required PR Gate` remains the deterministic aggregate of the five validation domains. It does not itself become trusted merge authority merely because the same aggregate also feeds the reporter.
6. The separate `Trusted PR Gate Reporter` job is eligible only for `repository_dispatch`, `refs/heads/main`, and `github.actor == github.repository_owner`. It owns the workflow's sole `statuses: write` permission and sole GitHub Actions token consumer.
7. The reporter checks out and verifies the trusted workflow revision at `github.sha`, then passes the dispatch payload to `scripts/trusted_pr_control.py`.
8. The helper refuses any non-`repository_dispatch` event, non-`refs/heads/main` ref, or non-owner actor before GitHub API access. It then re-fetches the pull request, requires it to remain open, target `main`, and be definitively mergeable, and requires the live head/base/prospective-merge identities to exactly equal the dispatched subject.
9. Diagnostic dispatches never publish merge authority. An authorized successful validation publishes `Trusted PR Gate` to the exact current pull-request head. An authorized non-success publishes failure and makes the reporter job exit nonzero.
10. A later pull-request update changes the head and prospective merge subject, so earlier exact-subject evidence/status cannot certify the newer revision.

The repository owner/admin account remains an external administrative trust root because that identity can change repository policy itself. No second-person approval ceremony is introduced.

## Why `repository_dispatch`, not `workflow_dispatch`

The trusted path deliberately avoids a manual `workflow_dispatch` branch selector. A trusted job must not rely on an operator merely choosing `main`, because a selected feature ref could also select feature-controlled workflow bytes. `repository_dispatch` is used instead because GitHub resolves that event against the default-branch workflow definition; the prospective merge SHA is passed as data and is never treated as the authority for the reporter implementation.

The in-workflow `github.ref == 'refs/heads/main'` and owner checks remain defense-in-depth conditions. The primary workflow-definition trust property comes from the default-branch event semantics plus the later external policy/bootstrap requirements, not from a condition that PR-editable workflow bytes could otherwise rewrite.

## Bootstrap and external-policy requirement

This architecture is deliberately **dormant on this draft branch**. `repository_dispatch` can provide trusted workflow-definition provenance only after the reviewed definition exists on the repository default branch. This PR therefore cannot use its own new reporter as evidence for itself.

Finding 13 also remains blocked until an independently controlled GitHub repository Actions Policy, or an equivalently strong external control, prevents ordinary PR-editable `pull_request` workflow code from acting as merge authority. The intended activation sequence is:

1. fully audit and validate this repository source as ordinary in-subject evidence;
2. bootstrap the reviewed trusted workflow/helper/verifier definition onto `main` through an explicitly audited revision;
3. configure and externally verify repository Actions Policy so ordinary `pull_request` workflow execution cannot supply the protected merge-authority status;
4. issue the fixed `trusted-pr-validation` `repository_dispatch` for an exact current PR subject through an authenticated repository-administration path;
5. inspect that run, its exact validation subject, reporter subject revalidation, terminal status, and artifacts;
6. only then change and re-fetch merge enforcement so `Trusted PR Gate`, rather than PR-editable `Required PR Gate`, is the protected merge authority.

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

`scripts/verify_ci_contract.py` independently freezes the complete `ci.yml` bytes to the reviewed Git blob identity and structurally requires the fixed `repository_dispatch` event type, `CI_SUBJECT_SHA` selector, five read-only validation checkouts, sole trusted `github.sha` reporter checkout, sole `statuses: write` permission, sole GitHub Actions token consumer, owner/default-branch reporter condition, exact client-payload arguments, cache denial, and the existing build/SBOM/container/evidence authority contracts.

Adversarial tests cover event/ref/owner denial, stale or ambiguous PR subjects, diagnostic no-status behavior, terminal success/failure reporting, exact target URLs, nonzero failure exit, replacement of `repository_dispatch` with `workflow_dispatch`, arbitrary repository-dispatch event types, client-payload subject bypass, additional token consumers, missing owner/main guards, unbound validation/reporter checkouts, and automatic/manual dependency-cache reintroduction.

## Evidence semantics

A green ordinary `pull_request` run of this draft proves only that the prototype source, verifier, tests, security gates, build evidence, and documentation are self-consistent for the exact PR event subject under the **existing** control plane. It does not prove that the new default-branch trusted workflow executed, that external Actions Policy is active, that `Trusted PR Gate` is a protected required status, or that this PR is merge-authorized.

Until those external/bootstrap steps are completed and observed, finding 13 remains blocked and PR #45 must remain a non-authoritative draft prototype.
