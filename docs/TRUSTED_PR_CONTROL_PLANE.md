# Trusted PR control plane

This document defines the trusted pull-request validation and terminal-status authority for **ƳƤ AI QA Automation Framework**. The design exists to prevent pull-request-controlled GitHub Actions workflow bytes from manufacturing the same protected check identity that authorizes merge.

The control plane is partially activated but **not yet merge-authoritative**. The reviewed trusted workflow is on `main`, the repository Actions Policy capability has been observed live, and the policy is active with `repository_dispatch` as the sole allowed event for the protected GitHub Actions identity. A live trusted dispatch exposed a reporter API-shape defect; the current remediation binds terminal reporting to GitHub's pull-request merge ref instead of the intermittently omitted `merge_commit_sha` field. `Protect Main` still requires `Required PR Gate`, so finding 13 remains open until a successful exact-subject trusted run is observed and the ruleset is transitioned and revalidated.

## Threat model

A stable check name is not an independent trust root when a pull request can cause feature-controlled workflow definitions to execute under the same GitHub Actions integration. Denying only `pull_request` is insufficient because `push`, `merge_group`, ref-selectable `workflow_dispatch`, or a future event could otherwise execute feature-ref workflow bytes under that same identity.

The required external invariant is therefore **default-branch-definition-only execution for the protected identity**. In the activated repository policy, only the fixed `repository_dispatch` path is allowed and the actor is restricted to the repository owner. Ordinary pull-request workflow execution has been observed failing at workflow startup with zero jobs while owner `repository_dispatch` execution succeeds in starting from the default-branch workflow definition.

A separate invariant is required for base drift. `Trusted PR Gate` is posted to the PR head commit, while the validated subject also includes the base and simulated merge result. Protected-branch enforcement must remain strict/up-to-date so a later base change cannot reuse a status created for an older prospective merge.

## Authority flow

The intended runtime authority chain is:

**exact PR subject → default-branch trusted workflow → read-only validation → deterministic aggregate → live PR/merge-ref revalidation → `Trusted PR Gate` status → strict protected-branch enforcement**

The individual authorities are intentionally separated:

1. `repository_dispatch` selects the workflow definition from the default branch. The payload carries PR number, expected head SHA, expected base SHA, expected simulated-merge SHA, and an explicit authorization boolean as untrusted data.
2. The five validation domains set `CI_SUBJECT_SHA` to the supplied expected merge SHA, check out that exact object with persisted credentials disabled, and verify the checkout revision before execution.
3. The trusted subject preflight verifies that the supplied merge commit has the expected base/head parents and that protected control-plane paths match the trusted default-branch revision before repository scripts execute.
4. The validation jobs remain read-only and secret-free. They cannot publish terminal merge authority.
5. `Required PR Gate` deterministically aggregates the five validation domains. It is validation evidence, not the intended terminal trust root.
6. `Trusted PR Gate Reporter` runs only for `repository_dispatch`, `refs/heads/main`, and repository-owner actor. It is the workflow's sole `statuses: write` authority and sole GitHub Actions token consumer.
7. The reporter checks out and verifies the trusted `github.sha` default-branch revision before invoking `scripts/trusted_pr_control.py`.
8. The helper admits only the fixed trusted event/ref/actor tuple before GitHub API access.
9. Before any status write, the helper revalidates the live open PR number/head/base identity, GitHub's exact `refs/pull/<number>/merge` ref, the merge commit's exact two parents `(base, head)`, then re-fetches both PR identity and merge ref to narrow the final TOCTOU window.
10. Only an authorized successful aggregate publishes `Trusted PR Gate: success` to the exact PR head. An authorized non-success publishes failure and the reporter exits nonzero. Diagnostic dispatches never publish status.

Model output has no role in this authorization path.

## Why the merge ref is authoritative

GitHub creates a temporary read-only `refs/pull/<PR>/merge` reference when a pull request can be simulated as a merge. GitHub documents that this ref represents what the repository would look like if the pull request were merged at that time and that it updates when the head or base changes.

Live activation runs showed that `GET /repos/{owner}/{repo}/pulls/{number}` can omit `merge_commit_sha` entirely when called by the workflow token, even while the pull request merge ref exists at the expected SHA. Treating that intermittently shaped response field as required terminal authority caused the reporter to fail closed after all validation domains passed.

The remediation therefore does **not** relax subject binding. It replaces the unstable field dependency with stronger Git-object evidence:

- the live PR must remain open, target `main`, and have the exact expected head/base identity;
- `refs/pull/<number>/merge` must exist, be exactly named, point to a commit, and equal the dispatched expected merge SHA;
- the Git commit object at that merge SHA must have exactly two parents in order: expected base then expected head;
- PR identity and merge ref are fetched again before the status write;
- any API failure, missing/malformed object, mismatched SHA/ref/type/parent, closed PR, base/head drift, or second-read drift fails closed with no status.

There is no retry after a status write and no generic retry of authorization/schema failures.

## External Actions Policy

The repository Actions Policy capability has been observed live. The active policy is intended to remain:

- enforcement: active;
- allowed actor: repository owner only;
- allowed event: `repository_dispatch` only;
- `pull_request`: denied;
- feature/ref-defined `push`: denied;
- `merge_group`: denied;
- ref-selectable `workflow_dispatch`: denied;
- future feature-ref-defined event classes: denied unless an independently enforced mechanism proves equivalent default-branch workflow-definition provenance.

Live disposable probe PRs demonstrated that ordinary `pull_request` runs are rejected at startup while the trusted `repository_dispatch` path starts from `main`. This is external runtime evidence; repository code and `verify_ci_contract.py` cannot independently attest the current GitHub policy UI/configuration.

## Merge-enforcement invariant

The current `Protect Main` ruleset still requires `Required PR Gate` and has strict/up-to-date required-status enforcement with no bypass actors. That is deliberately unchanged during reporter remediation.

The final transition is permitted only after a successful trusted dispatch publishes a verified `Trusted PR Gate` status on the exact current PR head. The transition must then:

- require `Trusted PR Gate` from the intended GitHub Actions integration;
- preserve strict/up-to-date required-status enforcement;
- remove `Required PR Gate` as protected merge authority;
- preserve the existing no-bypass contract; and
- be re-fetched after mutation before finding 13 can be closed.

Without strict/up-to-date enforcement, a base update could change the prospective merge while leaving the head SHA—and therefore an old status—unchanged.

## Bootstrap and live evidence

The trusted workflow/helper/verifier definition was bootstrapped to `main` through audited PR #45. The bounded PR-mergeability response stabilization introduced after initial activation failures was bootstrapped through PR #47, but a later trusted run demonstrated that the workflow-token PR response may omit the merge SHA field rather than return it as `null`.

Live evidence collected during activation includes:

- ordinary probe `pull_request` runs rejected at startup by the active external policy;
- owner `repository_dispatch` runs selecting the trusted default-branch workflow revision;
- exact prospective-merge checkout and trusted subject preflight succeeding;
- supply chain, security, 34-case deterministic control evaluation, Playwright reference SUT, and Python 3.11/3.13 deterministic suites succeeding on the dispatched merge subject;
- reporter failures producing no false trusted status when live subject evidence was incomplete;
- direct observation that `refs/pull/48/merge` pointed to the exact dispatched prospective merge SHA while the workflow-token PR response omitted `merge_commit_sha`.

Historical failed trusted runs are evidence of fail-closed behavior, not PASS evidence for the terminal trusted reporter.

## Current remediation contract

The merge-ref remediation changes only reporter subject resolution and focused tests. It does not change:

- `.github/workflows/ci.yml`;
- workflow triggers or permissions;
- protected-path preflight scope;
- deterministic validation domains or thresholds;
- dependency/cache authority;
- `Protect Main` rules;
- the external Actions Policy; or
- the requirement for owner/default-branch `repository_dispatch`.

Because `scripts/trusted_pr_control.py` is a protected control-plane path, a trusted dispatch cannot bootstrap its own changed reporter bytes. The exact remediation revision must first receive ordinary exact-revision CI under a narrowly controlled temporary `pull_request` policy window, be audited and merged to `main`, and then the policy must return to `repository_dispatch`-only before trusted activation testing resumes.

## Activation completion sequence

The remaining sequence is:

1. validate and audit the merge-ref reporter remediation as an ordinary PR revision;
2. bootstrap only that exact validated revision to `main`;
3. restore and independently observe the `repository_dispatch`-only Actions Policy boundary;
4. create a disposable probe from the new `main` and observe its ordinary `pull_request` workflow being denied;
5. obtain the exact current PR head/base/merge-ref tuple;
6. issue owner-authorized `trusted-pr-validation` `repository_dispatch` for that tuple;
7. require every validation domain and `Required PR Gate` to succeed;
8. require the trusted default-branch reporter to publish `Trusted PR Gate: success` to the exact head and independently read that status back;
9. inspect exact-subject artifacts and live PR state;
10. transition `Protect Main` from `Required PR Gate` to `Trusted PR Gate` while preserving strict/up-to-date enforcement and no bypass;
11. re-fetch the ruleset, main SHA, PR subject, and status provenance before closing finding 13.

No merge-authority claim is valid before step 11 completes.

## Repository controls

`scripts/trusted_pr_control.py` remains standard-library-only and enforces:

- fixed repository identifier and bounded API response ingestion;
- fixed `repository_dispatch` / `refs/heads/main` / owner admission before API access;
- exact open/main PR head/base identity;
- exact GitHub pull-request merge-ref identity;
- exact merge commit SHA and two-parent ordering;
- second PR/ref read immediately before status publication;
- diagnostic no-status behavior;
- exact-head success/failure commit-status publication;
- exact repository Actions-run target URL validation; and
- nonzero process exit after publishing an authorized validation failure.

`scripts/verify_ci_contract.py` freezes the reviewed workflow definition and structural authority model. It intentionally cannot certify live GitHub Actions Policy or ruleset state; those remain externally observed facts.

## Evidence semantics

A green ordinary PR run proves the repository candidate is internally consistent for that exact GitHub PR merge subject. It does not by itself prove trusted workflow-definition provenance.

A green trusted validation aggregate proves the dispatched prospective merge subject passed the deterministic repository gates. It does not prove terminal trusted authority unless the reporter also successfully revalidates the live PR/merge ref and publishes `Trusted PR Gate` on the exact current head.

A `Trusted PR Gate` success is not sufficient by itself until `Protect Main` requires that context with strict/up-to-date semantics and no bypass, and the resulting ruleset has been re-fetched.

Blocked, failed, missing, stale, or unobserved evidence remains non-PASS truth.
