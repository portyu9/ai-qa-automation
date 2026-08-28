# Trusted PR control plane

This document defines the trusted pull-request validation and terminal-status authority for **ƳƤ AI QA Automation Framework**. The design prevents pull-request-controlled GitHub Actions workflow bytes from manufacturing the same protected status identity that authorizes merge.

The control plane is **activated for the observed repository configuration**. The reviewed trusted workflow is on `main`; the repository Actions Policy has been observed active with repository-owner actor restriction and `repository_dispatch` as the sole allowed event; a live owner-authorized trusted dispatch completed successfully; `Trusted PR Gate` was independently read back on the exact PR head; and `Protect Main` was re-fetched after transition with `Trusted PR Gate` as its sole required status, strict/up-to-date semantics enabled, and no bypass actors.

This is evidence bound to the observed repository state, not a claim that repository source can self-attest future GitHub configuration. The external policy and ruleset remain platform-owned authorities that must be re-observed after material administrative change.

## Threat model

A stable check name is not an independent trust root when a pull request can cause feature-controlled workflow definitions to execute under the same GitHub Actions integration. Denying only `pull_request` is insufficient because `push`, `merge_group`, ref-selectable `workflow_dispatch`, or another event could otherwise execute feature-ref workflow bytes under that same identity.

The required external invariant is therefore **default-branch-definition-only execution for the protected identity**. In the observed activated repository policy:

- enforcement is active;
- actor is restricted to the repository owner;
- `repository_dispatch` is the sole allowed event;
- ordinary `pull_request` execution is denied;
- feature/ref-defined `push` is denied;
- `merge_group` is denied;
- ref-selectable `workflow_dispatch` is denied.

Live disposable probes demonstrated that ordinary `pull_request` runs are rejected at workflow startup while owner `repository_dispatch` runs execute the workflow definition from `main`.

A separate invariant is required for base drift. `Trusted PR Gate` is posted to the PR head commit, while the validated subject also includes the base and simulated merge result. Protected-branch enforcement therefore remains strict/up-to-date so a later base change cannot reuse a status created for an older prospective merge.

## Authority flow

The runtime authority chain is:

**exact PR subject → default-branch trusted workflow → read-only validation → deterministic aggregate → live PR/merge-ref revalidation → `Trusted PR Gate` status → strict protected-branch enforcement**

The authorities are intentionally separated:

1. `repository_dispatch` selects the workflow definition from the default branch. The payload carries PR number, expected head SHA, expected base SHA, expected simulated-merge SHA, and an explicit authorization boolean as untrusted data.
2. The five validation domains set `CI_SUBJECT_SHA` to the supplied expected merge SHA, check out that exact object with persisted credentials disabled, and verify the checkout revision before execution.
3. The trusted subject preflight verifies that the supplied merge commit has the expected base/head parents and that protected control-plane paths match the trusted default-branch revision before repository scripts execute.
4. Validation jobs remain read-only and secret-free. They cannot publish terminal merge authority.
5. `Required PR Gate` deterministically aggregates the five validation domains. It remains validation evidence but is no longer the protected merge status.
6. `Trusted PR Gate Reporter` runs only for `repository_dispatch`, `refs/heads/main`, and repository-owner actor. It is the workflow's sole `statuses: write` authority and sole GitHub Actions token consumer.
7. The reporter checks out and verifies the trusted `github.sha` default-branch revision before invoking `scripts/trusted_pr_control.py`.
8. The helper admits only the fixed trusted event/ref/actor tuple before GitHub API access.
9. Before any status write, the helper revalidates the live open PR number/head/base identity, GitHub's exact `refs/pull/<number>/merge` ref, the merge commit's exact two ordered parents `(base, head)`, then re-fetches both PR identity and merge ref to narrow the final TOCTOU window.
10. Only an authorized successful aggregate publishes `Trusted PR Gate: success` to the exact PR head. An authorized non-success publishes failure and the reporter exits nonzero. Diagnostic dispatches never publish status.
11. `Protect Main` requires `Trusted PR Gate` from the intended GitHub Actions integration with strict/up-to-date semantics and no bypass.

Model output has no role in this authorization path.

## Why the merge ref is authoritative

GitHub creates a temporary read-only `refs/pull/<PR>/merge` reference when a pull request can be simulated as a merge. It represents the simulated merge object for the current PR head/base state and changes as that subject changes.

Live activation runs showed that the workflow-token pull-request response can omit `merge_commit_sha` even while the pull-request merge ref exists at the expected SHA. Treating that intermittently shaped response field as required terminal authority caused earlier reporters to fail closed after all validation domains passed.

The remediation did **not** relax subject binding. Terminal reporting instead requires stronger Git-object evidence:

- the live PR remains open and targets `main`;
- PR number, head SHA, and base SHA equal the dispatched expected identity;
- `refs/pull/<number>/merge` exists, has the exact expected name/type, and points to the dispatched expected merge SHA;
- the Git commit object at that SHA has exactly two ordered parents: expected base then expected head;
- PR identity and merge ref are fetched again immediately before status publication;
- any API failure, missing/malformed object, mismatched SHA/ref/type/parent, closed PR, base/head drift, or final-read drift fails closed with no success status.

There is no retry after a status write and no generic retry of authorization, schema, or mutation failures.

## External Actions Policy

The activated external policy was observed through the repository GitHub settings surface. Its required invariant is:

- enforcement: active;
- allowed actor: repository owner only;
- allowed event: `repository_dispatch` only;
- all feature/ref-defined competing execution paths denied unless an independently enforced mechanism proves equivalent default-branch workflow-definition provenance.

Repository code and `scripts/verify_ci_contract.py` intentionally cannot attest that live policy state. An administrative policy edit is therefore an external authority change and invalidates any assumption that the last observation still holds.

Temporary activation-bootstrap windows that admitted `pull_request` were used only to validate protected reporter revisions before those revisions could exist on `main`. Those windows were closed after each bootstrap. The final activation probe independently demonstrated the restored `repository_dispatch`-only boundary before terminal transition.

## Merge-enforcement invariant

The observed `Protect Main` ruleset after activation requires:

- `Trusted PR Gate` as the sole required status;
- GitHub Actions integration ID `15368` for that context;
- `strict_required_status_checks_policy = true`;
- no bypass actors;
- pull-request review-thread resolution;
- merge commits as the allowed merge method;
- deletion and non-fast-forward protection.

`Required PR Gate` remains an internal deterministic aggregate inside the workflow. It is no longer protected merge authority.

Strict/up-to-date enforcement is essential. A base update can change the prospective merge while leaving the PR head SHA unchanged; strict enforcement forces revalidation rather than accepting a trusted status created for an older merge subject.

## Activation evidence

The activation sequence produced both positive and negative evidence.

### Bootstrap and fail-closed evidence

- PR #45 bootstrapped the reviewed trusted workflow/control-plane definition to `main`.
- Initial live trusted dispatches exposed GitHub pull-request mergeability/merge-SHA response-shape behavior.
- Those reporters failed closed and emitted no false trusted success status.
- PR #47 bootstrapped bounded mergeability stabilization after exact-revision ordinary CI.
- A later trusted run proved the workflow-token response could omit `merge_commit_sha` entirely.
- PR #49 bootstrapped the merge-ref authority remediation after exact-revision ordinary CI run #631.

Historical failed trusted runs are evidence of fail-closed behavior, not PASS evidence for the terminal trusted reporter.

### Successful terminal activation evidence

For disposable probe PR #50:

- ordinary `pull_request` run #633 was rejected at workflow startup by the restored external policy;
- PR head was `5dadafe85c0bc2710672963dcf220186b88f812d`;
- base was trusted `main` `fc95c3554853d3b9b50a788e7bcfd10257637126`;
- GitHub's live `refs/pull/50/merge` pointed to `15139baa4e1537eb37db328e32f654e27e3e1ac2` with exactly the expected ordered parents;
- owner-authorized `repository_dispatch` run #634 selected workflow revision `fc95c3554853d3b9b50a788e7bcfd10257637126` from `main`;
- trusted subject preflight succeeded;
- supply chain, security, 34-case deterministic control evaluation, Playwright reference SUT, Python 3.11.16, Python 3.13.15, and `Required PR Gate` all succeeded;
- Python 3.11 Mypy succeeded; Python 3.13 Mypy was intentionally skipped by workflow design;
- `Trusted PR Gate Reporter` succeeded and reported `status_posted: true` for the exact PR head;
- an independent status read returned `Trusted PR Gate: success` with target run #634 and GitHub Actions integration ID `15368`;
- `Protect Main` was then transitioned and independently re-fetched with `Trusted PR Gate` required, strict/up-to-date enabled, and no bypass actors;
- probe PR #50 was closed unmerged after serving its evidence purpose.

The external workflow-provenance finding addressed by this control plane is therefore closed for the observed activated configuration. A future change to the Actions Policy, protected required context, strict semantics, integration identity, default branch, trusted workflow definition, or reporter authority is a new material authority change and requires revalidation.

## Normal protected-PR operation

With the policy active, ordinary PR/push/merge-group workflows under this GitHub Actions identity are expected to be blocked. A merge candidate is validated through the trusted path:

1. obtain the current PR number, head SHA, base SHA, and live `refs/pull/<number>/merge` SHA;
2. verify the merge commit has ordered parents `(base, head)`;
3. issue owner-authorized `repository_dispatch` event type `trusted-pr-validation` with that exact tuple;
4. inspect the exact `repository_dispatch` run and persisted evidence;
5. require all five validation domains and `Required PR Gate` to succeed;
6. require `Trusted PR Gate Reporter` to succeed;
7. independently read `Trusted PR Gate: success` on the exact current head;
8. re-check PR head/base/merge subject before merge;
9. rely on strict protected-branch enforcement to reject stale base/head evidence.

If the subject changes, the old trusted status does not certify the new subject; issue a new exact-subject trusted validation.

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

A green ordinary PR run from a temporary bootstrap window proves the candidate was internally consistent for that exact GitHub PR merge subject. It does not by itself prove trusted workflow-definition provenance.

A green trusted validation aggregate proves the dispatched prospective merge subject passed the deterministic repository gates. It does not prove terminal trusted authority unless the reporter also successfully revalidates the live PR/merge ref and publishes `Trusted PR Gate` on the exact current head.

A `Trusted PR Gate` success proves terminal status publication for that exact observed subject, but merge authority additionally depends on the external Actions Policy and strict protected-branch ruleset remaining as observed.

Blocked, failed, missing, stale, or unobserved evidence remains non-PASS truth.

---

[← CI/CD](CI_CD.md) · [Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).