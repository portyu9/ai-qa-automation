# Trusted PR control-plane prototype

This document describes a **non-authoritative prototype** for closing the external workflow-provenance boundary identified during Phase 4 hardening. The prototype must not be interpreted as merge authority until the required GitHub repository policy is active and the trusted workflow path is fully implemented and revalidated.

## Problem

A required status check produced by a normal `pull_request` workflow is not an independent trust root when the pull request can edit that workflow or its repository-local verifier. GitHub rulesets bind a required status context and source integration, not a unique workflow definition.

## Intended authority model

The target architecture separates untrusted execution from terminal merge authority:

1. Repository Actions Policy denies the `pull_request` event before workflow launch.
2. A default-branch `pull_request_target` dispatcher reads only GitHub event metadata and never checks out or executes pull-request code.
3. The dispatcher requests `trusted-pr-validation.yml` with `ref: main`, so GitHub selects the validator definition from trusted `main` while the exact pull-request head/base/merge identities are passed only as data.
4. Validation jobs may execute the exact pull-request subject only with read-only repository authority, no secrets, no deployment/status/check write permission, and no dependency cache.
5. Automatic dispatches are diagnostic only. They cannot publish merge authorization.
6. Final merge authorization requires an explicit owner-initiated `workflow_dispatch` of the trusted `main` validator for the exact current pull-request subject.
7. A separate reporter job owns the only `statuses: write` permission. It checks the current pull request through GitHub again, requires the expected head/base/merge identities to remain unchanged, requires the trusted validation aggregate to succeed, and publishes `Trusted PR Gate` to the exact head only for an owner-authorized run.
8. A later push changes the head SHA, so the prior commit status cannot satisfy the new head.

The repository owner/admin account remains an external administrative trust root because that identity can change repository policy itself. No second-person approval ceremony is introduced.

## Bootstrap requirement

The architecture is deliberately dormant until GitHub repository Actions Policy is configured **outside pull-request-controlled source**. The event allow-list must deny `pull_request` execution. `pull_request_target` and `workflow_dispatch` may be allowed only for the trusted control flow; other events should remain denied unless an implemented workflow needs them. Policy state must be inspected as external evidence before the trusted gate is accepted.

The current connected GitHub tooling does not expose Actions Policy mutation or inspection, so this prerequisite cannot be certified from repository code.

## Cache boundary

Trusted and credentialed workflows must not restore dependency caches that untrusted pull-request execution could poison. The prototype therefore removes `setup-python` pip caching from manual validation as a prerequisite. A future verifier must reject caching across trusted workflows.

## Current prototype scope

`scripts/trusted_pr_control.py` implements the standard-library control logic for:

- bounded no-follow ingestion of `pull_request_target` event metadata;
- fresh GitHub API resolution of the current open `main`-targeting pull-request subject;
- diagnostic dispatch to `trusted-pr-validation.yml` at `ref: main`;
- exact head/base/merge subject revalidation before terminal reporting;
- owner-only authorization for merge status publication;
- diagnostic runs that never publish merge authority;
- fail-closed failure status for an owner-authorized validation that does not succeed; and
- repository-bound `Trusted PR Gate` target URLs.

The workflow dispatcher, trusted validator, reporter wiring, repository Actions Policy, and ruleset transition are **not yet implemented or active**. The current helper/tests are implementation scaffolding only, and even a green ordinary `pull_request` run validates the code under the existing vulnerable control plane rather than proving the new trust model. Until all missing controls are in place and adversarially exercised, finding 13 remains blocked and PR #43 remains unmerged.
