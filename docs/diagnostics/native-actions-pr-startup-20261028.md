# Disposable native GitHub Actions PR-event diagnostic — 2026-10-28

**DO NOT MERGE.** This documentation-only commit intentionally contains no
workflow YAML, application code, dependency, security policy, or runtime mutation.

## Frozen accepted evidence

- Default branch: `main@102ffc67a7e42c715bc35ad393f831ccceca7634`.
- Native `ci` file: `.github/workflows/ci.yml@d765d0214b6fb8927f3b929628c387b53e417f9e`.
- Native `security` file: `.github/workflows/security.yml@8d9388e279843897af94eb9893bfe0eedbbec330`.
- Workflow `ci` registered id: `339754724`.
- Explicit exact-main CI `workflow_dispatch` run `40749244582`, suite
  `110456043612`, concluded `startup_failure` before any jobs existed.

## Differential event test

Creating this normal, non-draft PR emits an actual `pull_request` event
without touching either native workflow. Observe whether GitHub creates
`ci` and `security` runs against this PR and whether their jobs materialize.
Do not substitute a successful trusted wake, smoke test, post-merge controller,
or synthetic check for native CI/Security evidence.

Record direct run IDs and conclusions, then comment and **close unmerged**.
The branch is safe to delete once the experiment is recorded. The experiment
does not claim to repair the native GitHub Actions workflow registration.
