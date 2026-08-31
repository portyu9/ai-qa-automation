# Trusted PR control plane

This document defines trusted pull-request validation and terminal merge-status authority for **ƳƤ AI QA Automation Framework**. The design separates candidate-controlled development feedback from the deterministic path allowed to request the dedicated merge-status identity.

Repository source defines the control-plane contract. GitHub App installation state, Environment protection, Actions Policy, and branch-ruleset configuration are external authorities and must be observed independently. Source must not report those controls as active merely because a workflow is designed to use them.

## Threat model

A stable check name is not a trust boundary when candidate-controlled workflow bytes can execute under the same integration identity that owns the required status. A same-repository pull request can change workflow YAML, tests, verification scripts, or requested `GITHUB_TOKEN` permissions. Therefore ordinary `pull_request` CI is development evidence only; it cannot publish the protected merge status.

The durable design uses two identities:

- **GitHub Actions** runs candidate feedback plus trusted default-branch orchestration and deterministic validation under read-only native-token authority.
- A dedicated **ƳƤ Trusted PR Gate GitHub App** owns the only status identity accepted by the `Protect Main` ruleset for context `Trusted PR Gate`.

A PR-controlled workflow may manufacture another status with the same text, but it cannot satisfy a required-status rule that is bound to the dedicated App integration.

Strict/up-to-date branch enforcement remains required because `Trusted PR Gate` is posted to the PR head while trusted validation binds the base and prospective merge object. Base drift must invalidate the previous merge subject.

Model output has no role in this authorization path.

## Authority flows

Routine and maintenance changes intentionally use different admission paths.

### Routine automatic path

After the automatic-admission migration is merged and independently proven live, the intended routine chain is:

**ordinary PR CI completion → default-branch `workflow_run` wake-up → live deterministic admission → exact prospective merge + protected-object guard → deterministic validation → fresh admission revalidation → dedicated App token → live PR/merge-ref revalidation → dedicated App status → strict protected-branch enforcement**

The `workflow_run` payload is only a wake-up signal. `scripts/auto_trusted_preflight.py` independently re-fetches the triggering run, current `main`, the live PR, `refs/pull/<number>/merge`, ordered merge parents, and recursive Git trees. Automatic admission requires all of the following:

1. the triggering run is the exact reviewed ordinary CI workflow ID/name/path;
2. it is a completed successful `pull_request` run;
3. repository, head repository, actor, and triggering actor match the single-maintainer repository contract;
4. exactly one open non-draft same-repository PR resolves from the live head SHA and targets `main`;
5. the PR base equals current `main`;
6. the live prospective merge has exactly two ordered parents `(base, head)`;
7. every automatic protected authority root has the same Git object ID at trusted base and prospective merge.

Any API failure, malformed/truncated response, bounded-PR-resolution saturation, ambiguity, fork head, stale base, identity drift, merge-parent mismatch, or protected-root change fails closed.

The trusted automatic workflow itself is selected from the default branch. Before any candidate script executes, trusted workflow YAML checks out the exact prospective merge, verifies its parents, and independently compares the core protected roots with `git ls-tree`. The default-branch preflight additionally treats versioned `.gitattributes` as indirect archive/build authority, so an attributes change is ineligible even though candidate code has not yet executed. Only a zero-drift admission permits candidate validation commands to run.

The validation jobs remain read-only and secret-free. Only the final `trusted-pr-gate` Environment job can reference the dedicated App credential. That reporter checks out the trusted default-branch revision, runs the automatic admission preflight again, requires exact equality with the original PR/head/base/merge/trusted tuple, and only then mints the short-lived App token. `scripts/auto_trusted_report.py` reuses the canonical live PR/head/base/merge resolver from `scripts/trusted_pr_control.py` immediately before status publication.

### Protected maintenance path

A PR that changes a protected authority root is deliberately **not** auto-authorized. It uses the explicit owner `repository_dispatch` path with an exact protected-object manifest. That path remains the maintenance escape hatch for legitimate changes to workflows, tests, verifier scripts, dependency/build authority, MCP/control-plane configuration, or other protected roots.

The owner-dispatch chain is:

**owner authorization → exact PR head/base/prospective merge tuple + protected-object manifest → trusted default-branch dispatch definition → deterministic validation → live PR/merge-ref revalidation → dedicated App status → strict protected-branch enforcement**

This distinction removes routine human dispatch work without letting an automatic change redefine its own judge.

## Protected authority roots

The explicit maintenance-manifest root set is:

- `.github`
- `.claude`
- `.dockerignore`
- `.mcp.json`
- `.pre-commit-config.yaml`
- `CLAUDE.md`
- `Dockerfile`
- `evals`
- `examples`
- `pyproject.toml`
- `requirements`
- `scripts`
- `tests`
- `src/ai_qa_automation/__init__.py`
- `src/ai_qa_automation/io_safety.py`
- `src/ai_qa_automation/tools/__init__.py`
- `src/ai_qa_automation/tools/execution_env.py`

The routine automatic preflight is intentionally stricter: it protects that entire set **plus `.gitattributes`**, because versioned Git attributes can alter archive bytes used by reproducible-build and container-context validation. A `.gitattributes` addition, removal, or object change therefore cannot enter the automatic trusted lane.

For automatic admission, **any** protected object-ID difference makes the PR ineligible. There is no automatic allowlist override. The trusted YAML subject guard independently repeats the core root comparison, while the preflight and final preflight revalidation both enforce the stricter automatic set.

For maintenance dispatch, the preflight uses an **exact protected-object manifest** for its reviewed manifest root set. The dispatch itself is an explicit owner authorization of the exact PR/base/prospective-merge tuple; the manifest adds exact object-transition binding for the reviewed control-plane roots. For each such root, it observes the Git object ID at the trusted base and at the prospective merge subject. Missing paths are represented only by the literal `MISSING` sentinel. A Git observation failure is fatal; `MISSING` is emitted only when an exact `git ls-tree` lookup succeeds and returns no object for that protected path.

`client_payload.protected_manifest` must be a bounded JSON array. Every entry must contain exactly:

```json
{"path":"tests","base_oid":"<40-hex-or-MISSING>","subject_oid":"<40-hex-or-MISSING>"}
```

The maintenance workflow rejects the dispatch unless the normalized supplied manifest equals the complete observed set of manifest-root changes exactly. Unknown paths, duplicates, malformed object IDs, omitted changes, extra changes, or stale object IDs fail closed.

An empty manifest means **no manifest-root changes are authorized**. A non-empty manifest is explicit owner authorization for exactly those object transitions. It is not independent proof that changed tests or control-plane code are correct; the candidate still requires full validation and adversarial review.

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

The reporter mints a short-lived App installation token using hosted `openssl`, `curl`, and Python standard-library JSON parsing. The private key is written only to a mode-restricted runner temporary file, removed before API use continues, and the installation token is masked before being written to `GITHUB_OUTPUT`.

## Native GitHub Actions authority

Ordinary PR CI is read-only and secret-free. The trusted automatic workflow also keeps its native `GITHUB_TOKEN` read-only, with only `actions: read`, `contents: read`, and `pull-requests: read` needed for admission and observation. It has no native `statuses: write` permission.

The automatic reporter obtains status-write authority only by minting the separately scoped dedicated App token after final deterministic admission revalidation. Validation jobs never receive that App token or its private key.

`pull_request_target` remains forbidden. Credentialed, destructive, publishing, deployment, load/stress, and other privileged jobs remain manual/environment-protected unless a separately reviewed control proves safe authority.

## Actions Policy boundary

Repository source can prove the automatic `workflow_run` contract statically, but external Actions Policy decides whether that event is actually permitted to start. Therefore the automatic path is not considered activated until a post-merge live source-only PR produces an observed `workflow_run` run and dedicated-App status.

The expected event policy after activation is:

- `pull_request` for ordinary development feedback;
- `workflow_run` for routine trusted automatic admission;
- `repository_dispatch` for explicit protected maintenance authorization.

If external policy blocks `workflow_run`, that is an environment-owned **BLOCKED** state, not evidence that the repository source passed or failed its runtime contract.

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

GitHub's read-only `refs/pull/<number>/merge` ref represents the prospective merge object for the current head/base pair. Both trusted lanes bind validation to that exact SHA.

Terminal reporting requires:

- PR remains open and targets `main`;
- current PR number, head SHA, and base SHA equal the admitted expected values;
- `refs/pull/<number>/merge` exists and points to the expected merge SHA;
- that merge commit has exactly two ordered parents `(base, head)`;
- automatic admission also remains eligible with zero protected-root drift;
- PR identity and merge ref are fetched again immediately before publication;
- any API failure, malformed response, missing ref, parent mismatch, head/base drift, closed PR, or final-read drift fails closed.

There is no retry after status publication and no generic retry of authorization or schema failures.

## Routine operation after activation

For an ordinary owner same-repository PR with no protected-root changes:

1. normal `pull_request` CI provides development evidence;
2. completed successful CI wakes the default-branch `workflow_run` orchestrator;
3. live admission recomputes the PR/head/base/merge tuple and protected Git objects;
4. trusted YAML independently rechecks merge parents and the core protected-object set before candidate execution;
5. the trusted validation domains execute against the exact prospective merge;
6. the aggregate must succeed;
7. the reporter re-runs the stricter live admission on the trusted default-branch checkout;
8. only then does it mint the dedicated App token and invoke final live PR/merge-ref revalidation;
9. independently observe `Trusted PR Gate: success` from the dedicated App integration on the exact head before merge.

A subject change requires a new ordinary PR run and a new automatic trusted evaluation. No human dispatch is expected for this routine path.

For a PR that changes any automatic protected root, automatic admission stops with `eligible=false`; use the maintenance path and exact owner authorization instead.

## Automatic-admission migration bootstrap

The automatic workflow, admission scripts, verifier, and tests are themselves protected control-plane changes. The automatic path therefore cannot authorize the PR that introduces it.

The migration must be narrow and auditable:

1. validate the migration PR's exact prospective merge revision with ordinary CI;
2. run full deterministic tests, security/supply-chain checks, and adversarial review on that exact revision;
3. verify the diff contains only the automatic admission/control-plane implementation, tests, and matching documentation;
4. authorize that exact protected revision once through the existing owner `repository_dispatch` manifest path;
5. require the dedicated App `Trusted PR Gate` success on the exact head;
6. merge only that validated revision;
7. re-fetch `main`, workflow bytes, ruleset binding, and merge signature;
8. open a source-only proof PR that changes no protected root;
9. require an observed automatic `workflow_run` validation and `Trusted PR Gate` status from the dedicated App;
10. only after that live proof classify automatic admission as activated.

If step 9 is blocked by external Actions Policy, adjust only the necessary environment policy and repeat the proof; do not weaken repository admission checks.

## Historical dedicated-App bootstrap

The earlier migration from a GitHub-Actions-owned status identity to the independent dedicated App required a separate one-time bootstrap. Historical green runs under GitHub Actions integration ID `15368` prove only the previous control plane. The active merge rule must continue to bind `Trusted PR Gate` to the dedicated App integration.

## Repository controls

`scripts/auto_trusted_preflight.py` is standard-library-only and performs bounded, fail-closed live admission from the `workflow_run` wake-up event. It uses no-follow bounded event-file ingestion and rejects ambiguous or saturated PR resolution, malformed refs/commits, stale base identity, truncated Git trees, or protected-object drift. It does not mutate GitHub or publish status.

`scripts/auto_trusted_report.py` is a thin automatic authorization adapter. It cannot discover or invent a subject; it receives the already admitted exact tuple and reuses `scripts/trusted_pr_control.py` for live PR/head/base/merge resolution and the App-backed status primitive.

`scripts/trusted_pr_control.py` remains the canonical exact-subject resolver for terminal status publication and the explicit owner-dispatch reporter. It enforces bounded API ingestion, exact live PR identity, exact merge-ref/parent identity, final live re-read, exact-head status publication, and nonzero exit after an authorized validation failure.

`scripts/ci_contract_base.py` preserves the previously hardened CI verifier bytes. `scripts/verify_ci_contract.py` retains that full contract and adds exact-byte plus structural verification for the automatic workflow: trigger identity, read-only native permissions, trusted/candidate checkout boundaries, core YAML protected paths, validation aggregation, final admission revalidation, isolated App credential use, and reporter ordering.

The repository verifier cannot certify live GitHub App installation state, secret values, Environment branch policy, Actions Policy, or ruleset integration ID; those remain external observations.

## Evidence semantics

A green ordinary PR run proves the candidate's deterministic gates for that exact ordinary GitHub event subject. It is not merge authority.

A green automatic trusted validation proves the live prospective merge passed the trusted automatic gate only if admission was eligible, automatic protected roots were unchanged, the final admission revalidation remained identical, and the reporter completed. It is not terminal merge authority unless the resulting `Trusted PR Gate` status came from the dedicated App integration required by the live ruleset.

A green owner-dispatch trusted validation proves the explicitly authorized prospective merge subject passed the deterministic repository gates under the trusted default-branch maintenance definition. It is not terminal authority unless the reporter also revalidates the live subject and publishes through the dedicated App.

A `Trusted PR Gate` success is merge-authorizing evidence only when its source is the dedicated App integration currently required by the strict ruleset and the PR subject remains current.

Blocked, failed, missing, stale, wrong-integration, unobserved, or protected-change-ineligible evidence is non-PASS truth.

---

[← CI/CD](CI_CD.md) · [Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
