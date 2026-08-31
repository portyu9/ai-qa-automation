# Trusted PR control plane

This document defines trusted pull-request validation and terminal merge-status authority for **ƳƤ AI QA Automation Framework**. The design separates candidate-controlled development feedback from the deterministic paths allowed to request the dedicated merge-status identity.

Repository source defines the control-plane contract. GitHub App installation state, Environment protection, Actions Policy, and branch-ruleset configuration are external authorities and must be observed independently. Source must not report those controls as active merely because a workflow is designed to use them.

## Threat model

A stable check name is not a trust boundary when candidate-controlled workflow bytes can execute under the same integration identity that owns the required status. A same-repository pull request can change workflow YAML, tests, verification scripts, dependency locks, or requested token authority. Therefore ordinary `pull_request` CI is development evidence only; it cannot publish the protected merge status.

The durable design uses two identities:

- **GitHub Actions** runs ordinary candidate feedback and trusted default-branch orchestration under read-only native-token authority.
- A dedicated **ƳƤ Trusted PR Gate GitHub App** owns the only status identity accepted by the `Protect Main` ruleset for context `Trusted PR Gate`.

A PR-controlled workflow may manufacture another status with the same text, but it cannot satisfy a required-status rule bound to the dedicated App integration.

Strict/up-to-date branch enforcement remains required because `Trusted PR Gate` is posted to the PR head while trusted admission binds the base and live prospective merge object. Base drift must invalidate previous evidence.

Model output has no role in this authorization path.

## Authority flows

Routine and protected-maintenance changes intentionally use different admission paths.

### Ordinary PR evidence

`ci.yml` executes ordinary `pull_request` validation under read-only, secret-free authority and binds every validation checkout to the exact GitHub event subject. `Required PR Gate` deterministically aggregates those validation jobs.

This path produces candidate evidence only. Candidate workflow/repository bytes are not an independent trust root, and ordinary CI never receives the dedicated App private key.

### Routine automatic path

For a completed successful ordinary CI run, `trusted-pr-auto.yml` may wake from `workflow_run`:

**ordinary PR CI completion → default-branch `workflow_run` wake-up → live deterministic admission → exact prospective merge + zero protected-object drift → deterministic validation → fresh admission revalidation → dedicated App token → live PR/merge-ref revalidation → App-backed status → strict protected-branch enforcement**

The `workflow_run` payload is only a wake-up signal. `scripts/auto_trusted_preflight.py` independently re-fetches the triggering run, current `main`, the live PR, `refs/pull/<number>/merge`, ordered merge parents, and recursive Git trees. Automatic admission requires all of the following:

1. the triggering run is the exact reviewed ordinary CI workflow identity;
2. it is a completed successful `pull_request` run;
3. repository, head repository, actor, and triggering actor match the single-maintainer repository contract;
4. exactly one open non-draft same-repository PR resolves from the live head SHA and targets `main`;
5. the PR base equals current `main`;
6. the live prospective merge has exactly two ordered parents `(base, head)`; and
7. every automatic protected authority root has the same Git object ID at trusted base and prospective merge.

Any API failure, malformed/truncated response, bounded-PR-resolution saturation, ambiguity, fork head, stale base, identity drift, merge-parent mismatch, or protected-root change fails closed.

The trusted automatic workflow is selected from the default branch. Before any candidate script executes, trusted YAML checks out the exact prospective merge, verifies its parents, and independently compares core protected roots. Only a zero-drift admission permits candidate validation commands to run.

Validation jobs remain read-only and secret-free. Only the final `trusted-pr-gate` Environment job can reference the dedicated App credential. That reporter checks out trusted default-branch bytes, repeats automatic admission, requires the same PR/head/base/merge/trusted tuple, and only then mints the short-lived App token. `scripts/auto_trusted_report.py` reuses the canonical live PR/head/base/merge resolver from `scripts/trusted_pr_control.py` immediately before status publication.

### Protected maintenance: full trusted execution

A protected change is deliberately not auto-authorized. The retained owner event `trusted-pr-validation` executes the prospective merge subject under the default-branch `ci.yml` definition after exact protected-object authorization:

**owner authorization → exact PR head/base/prospective merge + protected manifest → trusted default-branch workflow definition → deterministic candidate execution → aggregate → live subject revalidation → App-backed status → strict protected-branch enforcement**

This path remains appropriate when the trusted base workflow graph can validly execute the candidate dependency/runtime contract.

The inline preflight fails closed unless:

- `GITHUB_SHA` equals the expected base;
- the prospective merge has exactly two ordered parents `(base, head)`; and
- the normalized owner manifest exactly equals the complete observed protected-root object changes.

### Protected maintenance: exact ordinary-CI evidence authorization

A workflow/dependency control-plane migration can intentionally make the base workflow graph definition-stale. For example, a candidate may replace a compatibility lock and matrix lane; the old trusted workflow can then schedule a removed lock even though the candidate's own exact ordinary CI already succeeded. Keeping stale authority merely to satisfy that old graph would be the wrong repair.

`.github/workflows/trusted-pr-evidence.yml` provides a separate owner event:

```text
trusted-pr-evidence-authorization
```

Its chain is:

**owner authorization → trusted default-branch evidence workflow → live exact PR/head/base/merge + protected manifest → exact successful ordinary PR CI admission → digest-verified persisted merge-bound build evidence → fresh evidence revalidation → dedicated App token → canonical live subject revalidation → App-backed status → strict protected-branch enforcement**

The defining property is that **the evidence-authorization workflow never executes candidate bytes**. Both of its checkouts are `github.sha` from trusted `main`; persisted checkout credentials are disabled. Native permissions are exactly `actions: read`, `contents: read`, and `pull-requests: read`.

`scripts/trusted_pr_evidence.py` is standard-library-only at the trust boundary and performs bounded fail-closed admission. It requires:

1. owner `repository_dispatch` on `refs/heads/main`;
2. the exact live open same-repository PR number/head/base and target `main`;
3. the exact live prospective merge and ordered parents `(base, head)`;
4. exact equality between the owner protected manifest and the complete observed protected-root object transitions;
5. candidate `ci.yml` still contains the reviewed ordinary `pull_request` trigger, `github.sha` subject binding, and deterministic Required PR Gate;
6. a completed successful ordinary `pull_request` CI run bound to the exact PR/head/base/head-ref identity;
7. successful supply-chain/CI-contract proof, security, browser, deterministic evals, Required PR Gate, and exactly two successful quality lanes;
8. exactly one unexpired `supply-chain-evidence` artifact bound to the selected run/head/branch;
9. canonical artifact metadata including a SHA-256 digest and expected GitHub archive URL;
10. a bounded artifact archive whose downloaded bytes match the trusted metadata size/digest;
11. a bounded safe ZIP entry set with no traversal, absolute path, duplicate, encrypted entry, or symlink entry;
12. `build-manifest.json` with the reviewed schema/kind, exact authorized prospective merge SHA, and `tracked_worktree_clean=true`; and
13. a fresh live subject resolution after admission.

Artifact download follows the GitHub API redirect explicitly, then fetches the isolated HTTPS storage URL **without forwarding the GitHub authorization header**. Size, entry-count, uncompressed-size, and build-manifest-size bounds are enforced during admission.

The reporter repeats `trusted_pr_evidence.py` before App-token minting and requires the same admitted ordinary CI run ID. Only after that fresh admission may it mint the dedicated App token and invoke `scripts/trusted_pr_control.py report` for final live PR/head/base/merge revalidation.

This path does not turn candidate CI into a trust root. Owner authorization, trusted default-branch verifier bytes, exact protected-object transitions, exact GitHub run/job/artifact metadata, digest-verified persisted evidence, fresh revalidation, App identity, and strict branch protection remain distinct authorities.

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

The routine automatic preflight is intentionally stricter: it protects that set plus `.gitattributes`, because versioned Git attributes can alter archive/build authority. A `.gitattributes` change is therefore ineligible for automatic trusted admission.

For automatic admission, **any** protected object-ID difference makes the PR ineligible. There is no automatic allowlist override.

For both explicit maintenance paths, `client_payload.protected_manifest` is a bounded JSON array. Each entry contains exactly:

```json
{"path":"tests","base_oid":"<40-hex-or-MISSING>","subject_oid":"<40-hex-or-MISSING>"}
```

Unknown paths, duplicates, malformed identities, omitted changes, extra changes, or stale object IDs fail closed. `MISSING` is used only when an exact Git observation successfully establishes absence.

An empty manifest means no manifest-root changes are authorized. A non-empty manifest is explicit owner authorization for exactly those object transitions; it is not independent proof that changed tests, workflow, or verifier bytes are correct.

## Trusted App and Environment contract

The dedicated GitHub App should be installed only where intended and granted only:

- Contents: read-only;
- Pull requests: read-only;
- Commit statuses: read and write; and
- no other repository/organization permissions unless a future reviewed requirement proves them necessary.

No webhook is required for this workflow design.

Environment `trusted-pr-gate` owns:

- variable `TRUSTED_GATE_APP_CLIENT_ID`;
- secret `TRUSTED_GATE_APP_PRIVATE_KEY`.

The private key must not be pasted into source, issue text, PR text, logs, artifacts, or chat. Environment deployment policy must restrict credential release to trusted default-branch execution. Candidate/merge refs must not receive this credential.

The reporter writes the private key only to a mode-restricted runner temporary file, removes it before continuing API use, masks the installation token, and requests only the narrow repository token permissions above.

## Native GitHub Actions authority

Ordinary PR CI is read-only and secret-free. The trusted automatic and evidence workflows keep native `GITHUB_TOKEN` authority read-only. They have no native `statuses: write` permission.

Status-write authority is obtained only by minting the separately scoped dedicated App token after final deterministic admission revalidation. Validation jobs and evidence admission never receive that App token or private key.

`pull_request_target` remains forbidden. Credentialed, destructive, publishing, deployment, load/stress, and other privileged jobs remain manual/environment-protected unless separately reviewed authority proves otherwise.

## Actions Policy boundary

Repository source can prove workflow trigger and permission contracts statically, but external Actions Policy decides whether events are actually permitted to start. The intended event policy includes:

- `pull_request` for ordinary development feedback;
- `workflow_run` for routine trusted automatic admission;
- owner `repository_dispatch` for `trusted-pr-validation` when full trusted candidate execution is appropriate;
- owner `repository_dispatch` for `trusted-pr-evidence-authorization` when exact ordinary-CI evidence promotion is the reviewed maintenance transition; and
- `workflow_dispatch` only for manual validation outside merge authority.

If external policy blocks an intended trusted event, that is an environment-owned **BLOCKED** state. Do not weaken repository admission checks to manufacture green.

## Merge-enforcement invariant

`Protect Main` must require:

- context `Trusted PR Gate`;
- expected source/integration equal to the dedicated ƳƤ Trusted PR Gate GitHub App, not GitHub Actions;
- strict/up-to-date required-status semantics;
- no bypass actors;
- pull-request review-thread resolution;
- merge commits as the repository's selected merge method;
- deletion and non-fast-forward protection.

The integration binding is critical. Requiring only the context string would reintroduce status-spoofing ambiguity.

## Validation subject and live revalidation

GitHub's read-only `refs/pull/<number>/merge` ref represents the prospective merge object for the current head/base pair. Every trusted admission path binds to an exact expected merge SHA and ordered parents.

Terminal reporting requires the PR to remain open and targeting `main`, current head/base to equal admitted values, the live merge ref to remain exact, the merge to retain exactly ordered parents `(base, head)`, and the final live re-read to remain unchanged. Any API failure, malformed response, missing ref, parent mismatch, head/base drift, closure, or final-read drift fails closed.

There is no retry after status publication and no generic retry of authorization/schema failures.

## Routine operation

For an ordinary owner same-repository PR with no protected-root changes:

1. ordinary `pull_request` CI produces exact development evidence;
2. successful CI wakes the default-branch `workflow_run` orchestrator;
3. live admission recomputes the PR/head/base/merge tuple and protected objects;
4. trusted YAML independently rechecks merge parents and protected authority before candidate execution;
5. all trusted validation domains must succeed;
6. the reporter repeats admission;
7. only then does it mint the dedicated App token and invoke final live subject revalidation;
8. independently observe App-sourced `Trusted PR Gate: success` on the exact head before merge.

A subject change requires new ordinary CI and new automatic trusted admission.

For a PR that changes any automatic protected root, automatic admission stops. Complete ordinary exact-head CI and adversarial review, derive the exact protected manifest, then use the explicit owner maintenance mechanism appropriate to the transition. A matrix/dependency authority change that cannot be re-executed correctly by the old default-branch workflow should use `trusted-pr-evidence-authorization`, not retain stale authority merely to satisfy the old graph.

## Bootstrap and evolution rule

A control-plane feature cannot authorize the same revision that introduces it unless an already-trusted path independently validates that revision. Each migration therefore requires an older trusted mechanism for its bootstrap, followed by post-merge live proof before the new path is treated as established environment authority.

This is why the evidence-authorization path itself was bootstrapped through the pre-existing full `trusted-pr-validation` path. After merge, later workflow/dependency migrations can use the evidence path only when their exact ordinary CI and artifact evidence satisfy the newly trusted default-branch verifier.

No historical bootstrap evidence proves a newer revision.

## Repository controls

`scripts/auto_trusted_preflight.py` performs bounded fail-closed live automatic admission. It does not mutate GitHub or publish status.

`scripts/auto_trusted_report.py` is a thin adapter that reuses `scripts/trusted_pr_control.py` for live subject resolution and App-backed status publication.

`scripts/trusted_pr_evidence.py` performs the protected-maintenance evidence admission described above. It is independently exact-byte frozen by `scripts/verify_ci_contract.py`.

`scripts/trusted_pr_control.py` remains the canonical exact-subject resolver for terminal status publication. It enforces bounded API ingestion, exact live PR identity, merge-ref/parent identity, final live re-read, exact-head publication, and nonzero exit after an authorized validation failure.

`scripts/ci_contract_base.py` preserves the hardened automatic CI contract. `scripts/ci_contract_trusted_auto.py` independently freezes and validates the automatic trusted workflow. `scripts/verify_ci_contract.py` orchestrates those contracts and independently freezes/validates `trusted-pr-evidence.yml` and `trusted_pr_evidence.py`.

The repository verifier cannot certify live GitHub App installation state, secret values, Environment branch policy, Actions Policy, or ruleset integration ID; those remain external observations.

## Evidence semantics

A green ordinary PR run proves the candidate's deterministic gates for that exact ordinary GitHub event subject. It is not merge authority.

A green automatic trusted validation proves the exact live prospective merge passed the routine trusted gate only when automatic admission remained eligible, protected roots were unchanged, and final revalidation remained identical.

A green full owner-dispatch validation proves the explicitly authorized prospective merge passed the deterministic repository gates executed under the trusted default-branch maintenance definition.

A green evidence-authorization run proves trusted default-branch code independently admitted exact successful ordinary CI, exact protected-object transitions, and digest-verified persisted build evidence bound to the authorized prospective merge without executing candidate bytes under privileged authority.

None is terminal merge authority unless the resulting `Trusted PR Gate` status came from the dedicated App integration required by the live strict ruleset and the PR subject remains current.

Blocked, failed, missing, stale, wrong-integration, unobserved, or protected-change-ineligible evidence is non-PASS truth.

---

[← CI/CD](CI_CD.md) · [Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
