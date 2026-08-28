# CI/CD and Repository Governance

> [!IMPORTANT]
> **Workflow definition, workflow execution, validation subject, status identity, and merge enforcement are separate authorities.** The activated merge path relies on a default-branch `repository_dispatch` workflow, exact-subject deterministic validation, live PR/merge-ref revalidation, `Trusted PR Gate` status publication, and strict protected-branch enforcement. Repository source cannot self-attest the external GitHub Actions Policy or ruleset; those remain separately observed platform authorities.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Supply chain](SUPPLY_CHAIN.md) · [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md) · [Operations](OPERATIONS.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Authority split

The repository separates validation, terminal trusted reporting, and credentialed/manual workflows:

| Surface | Committed trigger | Write/secret authority | Role under the activated policy |
|---|---|---|---|
| `.github/workflows/ci.yml` validation path | `pull_request`, `push` to `main`, `merge_group`, fixed `repository_dispatch` type `trusted-pr-validation` | validation jobs are read-only and secret-free | deterministic gates for the selected exact subject; under the observed external policy only the trusted `repository_dispatch` execution path is allowed |
| `.github/workflows/ci.yml` trusted reporter | eligible only for trusted `repository_dispatch` on `refs/heads/main` by repository owner | sole `statuses: write` owner and sole GitHub Actions token consumer | live PR/merge-ref revalidation and terminal `Trusted PR Gate` publication |
| `.github/workflows/manual-validation.yml` | `workflow_dispatch` only | model step uses the `credentialed-validation` environment; provider credential is step-scoped | unavailable while the same protected GitHub Actions identity is externally restricted to `repository_dispatch` only, unless a separately trusted execution identity/mechanism is introduced |

Top-level workflow permissions remain `contents: read`. Persisted checkout credentials are disabled. Dependency caching is forbidden in both automatic/trusted and manual workflows.

The workflow trigger list describes repository source, not external execution permission. The observed active Actions Policy is stronger: actor is restricted to the repository owner and `repository_dispatch` is the sole allowed event for this GitHub Actions identity. Ordinary PR/push/merge-group execution is therefore expected to be rejected at startup while that policy remains active.

This default-branch-definition-only boundary is essential because denying only `pull_request` would leave other feature-ref-defined event classes capable of selecting feature-controlled workflow bytes under the same integration identity.

## Validation subject selection

`ci.yml` defines one explicit validation subject:

```text
CI_SUBJECT_SHA = repository_dispatch ? client_payload.expected_merge_sha : github.sha
```

For the trusted `repository_dispatch`, the prospective merge SHA in `client_payload` is **untrusted subject data**. It selects only the read-only validation checkout target; it does not select reporter code or authorize status publication.

Each of the five validation domains:

- checks out `${{ env.CI_SUBJECT_SHA }}`;
- disables persisted checkout credentials;
- requires `git rev-parse HEAD == CI_SUBJECT_SHA` before execution.

Wheel archives, build-manifest source identity, SBOM lineage, and runtime-container build context use the same subject rather than mutable `HEAD`.

## Trusted subject preflight

For `repository_dispatch`, the supply-chain job performs an inline trusted preflight before repository scripts execute. It requires:

- full-hex expected merge/head/base SHAs;
- `GITHUB_SHA` equal to the dispatched expected base SHA;
- the prospective merge commit to have ordered parents `(expected_base, expected_head)`;
- protected control-plane path identities in the prospective merge to match the trusted default-branch revision.

The protected-path comparison prevents a trusted dispatch from executing candidate-controlled changes to the workflow/control-plane authority before those changes have first been intentionally bootstrapped to `main`.

## Trusted reporter definition

The reporter is a separate checkout/authority domain. It is eligible only when:

- event is `repository_dispatch`;
- ref is exactly `refs/heads/main`;
- actor equals the repository owner.

Its job permissions are exactly the minimum required role: `contents: read`, `pull-requests: read`, and `statuses: write`.

The reporter:

1. checks out `${{ github.sha }}` from the trusted default branch, not `CI_SUBJECT_SHA`;
2. disables persisted credentials;
3. verifies the checkout equals `GITHUB_SHA`;
4. invokes `scripts/trusted_pr_control.py` with the dispatch subject and deterministic aggregate result;
5. publishes status only after live exact-subject revalidation.

The helper verifies the live PR identity plus GitHub's `refs/pull/<number>/merge` object and exact merge parents, then repeats the live PR/ref read immediately before status publication. A mismatch, missing/malformed object, closure, drift, API failure, or authorization failure fails closed.

---

## Deterministic validation domains

The five validation domains are:

- CPython 3.11.16 and 3.13.15 quality/full deterministic pytest lanes;
- the fixed 34-case deterministic control evaluation;
- supply-chain, build-authority, documentation, Mermaid, runtime SBOM, reproducible-wheel, and container validation;
- Bandit, hash-locked dependency audit, and secret scanning;
- deterministic Playwright reference-SUT validation against the hosted image's existing Chrome runtime.

### Dependency and project-install authority

Before every automatic hash-locked dependency installation, `scripts/verify_build_authority.py` validates the exact reviewed lock-file set and bytes through bounded descriptor-relative no-follow ingestion. It rejects symlink/special-file substitution, unexpected lock files, directory exhaustion, oversized inputs, and reviewed Git-blob drift.

Every automatic `python -m pip install --require-hashes -r ...` site is bracketed by the reviewed build-authority check. Immediately before every automatic `pip install --no-deps --no-build-isolation .`, the same verifier requires:

- exact static Hatchling build configuration;
- distribution name `ai-qa-automation`;
- sole console script `ai-qa = ai_qa_automation.cli:app`;
- no project GUI or additional project entry-point groups;
- fixed `README.md` and `LICENSE` file-valued inputs;
- no `license-files` expansion;
- bounded, symlink-free `src/ai_qa_automation` package authority;
- no installed `hatch` plugin entry point.

README/LICENSE are each capped at 2 MiB, each selected source file at 8 MiB, aggregate selected source bytes at 32 MiB, and package-tree ingestion at 1024 entries.

### Browser authority

Automatic browser validation does **not** run `playwright install`, `--with-deps`, `sudo`, `apt-get`, or `apt install`. It requires hosted `/usr/bin/google-chrome`, records its version, and uses the narrow system-Chrome reference-SUT mode.

The hosted browser remains an environment input. Observing its version does not cryptographically attest those bytes or promise later runner-image equivalence.

### Exact workflow definition

`scripts/verify_ci_contract.py` structurally freezes the reviewed `ci.yml` authority model and binds complete workflow bytes to the reviewed Git blob identity. That is strong source self-consistency evidence; it is not a substitute for the external Actions Policy that prevents candidate-controlled workflow definitions from executing under the protected identity.

### Reproducible wheel and manifest subject

The reproducible-wheel step creates fresh source directories plus an isolated bare Git view. Git runs with reviewed replacement-object/config/attribute controls. Both archives name `$CI_SUBJECT_SHA`, and each extracted archive is independently passed through build-authority verification immediately before wheel construction.

The build manifest receives the same explicit expected source. The two wheel outputs must be byte-identical under the repository reproducibility contract.

### Runtime-container subject

The runtime-container build creates an isolated Git view and streams an archive of exact `$CI_SUBJECT_SHA` directly to Docker rather than using mutable checkout `.` as build context.

This binds repository context to the selected validation subject. It does not attest Docker/BuildKit, the hosted runner, registries, or container-image byte reproducibility.

### SBOM and documentation evidence

The runtime CycloneDX SBOM is generated from the hash-locked runtime graph. Its SHA-256 is revalidated across later build-manifest/wheel steps so a later action cannot silently substitute a different structurally valid SBOM while preserving lineage checks.

Documentation verification and digest-pinned Mermaid rendering are unconditional Supply Chain steps. Their evidence is archived together with build authority, CI contract, SBOM, wheel, manifest/checksum, and container-image evidence.

---

## Deterministic aggregate versus protected status

The internal aggregate remains:

```text
Required PR Gate
```

It uses `if: ${{ always() }}`, depends on every validation domain, and succeeds only when each dependency result is `success`. A skipped, cancelled, timed-out, or failed prerequisite therefore cannot be hidden by partial green under the reviewed workflow definition.

`Required PR Gate` is **validation evidence**, not protected merge authority. The activated `Protect Main` ruleset no longer requires it.

The reporter consumes that deterministic aggregate and, only after live subject revalidation, publishes:

```text
Trusted PR Gate
```

`Trusted PR Gate` is the protected merge status in the observed activated ruleset.

---

## Activated trusted PR path

For event type `trusted-pr-validation`, GitHub's `repository_dispatch` semantics select the workflow definition from the repository default branch. The dispatch payload supplies:

- pull-request number;
- expected current head SHA;
- expected current base SHA;
- expected prospective merge SHA;
- explicit authorization boolean.

The read-only validation jobs execute the supplied prospective merge subject. The reporter executes trusted default-branch code and publishes only after verifying:

- fixed event/ref/owner admission;
- PR remains open and targets `main`;
- exact live PR number/head/base identity;
- exact `refs/pull/<number>/merge` ref identity and commit type;
- merge ref equals the dispatched expected merge SHA;
- merge commit has exactly two ordered parents `(base, head)`;
- a second live PR/ref read still matches immediately before status publication.

Diagnostic runs never publish status. Authorized failed validation publishes failure and exits nonzero. Authorized success publishes `Trusted PR Gate` success to the exact current head.

### Base drift and strict enforcement

A head update changes the status subject naturally. A base update can leave the head SHA unchanged while changing the prospective merge.

The observed `Protect Main` ruleset therefore keeps `strict_required_status_checks_policy = true`. GitHub must require the PR to be up to date/revalidated rather than accept an old head-bound trusted status for a different prospective merge subject.

---

## Activated external governance

The external activation evidence established:

- repository Actions Policy active;
- actor restricted to repository owner;
- only `repository_dispatch` allowed;
- ordinary `pull_request` probes rejected at startup;
- owner trusted dispatch run #634 executed workflow revision `fc95c3554853d3b9b50a788e7bcfd10257637126` from `main`;
- trusted preflight and every validation domain succeeded for exact merge subject `15139baa4e1537eb37db328e32f654e27e3e1ac2`;
- `Trusted PR Gate Reporter` succeeded and published to exact head `5dadafe85c0bc2710672963dcf220186b88f812d`;
- independent status read returned `Trusted PR Gate: success` targeting run #634 from GitHub Actions integration `15368`;
- ruleset `Protect Main` was transitioned and re-fetched with `Trusted PR Gate` as the sole required status, strict/up-to-date enabled, and no bypass actors.

These are observed external facts. Repository source cannot prove they remain unchanged after a future administrative mutation.

## Normal PR validation procedure

While the external policy remains `repository_dispatch`-only, ordinary automatic PR workflow execution is intentionally unavailable. A protected PR is validated as follows:

1. read current PR number/head/base;
2. read `refs/pull/<number>/merge` and verify its merge commit parents `(base, head)`;
3. issue owner-authorized `repository_dispatch` event `trusted-pr-validation` with that exact tuple;
4. inspect the exact trusted run and artifacts;
5. require every deterministic validation domain and `Required PR Gate` to succeed;
6. require the trusted reporter to succeed;
7. independently verify `Trusted PR Gate: success` on the exact head;
8. re-read the PR subject before merge;
9. rely on strict protected-branch enforcement to reject stale-base evidence.

Any head/base/merge-subject change requires a new trusted dispatch.

---

## Manual-only validation

`manual-validation.yml` remains `workflow_dispatch`-only and is not part of protected merge evidence.

Because `workflow_dispatch` can be ref-selectable under the same GitHub Actions identity, the observed `repository_dispatch`-only policy prevents this workflow from executing while the protected identity invariant is active. Credentialed model validation therefore requires a separately trusted identity/mechanism or a deliberate policy change with equivalent default-branch-definition provenance controls; it must not be enabled by casually widening the protected identity's event allow-list.

The Claude Agent SDK smoke path itself remains environment-bound and step-scoped when executable. Missing credentials, provider outage, missing environment approval, or other external limitations are not converted into automatic PASS evidence.

---

## Deterministic workflow-policy verifier

Run:

```bash
python scripts/verify_ci_contract.py
```

The verifier fails closed unless the reviewed repository authority model remains intact. Among other invariants it requires:

- exactly the reviewed automatic/manual workflow files;
- bounded no-follow workflow ingestion;
- `ci.yml` trigger contract including fixed `repository_dispatch` type `trusted-pr-validation`;
- no `pull_request_target`;
- read-only top-level permissions;
- no validation-domain secret use or write permissions;
- no automatic browser/OS installation authority;
- no dependency-cache configuration;
- immutable reviewed Action SHAs and exact Python patch versions;
- five validation checkouts bound to `CI_SUBJECT_SHA` with persisted credentials disabled;
- one trusted reporter checkout bound to `github.sha`;
- reporter owner/main/event guards;
- sole reporter `statuses: write` and token authority;
- exact client-payload arguments to the reporter helper;
- reviewed dependency/project-install counts and authority brackets;
- exact supply-chain, SBOM, reproducible-wheel, container-context, documentation, Mermaid, artifact-upload, and aggregate definitions;
- complete `ci.yml` bytes equal to the reviewed Git blob identity.

The verifier intentionally cannot attest the live Actions Policy allow-list or current ruleset. Those remain externally observed authorities.

---

## Repository settings and merge enforcement

The observed activated `Protect Main` ruleset has:

- enforcement active on the default branch;
- deletion protection;
- non-fast-forward protection;
- pull requests required;
- review-thread resolution required;
- merge commits as the allowed merge method;
- strict/up-to-date required-status semantics;
- sole required status `Trusted PR Gate` from GitHub Actions integration `15368`;
- no bypass actors and `current_user_can_bypass = never`.

This repository configuration, together with the active external execution policy and trusted status path, closes the same-integration workflow-provenance boundary for the observed state. Any material administrative change to those authorities requires a fresh observation and exact-subject validation before equivalent assurance can be claimed.

---

## Secrets and privileged authority

Validation jobs:

- have read-only repository authority;
- disable persisted checkout credentials;
- do not consume provider/repository secrets;
- do not own terminal status-write permission;
- cannot invoke privileged browser/OS installation through the reviewed definition.

The reporter owns only the minimum additional authority needed for its role: PR read plus commit-status write. Model/provider credentials are not part of the trusted reporter path.

This design does not replace GitHub platform isolation, Actions Policy, administrative identity trust, hosted-runner trust, environment protection, or secure review.

---

## Release and deployment authority

This phase does not add package publishing, image registry publication, deployment, production mutation, signing keys, or destructive infrastructure authority.

A green validation run or `Trusted PR Gate` is not a release signature, deployment approval, or proof that a production environment changed.

---

## Evidence and non-claims

A successful trusted run can prove that the dispatched exact prospective merge subject passed the executed deterministic gates and that the trusted default-branch reporter published status only after the live subject checks described above.

It does **not** prove:

- the Actions Policy or ruleset will remain unchanged after the last observation;
- hosted runner/Chrome bytes are immutable or cryptographically attested;
- package publisher identity;
- provider credentials or external services are available;
- a release or deployment occurred;
- committed repository-visible evaluation cases are blind holdouts;
- unsigned build evidence is signed provenance.

Historical ordinary PR greens prove only their historical exact subjects. Historical failed trusted runs prove fail-closed behavior, not terminal PASS. Blocked/unexecuted/unobserved work remains non-PASS truth.

---

[← Supply chain](SUPPLY_CHAIN.md) · [Trusted PR control plane →](TRUSTED_PR_CONTROL_PLANE.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).