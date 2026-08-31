# CI/CD and Repository Governance

> [!IMPORTANT]
> **Workflow definition, workflow execution, validation subject, status identity, and merge enforcement are separate authorities.** Ordinary pull-request CI is development evidence. Protected merge authority requires a trusted default-branch dispatch, exact-subject validation, live PR/merge-ref revalidation, and `Trusted PR Gate` publication by an independent GitHub App identity. Repository source cannot self-attest the live App installation, Environment protection, Actions Policy, or ruleset binding.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Supply chain](SUPPLY_CHAIN.md) · [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md) · [Operations](OPERATIONS.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Authority split

The repository separates automatic validation, terminal trusted reporting, and credentialed/manual workflows:

| Surface | Committed trigger | Repository-owned authority | Intended role |
|---|---|---|---|
| `.github/workflows/ci.yml` validation path | `pull_request`, `push` to `main`, `merge_group`, fixed `repository_dispatch` type `trusted-pr-validation` | validation jobs are read-only and secret-free | deterministic development feedback for ordinary events and exact-subject validation for trusted dispatch |
| `.github/workflows/ci.yml` trusted reporter | eligible only for owner `repository_dispatch` on `refs/heads/main` | GitHub Actions token remains read-only; reporter mints a narrowly scoped dedicated GitHub App installation token from Environment-protected credentials | live PR/merge-ref revalidation and terminal `Trusted PR Gate` publication |
| `.github/workflows/manual-validation.yml` | `workflow_dispatch` only | model step uses the `credentialed-validation` environment; provider credential is step-scoped | optional H-series/model evidence; never protected merge authority |

Top-level automatic-workflow permissions remain exactly `contents: read`. Persisted checkout credentials are disabled. Dependency caching is forbidden in automatic/trusted and manual workflows.

Ordinary `pull_request` execution is intentionally useful but cannot certify merge by itself. A pull request controls its candidate workflow bytes, so its green result is **in-subject validation evidence**, not an independent trust root. The protected status identity is therefore separated from the native GitHub Actions identity: a PR workflow must not possess the GitHub App private key or be accepted as the required `Trusted PR Gate` source.

---

## Validation subject selection

`ci.yml` defines one explicit validation subject:

```text
CI_SUBJECT_SHA = repository_dispatch ? client_payload.expected_merge_sha : github.sha
```

For ordinary GitHub events, `github.sha` is the event subject. For the trusted `repository_dispatch`, the prospective merge SHA in `client_payload` is **untrusted subject data**: it selects only what the read-only validation jobs inspect. It does not select reporter code, grant credential access, or authorize status publication.

Each of the five validation domains:

- checks out `${{ env.CI_SUBJECT_SHA }}`;
- disables persisted checkout credentials;
- requires `git rev-parse HEAD == CI_SUBJECT_SHA` before project execution.

Wheel archives, build-manifest source identity, SBOM lineage, and runtime-container build context use that same exact subject rather than mutable `HEAD`.

---

## Trusted dispatch preflight

For `repository_dispatch`, the Supply Chain job executes a trusted inline preflight before repository scripts run. It requires:

- exact expected merge/head/base identity supplied by the owner-authorized dispatch;
- `GITHUB_SHA` equal to the expected base SHA, binding the workflow definition to the current default branch;
- the prospective merge commit to have exactly two ordered parents `(expected_base, expected_head)`;
- protected control-plane changes to match an explicit bounded object-ID manifest.

### Exact protected-path maintenance manifest

Legitimate maintenance must be possible without silently converting any candidate control-plane change into trusted authority. The preflight therefore compares protected root identities between trusted `GITHUB_SHA` and the prospective merge subject. If a protected root changes, the owner dispatch must supply an entry containing exactly:

```text
path
base_oid
subject_oid
```

The manifest is accepted only when:

- it is a JSON array within the bounded protected-root set;
- every entry contains exactly `path`, `base_oid`, and `subject_oid`;
- paths are known and non-duplicated;
- each object identity is a full 40-hex Git object ID or the explicit `MISSING` sentinel;
- normalized supplied entries equal the complete observed set of protected-root object changes.

An empty manifest therefore authorizes **no protected changes**. A partial, stale, over-broad, malformed, or wrong-object manifest fails closed.

This mechanism is an explicit owner trust transition. It binds authorization to the exact reviewed base/subject object identities; it does **not** prove that changed workflow, test, dependency, or verifier bytes are intrinsically correct. Exact-revision CI, adversarial review, and external control-plane validation remain required.

---

## Trusted reporter and independent status identity

The `trusted-status` job is a separate authority domain. It is eligible only when all of the following are true:

- event is `repository_dispatch`;
- ref is exactly `refs/heads/main`;
- actor equals the repository owner;
- the job can enter Environment `trusted-pr-gate`.

Its GitHub Actions job permissions are only:

```text
contents: read
```

The native `GITHUB_TOKEN` is not used to publish `Trusted PR Gate`.

The reporter:

1. checks out `${{ github.sha }}` from the trusted default branch, not `CI_SUBJECT_SHA`;
2. disables persisted checkout credentials;
3. verifies the checkout equals `GITHUB_SHA`;
4. receives the dedicated App client ID and private key only through Environment `trusted-pr-gate`;
5. constructs a short-lived GitHub App JWT and exchanges it for the repository installation token;
6. requests only `contents: read`, `pull_requests: read`, and `statuses: write` on that installation token;
7. masks the installation token before passing it to `scripts/trusted_pr_control.py`;
8. invokes the existing reporter helper with the exact dispatched PR/head/base/merge identity and deterministic aggregate result.

`scripts/trusted_pr_control.py` then revalidates the live open PR, exact head/base, `refs/pull/<number>/merge`, merge commit type, and exactly ordered merge parents. It repeats the live PR/ref read immediately before status publication to narrow the final TOCTOU window. A mismatch, closure, API failure, malformed object, or subject drift fails closed.

The dedicated App identity matters because the protected ruleset must bind `Trusted PR Gate` to that App integration, not to GitHub Actions. Automatic PR workflows may then run for feedback without acquiring the identity that can satisfy the protected status requirement.

---

## Environment-owned activation requirements

Repository source defines the intended boundary but cannot prove the corresponding platform configuration is active. Before the independent reporter can be treated as merge authority, the external environment must establish and independently observe all of these facts:

- a dedicated GitHub App exists for the trusted reporter;
- the App is installed only where intended, including this repository;
- its installation permissions are no broader than required: repository contents read, pull requests read, commit statuses write, plus GitHub-required metadata read;
- Environment `trusted-pr-gate` exists and is restricted so candidate/feature refs cannot receive its credentials;
- Environment variable `TRUSTED_GATE_APP_CLIENT_ID` identifies the intended App;
- Environment secret `TRUSTED_GATE_APP_PRIVATE_KEY` contains the App private key and is not repository-visible data;
- the repository ruleset requires `Trusted PR Gate` from the **dedicated App integration**;
- required-status semantics remain strict/up-to-date;
- no bypass actor silently circumvents the protected status;
- the Actions Policy admits the intended ordinary read-only PR feedback plus owner trusted dispatch while preserving the separate App credential boundary.

Until those external facts are configured and observed, source support for the independent App is **designed but not activated merge authority**.

---

## Deterministic validation domains

The five automatic validation domains remain:

- exact CPython 3.11.16 full-quality validation plus exact CPython 3.14.7 deterministic compatibility validation; Python 3.11 owns Ruff, strict Mypy, full deterministic pytest, and coverage, while Python 3.14 runs compile plus the full deterministic compatibility pytest suite without duplicating lint/type/coverage authority;
- the fixed 34-case deterministic control evaluation;
- supply-chain, build-authority, documentation, Mermaid, runtime SBOM, reproducible-wheel, and container validation;
- Bandit, hash-locked dependency audit, and secret scanning;
- deterministic Playwright reference-SUT validation against hosted Chrome.

### Dependency and project-install authority

Before every automatic hash-locked dependency installation, `scripts/verify_build_authority.py` validates the reviewed lock-file set and bytes through bounded descriptor-relative no-follow ingestion. Every automatic `python -m pip install --require-hashes -r ...` site is bracketed by that authority check, and every project install is immediately preceded by build-authority revalidation.

The build-authority verifier also constrains static build metadata, selected source/package-tree shape, file/resource bounds, project entry points, and Hatch plugin authority. See [Supply-Chain Integrity](SUPPLY_CHAIN.md).

### Browser authority

Automatic browser validation does **not** run `playwright install`, `--with-deps`, `sudo`, `apt-get`, or `apt install`. It requires hosted `/usr/bin/google-chrome`, records its version, and runs only the deterministic localhost reference SUT. The hosted browser remains an environment input rather than a cryptographically attested repository asset.

### Exact workflow definition

`scripts/verify_ci_contract.py` structurally constrains the reviewed `ci.yml` authority model and binds complete workflow bytes to the reviewed Git blob identity. It verifies the trigger/subject model, validation checkout binding, read-only native token authority, trusted Environment/App-token structure, protected-manifest contract, required aggregate, quality-lane split, and supply-chain execution definition.

That is source self-consistency evidence. It cannot attest the live Environment restriction, App installation, Actions Policy, or ruleset expected-source binding.

---

## Deterministic aggregate versus protected status

The internal aggregate remains:

```text
Required PR Gate
```

It uses `if: ${{ always() }}`, depends on every validation domain, and succeeds only when each dependency result is `success`. A skipped, cancelled, timed-out, or failed prerequisite therefore cannot be hidden by partial green under the reviewed workflow definition.

`Required PR Gate` is validation evidence, not protected merge authority.

The trusted reporter consumes that aggregate and, only after live subject revalidation, publishes:

```text
Trusted PR Gate
```

After the independent-identity migration is activated, the branch ruleset must require this context from the dedicated GitHub App integration. A same-named status from GitHub Actions or another identity must not satisfy the protected rule.

---

## Historical activation evidence

Before the independent-App migration, the repository activated an earlier protected path in which the external Actions Policy admitted only owner `repository_dispatch`, and `Trusted PR Gate` was published by GitHub Actions itself.

For disposable probe PR #50, historical evidence showed:

- ordinary `pull_request` startup was rejected by the then-active external policy;
- owner trusted dispatch run #634 executed the workflow definition from trusted `main`;
- supply chain, security, the 34-case deterministic evaluator, Playwright reference SUT, Python 3.11.16, Python 3.13.15, and `Required PR Gate` succeeded;
- the reporter revalidated the exact PR/merge subject and published `Trusted PR Gate: success`;
- independent status readback identified GitHub Actions integration ID `15368` as the status source;
- `Protect Main` was then observed with `Trusted PR Gate` required, strict/up-to-date semantics enabled, and no bypass actors.

Those observations remain valid **historical evidence for that earlier control plane**. They do not prove that a future dedicated App, Environment restriction, ruleset binding, or Actions Policy state is configured correctly. The independent-identity migration requires its own live evidence.

---

## Normal operation after independent-identity activation

A normal pull request has two distinct evidence paths.

### Automatic development feedback

1. `pull_request` starts ordinary CI automatically.
2. Validation jobs execute the exact GitHub event subject with read-only native token authority and no reporter App credential.
3. `Required PR Gate` may summarize those validation jobs.
4. This green is useful development evidence, but it is **not merge authority**.

### Protected merge validation

1. read current PR number, head SHA, base SHA, and live `refs/pull/<number>/merge` SHA;
2. verify the merge commit has exactly ordered parents `(base, head)`;
3. derive the exact protected-root object manifest, empty when no protected root changes;
4. issue owner-authorized `repository_dispatch` event `trusted-pr-validation` with that exact tuple and explicit authorization;
5. require the trusted preflight and every deterministic validation domain to succeed for the prospective merge subject;
6. require `Required PR Gate` to succeed;
7. require the main-only reporter to mint the dedicated App token and complete live subject revalidation;
8. independently read `Trusted PR Gate: success` from the required dedicated App integration on the exact current head;
9. re-read the PR head/base/merge subject immediately before merge;
10. rely on strict/up-to-date protected-branch enforcement to reject stale-base evidence.

Any head/base/merge-subject change requires a new trusted dispatch. A prior automatic green or trusted status never certifies newer bytes or a different prospective merge.

---

## Manual-only validation

`manual-validation.yml` remains `workflow_dispatch`-only and outside protected merge evidence. Repository-visible H-series readiness and the credentialed Claude Agent SDK smoke path are separate evidence classes.

When the model smoke is executable, `ANTHROPIC_API_KEY` remains scoped to its selected credentialed job. Missing credentials, provider outage, missing Environment approval, or other external limitations remain blocked/unavailable facts rather than automatic PASS.

Manual evidence does not acquire `Trusted PR Gate` authority merely by succeeding.

---

## Deterministic workflow-policy verifier

Run:

```bash
python scripts/verify_ci_contract.py
```

The verifier fails closed unless the reviewed repository authority model remains intact. Among other invariants it requires:

- exactly the reviewed automatic/manual/trusted-auto workflow files;
- bounded no-follow workflow ingestion;
- fixed `pull_request`, `push`, `merge_group`, and `trusted-pr-validation` trigger contract;
- no `pull_request_target`;
- read-only top-level/native reporter permissions;
- no validation-domain secret use or write permissions;
- no native `GITHUB_TOKEN` use for terminal status publication;
- exactly one trusted App private-key/client-ID consumer in the main-only reporter;
- exact protected-manifest comparison structure;
- immutable reviewed Action SHAs and exact Python patch versions;
- the exact Python 3.11 full-quality / Python 3.14 compatibility lane split;
- five validation checkouts bound to `CI_SUBJECT_SHA` and one separate reporter checkout bound to `github.sha`;
- reporter owner/main/event guards;
- reviewed dependency/project-install authority brackets;
- supply-chain, SBOM, reproducible-wheel, container-context, documentation, Mermaid, evidence-upload, and deterministic aggregate controls;
- complete `ci.yml` bytes equal to the reviewed Git blob identity.

The verifier intentionally cannot attest live GitHub administrative state.

---

## Merge-enforcement invariant

The protected-branch contract is:

- pull requests required for `main`;
- strict/up-to-date required-status semantics;
- review-thread resolution and configured merge-method restrictions preserved;
- no persistent bypass actor;
- `Trusted PR Gate` required from the intended **dedicated GitHub App integration** after migration.

Strict/up-to-date enforcement is essential because a base update can change the prospective merge while leaving the PR head SHA unchanged. The trusted reporter publishes to the head only after validating a specific `(base, head, merge)` tuple; branch protection must reject reuse of that status after base drift.

Repository source cannot self-attest that this ruleset is active. Re-fetch it after any material administrative mutation and immediately before relying on it for merge.

---

## Secrets and privileged authority

Automatic validation jobs:

- have read-only repository authority;
- disable persisted checkout credentials;
- consume no provider/reporter secrets;
- do not own terminal status-write permission;
- cannot invoke privileged browser/OS installation through the reviewed definition.

The trusted reporter's **native GitHub Actions token remains read-only**. Commit-status write authority belongs to the short-lived dedicated App installation token, whose private key must be released only through Environment `trusted-pr-gate` under the externally enforced trusted-ref restriction.

This design does not replace GitHub platform isolation, administrative identity trust, Environment protection, secret management, or secure review.

---

## Release and deployment authority

This control plane does not add package publishing, image registry publication, deployment, production mutation, signing keys, or destructive infrastructure authority.

A green automatic run, trusted validation run, or `Trusted PR Gate` is not a release signature, deployment approval, or proof that a production environment changed.

---

## Evidence semantics

A green ordinary PR run proves only the executed candidate workflow and selected exact GitHub event subject satisfied those deterministic checks. It does not prove independent workflow-definition provenance or terminal merge authority.

A green trusted validation aggregate proves the dispatched prospective merge subject passed the executed deterministic repository gates, provided the default-branch preflight admitted that exact subject and protected manifest. It does not prove terminal authority unless the reporter also successfully revalidates the live PR/merge ref and publishes `Trusted PR Gate` through the required App identity.

A `Trusted PR Gate` success is merge-authority evidence only when its source identity, exact subject, strict/up-to-date ruleset, Environment/App configuration, and no-bypass assumptions still match the independently observed external configuration.

Blocked, failed, missing, stale, historical-only, or unobserved evidence remains non-PASS truth.

---

[← Supply chain](SUPPLY_CHAIN.md) · [Trusted PR control plane →](TRUSTED_PR_CONTROL_PLANE.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
