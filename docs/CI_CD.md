# CI/CD and Repository Governance

> [!IMPORTANT]
> **Workflow definition, workflow execution, validation subject, status identity, and merge enforcement are separate authorities.** Ordinary `pull_request` CI remains exact-subject self-consistency evidence; it is not an independently trusted merge root while a pull request can edit the workflow and verifier that emit the same check name. This branch also implements a dormant default-branch `repository_dispatch` path for a future `Trusted PR Gate`, but that path is not merge authority until the reviewed definition is on `main`, external Actions Policy is active and observed, the trusted event is exercised, and repository merge enforcement is revalidated.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Supply chain](SUPPLY_CHAIN.md) · [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md) · [Operations](OPERATIONS.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Authority split

The repository separates ordinary validation, dormant trusted reporting, and manual credentialed validation:

| Surface | Trigger | Write/secret authority | Purpose |
|---|---|---|---|
| `.github/workflows/ci.yml` ordinary path | `pull_request`, `push` to `main`, `merge_group` | validation jobs are read-only and secret-free | deterministic repository gates for the exact GitHub event subject |
| `.github/workflows/ci.yml` dormant trusted path | fixed `repository_dispatch` type `trusted-pr-validation` | only `Trusted PR Gate Reporter` has `statuses: write` and the GitHub Actions run token | validate an exact prospective merge subject using the default-branch workflow definition, then revalidate the live PR before optional status publication |
| `.github/workflows/manual-validation.yml` | `workflow_dispatch` only | model step uses the `credentialed-validation` environment; Anthropic credential is step-scoped | repository-visible H-series readiness and optional credentialed Agent SDK evidence |

Top-level workflow permissions remain `contents: read`. Persisted checkout credentials are disabled everywhere. Dependency caching is forbidden in both automatic/trusted and manual workflows.

### Validation subject selection

`ci.yml` defines one explicit validation subject:

```text
CI_SUBJECT_SHA = repository_dispatch ? client_payload.expected_merge_sha : github.sha
```

For normal `pull_request`, `push`, and `merge_group` execution, the five validation jobs therefore retain the existing `github.sha` behavior. For a trusted `repository_dispatch`, the prospective merge SHA in `client_payload` is treated only as **untrusted subject data** and becomes the read-only validation checkout target.

Each of the five validation domains checks out `${{ env.CI_SUBJECT_SHA }}`, disables persisted credentials, and immediately requires `git rev-parse HEAD == CI_SUBJECT_SHA`. Wheel archives, build-manifest source identity, and runtime-container build context use the same `CI_SUBJECT_SHA`; they do not derive authority from mutable `HEAD`.

### Trusted reporter definition

The reporter is a sixth, separate checkout domain. It is eligible only when all of these are true:

- event is `repository_dispatch`;
- ref is exactly `refs/heads/main`;
- actor equals the repository owner.

Its job permissions are exactly `contents: read`, `pull-requests: read`, and `statuses: write`. The reporter checks out `${{ github.sha }}`, not `CI_SUBJECT_SHA`, and verifies `git rev-parse HEAD == GITHUB_SHA` before invoking the standard-library reporter helper. That separates the trusted reporter implementation subject from the untrusted prospective merge subject it validates.

The repository verifier requires the reporter to be the sole `statuses: write` owner and the sole consumer of `${{ secrets.GITHUB_TOKEN }}` in `ci.yml`.

---

## Automatic PR/main gate

The five validation domains are:

- CPython 3.11.16 and 3.13.15 quality/full deterministic pytest lanes;
- the fixed 34-case deterministic control evaluation;
- supply-chain, build-authority, documentation, Mermaid, runtime SBOM, reproducible-wheel, and container validation;
- Bandit, hash-locked dependency audit, and secret scanning;
- deterministic Playwright reference-SUT validation against the hosted image's existing Chrome runtime.

### Dependency and project-install authority

Before every automatic hash-locked dependency installation, `scripts/verify_build_authority.py` validates the exact reviewed lock-file set and bytes through bounded descriptor-relative no-follow ingestion. The verifier rejects symlink/special-file substitution, unexpected lock files, directory exhaustion, oversized inputs, and reviewed Git-blob drift. Every one of the five automatic `python -m pip install --require-hashes -r ...` sites is immediately bracketed by the reviewed build-authority check.

Immediately before every automatic `pip install --no-deps --no-build-isolation .`, the same verifier requires:

- exact static Hatchling build configuration;
- distribution name `ai-qa-automation`;
- sole console script `ai-qa = ai_qa_automation.cli:app`;
- no project GUI or additional project entry-point groups;
- fixed `README.md` and `LICENSE` file-valued inputs;
- no `license-files` expansion;
- bounded, symlink-free `src/ai_qa_automation` package authority;
- no installed `hatch` plugin entry point.

README/LICENSE are each capped at 2 MiB, each selected source file at 8 MiB, aggregate selected source bytes at 32 MiB, and package-tree ingestion at 1024 entries. These checks prevent project installation from silently replacing locked tool distributions, adding later-CI executable names, or expanding build/plugin authority while preserving verifier `PASS`.

### Browser authority

Automatic browser validation does **not** run `playwright install`, `--with-deps`, `sudo`, `apt-get`, or `apt install`. The job requires `/usr/bin/google-chrome` from the hosted `ubuntu-24.04` image, records its version, and uses only the narrow system-Chrome mode exposed by the repository browser probe.

The browser remains a hosted-runner input. Recording its observed version proves which executable the job used; it does not cryptographically attest the browser or promise that a later hosted image contains identical bytes.

### Exact workflow definition

After structural checks, `scripts/verify_ci_contract.py` binds the complete `ci.yml` bytes to the reviewed Git blob identity. This rejects accidental or unreviewed definition drift, including extra semantically equivalent installation commands.

For an ordinary PR run, that exact-blob check is still **in-subject self-consistency evidence**: a hostile pull request can in principle change both workflow and verifier unless an external GitHub control prevents PR-editable workflow execution from supplying merge authority. The dormant `repository_dispatch` design addresses workflow-definition provenance only after the reviewed workflow exists on the default branch and the external policy boundary is activated.

### Reproducible wheel and manifest subject

The reproducible-wheel step creates fresh random build directories plus a fresh bare Git view and empty template under `RUNNER_TEMP`. Git runs under a clean environment with reviewed replacement-object, lazy-fetch, optional-lock, config, and attribute controls. Both source archives name `$CI_SUBJECT_SHA`; extraction uses `/usr/bin/tar` under a clean environment.

Each archive root is independently passed through `verify_build_authority.py` immediately before its wheel build. The resulting `build-authority-archive-a.json` and `build-authority-archive-b.json` must be byte-identical. The build manifest receives the same `CI_SUBJECT_SHA` as its explicit expected source, and the two wheel outputs must be reproducibly identical under the repository contract.

### Runtime-container subject

The runtime-container build creates a separate fresh bare Git view/empty template rather than handing checkout `.` to Docker. It archives exact `$CI_SUBJECT_SHA` under the same clean Git authority and streams that tar directly to:

```text
docker build --tag "$image" -
```

Later worktree mutations and checkout-local `.dockerignore` or Git metadata therefore cannot silently retarget repository context. This binds repository bytes to the selected validation subject; it does not attest Docker/BuildKit, the hosted runner, registries, or container-image byte reproducibility.

### SBOM and documentation evidence

The runtime CycloneDX SBOM is generated from the hash-locked runtime graph. Its SHA-256 is exported by the parent step and revalidated before wheel generation, after wheel generation, and after build-manifest generation. A later build action cannot silently substitute a different structurally valid SBOM while preserving the reviewed lineage checks.

Documentation verification and pinned Mermaid rendering are unconditional required steps inside Supply Chain. Their JSON evidence is archived together with build authority, CI contract, SBOM, wheel, manifest/checksum, and container-image evidence.

---

## Stable aggregate check

The deterministic validation aggregate remains:

```text
Required PR Gate
```

It uses `if: ${{ always() }}`, depends on every validation domain, and succeeds only when each dependency result is `success`. A skipped, cancelled, timed-out, or failed prerequisite cannot be hidden by partial green when the reviewed definition is the workflow actually executing.

`Required PR Gate` remains useful repository validation evidence and is still the existing branch-policy interface during this prototype. It must **not** be described as independently trusted merge provenance while ordinary PR-editable workflow code can still produce it.

For the dormant trusted event, `Required PR Gate` is only an input to `Trusted PR Gate Reporter`. It does not itself gain write authority or become the terminal trusted status.

---

## Trusted PR Gate prototype

For event type `trusted-pr-validation`, GitHub's default-branch `repository_dispatch` semantics select the workflow definition from the repository default branch. The dispatch payload supplies:

- pull-request number;
- expected current head SHA;
- expected current base SHA;
- expected prospective merge SHA;
- explicit authorization boolean.

The read-only validation jobs execute the supplied prospective merge subject. The reporter executes trusted default-branch workflow code and invokes `scripts/trusted_pr_control.py`, which then re-fetches the pull request and requires:

- event remains `repository_dispatch`;
- ref is `refs/heads/main`;
- actor is the repository owner;
- pull request remains open and targets `main`;
- GitHub reports it definitively mergeable;
- current head/base/prospective-merge identities exactly match the dispatch payload.

Diagnostic runs do not publish status. An authorized successful aggregate publishes `Trusted PR Gate` success to the exact current PR head. An authorized non-success publishes failure and exits the reporter job nonzero.

This design is intentionally **dormant on the prototype branch**. The branch cannot use a default-branch-trusted workflow definition that has not yet been bootstrapped to `main`, and the connected tooling cannot certify the external Actions Policy prerequisite or issue the live `repository_dispatch`. See [`TRUSTED_PR_CONTROL_PLANE.md`](TRUSTED_PR_CONTROL_PLANE.md).

---

## Manual-only validation

`manual-validation.yml` remains `workflow_dispatch`-only and is not part of automatic PR merge evidence.

### Repository-visible H-series readiness

The H-series corpus is repository-visible and execution-separated from the routine primary evaluator. Manual execution preserves that separation without representing committed fixtures as blind or independently secret evidence.

### Credentialed model smoke

The Claude Agent SDK smoke path runs only when `run_model=true`. It references the `credentialed-validation` environment and requires `GITHUB_REF == refs/heads/main` before any credential-bearing step.

`ANTHROPIC_API_KEY` is step-scoped to the explicit credential check and bounded live Agent SDK evaluation. Checkout, revision verification, Python setup, and hash-locked project installation run without the provider credential.

GitHub environment protection remains an external fact. Missing credentials, provider outage, missing environment approval, or other external limitation is not converted into automatic PR PASS evidence.

### Cache boundary

Neither `ci.yml` nor `manual-validation.yml` enables `actions/setup-python` dependency caching. `scripts/verify_ci_contract.py` rejects `cache:` or `cache-dependency-path:` configuration in both workflow definitions. This prevents a future trusted/credentialed run from restoring cache state that could have been populated by untrusted execution.

---

## Deterministic workflow-policy verifier

Run:

```bash
python scripts/verify_ci_contract.py
```

The verifier fails closed unless the reviewed repository authority model remains intact. It requires, among other invariants:

- exactly `ci.yml` and `manual-validation.yml` as workflow YAML files;
- bounded descriptor-pinned no-follow workflow ingestion;
- `ci.yml` triggers exactly `pull_request`, `push`, `merge_group`, and fixed `repository_dispatch` type `trusted-pr-validation`;
- manual trigger exactly `workflow_dispatch`;
- top-level permissions exactly `contents: read`;
- no `pull_request_target`;
- no validation-domain secret use or write permissions;
- no automatic `playwright install`, `sudo`, `apt-get`, or `apt install` authority;
- no dependency cache configuration in automatic/trusted or manual workflows;
- immutable reviewed GitHub Action SHAs and exact Python patch versions;
- five validation checkouts bound to `CI_SUBJECT_SHA`, persisted credentials disabled, exact revision verified;
- one and only one trusted reporter checkout bound to `github.sha`, persisted credentials disabled, exact trusted revision verified;
- the fixed `repository_dispatch` subject selector using only `client_payload.expected_merge_sha` or `github.sha`;
- reporter condition requiring `repository_dispatch`, `refs/heads/main`, and repository-owner actor;
- reporter as the sole `statuses: write` permission owner and sole GitHub Actions token consumer;
- exact client-payload arguments to the reporter helper;
- exactly five reviewed automatic dependency-install sites with pre/post authority checks;
- exactly five reviewed project-install sites with immediate build-authority revalidation;
- complete `ci.yml` bytes equal to the reviewed Git blob identity;
- exact supply-chain build-authority, SBOM, reproducible-wheel, container-context, documentation, Mermaid, artifact-upload, and aggregate-gate definitions;
- both wheel archives, manifest expected source, and container build context bound to `CI_SUBJECT_SHA` rather than mutable `HEAD`.

The regression suite adversarially mutates these paths. Coverage includes trigger substitution, arbitrary repository-dispatch event types, client-payload subject bypass, `pull_request_target`, added write permission, validation secrets, second reporter token consumers, missing reporter owner/main guards, unbound validation/reporter checkouts, automatic/manual cache reintroduction, dependency/build authority removal/reordering, alternate project-install spellings, mutable archive/container subjects, Git replace/config/attribute authority, SBOM lineage, documentation/Mermaid fail-open behavior, artifact-upload weakening, and aggregate result-check corruption.

Repository tests and exact-workflow blob identity are strong reviewed-code controls; they are not an external trust anchor for themselves during ordinary PR execution.

---

## Repository settings and merge enforcement

Repository code can define workflow behavior, but it cannot prove current GitHub Actions Policy, environment protection, ruleset configuration, or required-check state. Those are separate external authorities and must be re-fetched when used as completion evidence.

During this prototype:

- `Required PR Gate` remains ordinary repository validation evidence;
- `Trusted PR Gate` is implemented in source but is **not yet an active protected merge authority**;
- PR #45 must remain non-authoritative until the trusted definition is bootstrapped to `main` and the external policy/dispatch/ruleset steps are performed and observed.

The intended activation sequence is:

1. validate and adversarially audit the repository source;
2. bootstrap the reviewed trusted definition to `main` through an explicitly audited revision;
3. configure and verify repository Actions Policy so ordinary PR-editable `pull_request` workflow execution cannot supply protected merge authority;
4. issue and inspect the fixed `trusted-pr-validation` `repository_dispatch` for an exact current PR subject;
5. verify `Trusted PR Gate` was produced by the trusted default-branch reporter after exact live subject revalidation;
6. only then update and re-fetch merge enforcement to require `Trusted PR Gate`.

Force-push/deletion protection, review-thread resolution, merge-queue use, and other repository settings remain platform configuration and must not be inferred from workflow source.

---

## Secrets and privileged authority

Ordinary validation jobs:

- have read-only repository authority;
- disable persisted checkout credentials;
- do not consume repository/provider secrets;
- do not own status/check write permission;
- cannot invoke privileged browser/OS installation through the reviewed definition.

The dormant reporter owns only the minimum additional authority needed for its role: pull-request read plus commit-status write, with the GitHub Actions run token scoped to that final step.

Credentialed Agent SDK execution remains manual, `main`-gated, environment-bound, and step-scoped.

This does not replace GitHub platform isolation, Actions Policy, environment protection, administrative identity trust, hosted-runner trust, or secure review.

---

## Release and deployment authority

This phase does not add package publishing, image registry publication, deployment, production mutation, signing keys, or destructive infrastructure authority.

A green validation run is not a release signature, deployment approval, or proof that a production environment changed.

---

## Evidence and non-claims

A green ordinary PR run can prove, for its exact PR event subject, that the reviewed source passed the executed deterministic gates and produced the persisted artifacts associated with that run. Supply-chain artifact presence alone is not terminal authority; failure-path uploads may contain partial diagnostics, so job conclusions and the aggregate gate still matter.

Ordinary green CI does **not** by itself prove:

- external Actions Policy is active;
- the trusted workflow definition exists on `main`;
- a `repository_dispatch` trusted run occurred;
- `Trusted PR Gate` was published or required by merge policy;
- the current GitHub ruleset/environment settings match an older observation;
- hosted runner/Chrome bytes are immutable or cryptographically attested;
- provider credentials or external services are available;
- a release or deployment occurred.

Finding 13 therefore remains an explicit environment/bootstrap boundary until the trusted path and external merge-policy controls are activated and observed.

---

[← Supply chain](SUPPLY_CHAIN.md) · [Trusted PR control plane →](TRUSTED_PR_CONTROL_PLANE.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
