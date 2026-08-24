# CI/CD and Repository Governance

> [!IMPORTANT]
> **Workflow definitions, workflow execution, and repository merge enforcement are different authorities.** Automatic CI can produce exact-subject evidence and a stable aggregate gate; GitHub branch protection or rulesets must separately require that gate before merges are technically blocked.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Supply chain](SUPPLY_CHAIN.md) · [Operations](OPERATIONS.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Authority split

The repository deliberately separates ordinary automatic validation from manually authorized validation:

| Surface | Trigger | Secret authority | Purpose |
|---|---|---|---|
| `.github/workflows/ci.yml` | `pull_request`, `push` to `main`, `merge_group` | none | automatic non-privileged repository gates |
| `.github/workflows/manual-validation.yml` | `workflow_dispatch` only | model job references the `credentialed-validation` environment; Anthropic secret is step-scoped | H-series readiness and optional credentialed Agent SDK evidence |

Both workflows declare only `contents: read`. Every checkout disables persisted credentials, binds to `${{ github.sha }}`, and immediately verifies that `git rev-parse HEAD` equals `GITHUB_SHA`.

For a normal pull-request event, `github.sha` is GitHub's prospective merge subject rather than merely the feature-branch head. A green PR run therefore proves the tested event subject, not an arbitrary nearby commit.

---

## Automatic PR/main gate

The automatic workflow runs these repository-owned gates:

- CPython 3.11.16 and 3.13.15 hash-locked quality/full deterministic pytest lanes;
- the fixed 34-case primary deterministic control evaluation;
- supply-chain verification, official digest-pinned Mermaid CLI rendering of the public Markdown corpus, runtime dependency audit, CycloneDX SBOM generation, same-environment wheel repeatability, and runtime-container inspection;
- Bandit, hash-bound dependency audit, and secret scanning;
- deterministic Playwright reference-SUT execution.

Each automatic job verifies the exact GitHub event revision before installing or executing project code.

The Mermaid renderer is part of the required supply-chain job rather than an optional documentation side job. It discovers Mermaid blocks across the public Markdown corpus under bounded ingestion, invokes the official Mermaid CLI image by immutable OCI digest with network disabled and reduced container authority, requires every discovered block to produce the expected SVG output, rejects remaining unrendered Mermaid blocks, and emits `mermaid-validation.json` as revision-bound supply-chain evidence. This proves parser/render success under the pinned CLI subject; it does not claim pixel-identical behavior with GitHub.com's evolving frontend renderer.

### Stable aggregate check

The final job is deliberately named:

```text
Required PR Gate
```

It uses `if: ${{ always() }}` and depends on every automatic gate. It succeeds only when every required dependency reports `success`. A skipped, cancelled, timed-out, or failed prerequisite therefore cannot be hidden behind partial green.

This stable aggregate is the repository-owned status check intended for GitHub required-check enforcement. It avoids coupling branch policy to every matrix job name while remaining fail closed on all protected work.

Superseded PR runs use `cancel-in-progress: true` so stale revisions do not continue consuming CI capacity or look current after a newer event subject exists.

---

## Manual-only validation

`manual-validation.yml` is intentionally excluded from automatic PR execution.

### Repository-visible H-series readiness

The H-series corpus remains repository-visible and execution-separated from the routine primary evaluator. Manual execution preserves that separation without pretending the committed fixtures are blind or independent evidence.

### Credentialed model smoke

The Claude Agent SDK smoke path executes only when `run_model=true` is explicitly selected. The job references the named GitHub environment `credentialed-validation`, and the workflow rejects any credentialed validation subject whose `GITHUB_REF` is not exactly `refs/heads/main` before any credential-bearing step executes.

`ANTHROPIC_API_KEY` is not a job-level environment variable. Checkout, revision verification, Python setup, and hash-locked project installation execute without the provider credential. The secret is scoped only to the explicit credential-presence check and the bounded live Agent SDK evaluation step.

GitHub settings remain an independent authority boundary. The `credentialed-validation` environment should be configured with appropriate environment protection and restricted deployment branches/tags, and `ANTHROPIC_API_KEY` should be stored as an environment-scoped secret rather than a broadly available repository secret. The repository workflow can reference that control point and fail closed on its own subject checks, but repository code cannot prove the external environment protections are enabled.

A missing credential, provider outage, unapproved environment, or other environment limitation is not converted into automatic PR PASS evidence.

---

## Deterministic workflow-policy verifier

Run:

```bash
python scripts/verify_ci_contract.py
```

The verifier fails closed unless repository workflow definitions preserve the intended authority model. Among other invariants, it requires:

- exactly `ci.yml` and `manual-validation.yml` as workflow YAML files;
- bounded, descriptor-pinned, no-follow workflow ingestion;
- automatic triggers exactly `pull_request`, `push`, and `merge_group`;
- manual trigger exactly `workflow_dispatch`;
- workflow permissions exactly `contents: read`;
- no `pull_request_target`, secrets, workflow inputs, or `continue-on-error: true` in automatic CI;
- only reviewed immutable GitHub Action SHAs;
- every checkout bound to `github.sha`, with persisted credentials disabled and exact-revision verification;
- exact supported Python patch versions and hash-required dependency installation;
- no editable/live dependency-resolution shortcuts in CI;
- exactly one required Mermaid render invocation in the supply-chain job plus its evidence upload;
- the stable `Required PR Gate`, `if: always()`, complete dependency set, and explicit success assertion for every required job.

Adversarial unit tests cover trigger-comment spoofing, write permission, secret introduction, automatic-trigger leakage into the manual workflow, unexpected workflow files, symlinked workflow paths/directories, directory exhaustion, unbound checkout, removal of the Mermaid render invocation or evidence upload, missing aggregate dependencies, corrupted aggregate result checks, a fail-open aggregate condition, and the credentialed model job's environment/main-ref/step-local-secret scope.

The automatic supply-chain job emits the verifier's JSON result as `ci-contract-verification.json` with the other revision-bound supply-chain evidence.

---

## Immutable and bounded inputs

Workflow code continues the Phase 4 supply-chain contract:

- GitHub Actions use reviewed 40-character commit SHAs rather than mutable tags;
- the official Mermaid CLI renderer is selected by an exact OCI SHA-256 digest rather than a mutable image tag;
- CPython versions are exact patch versions;
- Python dependency graphs are hash locked;
- project installation occurs only after the locked graph and uses `--no-deps --no-build-isolation`;
- the runner family is `ubuntu-24.04`, not `ubuntu-latest`.

`ubuntu-24.04` is still a hosted-runner family label, not an immutable runner-image digest. GitHub's tool cache, bootstrap `pip`, runner image, network availability, external package infrastructure, and container-registry availability remain platform boundaries rather than repository-certified facts.

---

## Branch protection / ruleset boundary

The repository-owned workflow is only one half of merge governance. To technically prevent merging a failing PR, GitHub repository settings should require the stable `Required PR Gate` on `main`.

For this single-contributor repository, useful enforcement is narrow and technical rather than ceremonial:

- require changes to flow through pull requests when supported by the chosen repository policy;
- require `Required PR Gate` before merge;
- prevent force pushes and branch deletion on `main` where appropriate;
- use merge-queue support only if the repository actually enables it;
- do **not** invent a second-person approval requirement that cannot honestly be satisfied.

The workflow verifier does not claim these external settings are enabled. Repository API state is authoritative for that question.

---

## Fork and secret posture

Automatic CI is designed for non-privileged execution:

- top-level token permission is read-only;
- checkout credentials are not persisted;
- no automatic job references repository secrets;
- `pull_request_target` is forbidden;
- model credentials remain manual-only, main-subject-gated, environment-bound, and step-scoped.

This limits repository-token/secret authority if a pull request contains hostile code. It does not replace GitHub's platform isolation, organization policy, runner trust, environment protection, or general secure-review requirements.

---

## Release and deployment authority

This phase does not add publishing, package registry, image registry, deployment, production mutation, signing-key, or destructive infrastructure authority.

If those capabilities are added later, credentialed/destructive jobs should remain explicit, manual and environment-protected, least-privilege, subject-bound, and separate from ordinary untrusted PR execution.

A green automatic CI run is not a release signature, deployment approval, or proof that a production environment was modified.

---

## What green proves

A successful automatic run proves that the repository-controlled automatic jobs completed successfully for the exact GitHub event subject they each verified. When the supply-chain job succeeds, the pinned Mermaid CLI also parsed/rendered every Mermaid block discovered in the bounded public Markdown corpus and emitted its machine-readable render report for that event subject.

It does **not** by itself prove:

- pixel-equivalent rendering by GitHub.com's current Markdown/Mermaid frontend;
- branch protection or required-check settings are enabled;
- the `credentialed-validation` environment is configured with the intended external protection rules;
- the GitHub-hosted runner image/tool cache is cryptographically attested by this repository;
- manual H-series or credentialed model validation ran for that revision;
- external provider credentials/services were available;
- release signing, publishing, deployment, or production validation occurred.

That distinction prevents historical or wrong-subject green evidence from becoming merge/release authority it does not possess.

---

## Related documentation

- [Supply-chain integrity](SUPPLY_CHAIN.md)
- [Operations](OPERATIONS.md)
- [Setup and configuration](SETUP.md)
- [Production readiness](PRODUCTION_READINESS.md)
- [Design boundaries and non-claims](LIMITATIONS.md)
- [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

[← Supply chain](SUPPLY_CHAIN.md) · [Operations →](OPERATIONS.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
