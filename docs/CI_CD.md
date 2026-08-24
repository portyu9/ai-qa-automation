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
| `.github/workflows/manual-validation.yml` | `workflow_dispatch` only | model job may receive `ANTHROPIC_API_KEY` | H-series readiness and optional credentialed Agent SDK evidence |

Both workflows declare only `contents: read`. Every checkout disables persisted credentials, binds to `${{ github.sha }}`, and immediately verifies that `git rev-parse HEAD` equals `GITHUB_SHA`.

For a normal pull-request event, `github.sha` is GitHub's prospective merge subject rather than merely the feature-branch head. A green PR run therefore proves the tested event subject, not an arbitrary nearby commit.

---

## Automatic PR/main gate

The automatic workflow runs these repository-owned gates:

- CPython 3.11.16 and 3.13.15 hash-locked quality/full deterministic pytest lanes;
- the fixed 34-case primary deterministic control evaluation;
- supply-chain verification, runtime dependency audit, CycloneDX SBOM generation, same-environment wheel repeatability, and runtime-container inspection;
- Bandit, hash-bound dependency audit, and secret scanning;
- deterministic Playwright reference-SUT execution.

Each automatic job verifies the exact GitHub event revision before installing or executing project code.

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

The Claude Agent SDK smoke path executes only when `run_model=true` is explicitly selected. That job alone consumes `ANTHROPIC_API_KEY` from GitHub Secrets. Automatic PR CI contains no secret references and does not depend on live model/provider availability.

A missing credential, provider outage, or environment limitation is not converted into automatic PR PASS evidence.

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
- the stable `Required PR Gate`, `if: always()`, complete dependency set, and explicit success assertion for every required job.

Adversarial unit tests cover trigger-comment spoofing, write permission, secret introduction, automatic-trigger leakage into the manual workflow, unexpected workflow files, symlinked workflow paths/directories, directory exhaustion, unbound checkout, missing aggregate dependencies, corrupted aggregate result checks, and a fail-open aggregate condition.

The automatic supply-chain job emits the verifier's JSON result as `ci-contract-verification.json` with the other revision-bound supply-chain evidence.

---

## Immutable and bounded inputs

Workflow code continues the Phase 4 supply-chain contract:

- GitHub Actions use reviewed 40-character commit SHAs rather than mutable tags;
- CPython versions are exact patch versions;
- Python dependency graphs are hash locked;
- project installation occurs only after the locked graph and uses `--no-deps --no-build-isolation`;
- the runner family is `ubuntu-24.04`, not `ubuntu-latest`.

`ubuntu-24.04` is still a hosted-runner family label, not an immutable runner-image digest. GitHub's tool cache, bootstrap `pip`, runner image, network availability, and external package infrastructure remain platform boundaries rather than repository-certified facts.

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
- model credentials remain manual-only.

This limits repository-token/secret authority if a pull request contains hostile code. It does not replace GitHub's platform isolation, organization policy, runner trust, or general secure-review requirements.

---

## Release and deployment authority

This phase does not add publishing, package registry, image registry, deployment, production mutation, signing-key, or destructive infrastructure authority.

If those capabilities are added later, credentialed/destructive jobs should remain explicit, manual or environment-protected, least-privilege, subject-bound, and separate from ordinary untrusted PR execution.

A green automatic CI run is not a release signature, deployment approval, or proof that a production environment was modified.

---

## What green proves

A successful automatic run proves that the repository-controlled automatic jobs completed successfully for the exact GitHub event subject they each verified.

It does **not** by itself prove:

- branch protection or required-check settings are enabled;
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
