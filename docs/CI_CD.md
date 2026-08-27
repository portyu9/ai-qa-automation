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
- pre-build static project-authority verification, supply-chain verification, deterministic documentation authority verification, official digest-pinned Mermaid CLI rendering, runtime dependency audit, CycloneDX SBOM generation, exact-event-subject wheel repeatability, and runtime-container inspection;
- Bandit, hash-bound dependency audit, and secret scanning;
- deterministic Playwright reference-SUT execution.

Each automatic job verifies the exact GitHub event revision before installing or executing project code. Project build configuration is also an authority boundary: the supply-chain job runs the standard-library-only `scripts/verify_build_authority.py` before installing the project, persists `build-authority-verification.json`, and re-runs the verifier immediately before `pip install --no-deps --no-build-isolation .`. The verifier permits only the reviewed static Hatchling backend/configuration and rejects backend paths, custom build hooks, metadata/version execution sources, custom builders, and dynamic project metadata.

The reproducible-wheel step archives the event subject itself rather than mutable `HEAD`: both source trees come from `git --no-replace-objects archive "$GITHUB_SHA"`, replacement refs are disabled, and the build manifest receives the same `$GITHUB_SHA` as its explicit expected source.

The runtime CycloneDX SBOM also has explicit lineage. Immediately after the hash-locked runtime audit, CI records its SHA-256 into the GitHub step environment. The reproducible-build step requires that digest to match before wheel generation, after both wheel builds, and again after manifest generation. Later build activity therefore cannot silently replace the earlier audited SBOM subject while preserving a green supply-chain result.

The documentation verifier is an explicit required step in the supply-chain job rather than an indirect consequence of the pytest suite. It validates bounded public-document ingestion, local links and anchors, documentation navigation, Mermaid accessibility metadata, prohibited project-progress headings, setup-snippet policy, and selected implementation-coupled README facts. The exact Claude Agent SDK pin, default model identifier, and internal QA-tool count are derived from bounded repository source inputs. The Skill claim is derived from the literal `ClaudeAgentOptions.skills` runtime allowlist and is accepted only when that allowlist matches the safely inspected `.claude/skills` directory set exactly. The resulting `documentation-integrity.json` is persisted with the revision-bound supply-chain evidence.

The Mermaid renderer is part of the required supply-chain job rather than an optional documentation side job. It discovers Mermaid blocks across the public Markdown corpus under bounded ingestion, invokes the official Mermaid CLI image by immutable OCI digest with network disabled and reduced container authority, bounds each renderer-created file to 16 MiB, requires every discovered block to produce the expected SVG output, rejects remaining unrendered Mermaid blocks, and emits `mermaid-validation.json` as revision-bound supply-chain evidence. This proves parser/render success under the pinned CLI subject; it does not claim pixel-identical behavior with GitHub.com's evolving frontend renderer.

### Stable aggregate check

The final job is deliberately named:

```text
Required PR Gate
```

It uses `if: ${{ always() }}` and depends on every automatic gate. Its result-check step is an exact reviewed script block that succeeds only when every required dependency reports `success`; shell short-circuit additions such as `|| true` are rejected by the repository CI-contract verifier. A skipped, cancelled, timed-out, or failed prerequisite therefore cannot be hidden behind partial green.

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
- the static build-authority verifier as an exact evidence-producing pre-install step and an immediate revalidation before the supply-chain project build;
- safety-critical ordering of build authority → project install → repository verification → runtime SBOM → reproducible wheel build;
- the runtime SBOM audit as an exact reviewed digest-exporting step and the later wheel-build block as an exact SHA-256-bracketed consumer;
- the documentation verifier and Mermaid renderer as exact reviewed, unconditional script steps in the required supply-chain job;
- the reproducible-wheel block as an exact reviewed event-subject-bound step: fixed source-date epoch, replacement objects disabled, both archives from `$GITHUB_SHA`, and the manifest's explicit expected source equal to `$GITHUB_SHA`;
- the supply-chain evidence step as the exact reviewed immutable `actions/upload-artifact` invocation, including `build-authority-verification.json`, the complete expected path set, `if-no-files-found: error`, and bounded retention;
- the stable `Required PR Gate`, `if: always()`, complete dependency set, and an exact fail-closed result-check script for every required job.

Adversarial unit tests cover trigger/comment spoofing, write permission, secret introduction, automatic-trigger leakage into the manual workflow, unexpected workflow files, symlinked workflow paths/directories, directory exhaustion, unbound checkout, build-authority removal/reordering, loss of the immediate pre-install revalidation, custom build configuration, runtime-SBOM digest lineage removal, mutable-`HEAD` reproducible archives, re-enabled Git replacement objects, removal of the no-replace environment, a build manifest subject derived from mutable `HEAD`, documentation/Mermaid fail-open changes, evidence upload weakening, aggregate dependency/result-check corruption, and the credentialed model job's environment/main-ref/step-local-secret scope.

The automatic supply-chain job emits `build-authority-verification.json`, `ci-contract-verification.json`, `documentation-integrity.json`, and the other supply-chain evidence. Its upload step deliberately uses `if: always()` so failure diagnostics can survive a red job. Consequently, an uploaded artifact or a successful upload step is **not** proof that the supply-chain job passed or that every listed evidence file existed; closure requires the supply-chain job itself, and then the aggregate `Required PR Gate`, to succeed for the exact subject.

---

## Immutable and bounded inputs

Workflow code continues the Phase 4 supply-chain contract:

- GitHub Actions use reviewed 40-character commit SHAs rather than mutable tags;
- the official Mermaid CLI renderer is selected by an exact OCI SHA-256 digest rather than a mutable image tag;
- CPython versions are exact patch versions;
- Python dependency graphs are hash locked;
- project build configuration is checked before the required supply-chain project build can execute;
- project installation occurs only after the locked graph and uses `--no-deps --no-build-isolation`;
- reproducible source archives name the exact GitHub event object and explicitly disable replacement-object rewriting;
- the runtime-SBOM subject is SHA-256 bracketed across later wheel/manifest activity;
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

A successful automatic run proves that the repository-controlled automatic jobs completed successfully for the exact GitHub event subject they each verified. A successful supply-chain run additionally proves that the reviewed static build-authority check passed before its project build, the runtime-SBOM digest remained stable across later wheel/manifest activity, the reproducible wheel archives named the event subject with replacement-object rewriting disabled, the manifest accepted the same explicit source subject, and the manifest's recorded Dockerfile/pyproject/lock bytes matched blobs in that exact commit. The documentation and Mermaid evidence proves their corresponding bounded structural/render contracts for that checked-out subject.

Artifact presence by itself is diagnostic evidence, not terminal authority. In particular, a failure-path `if: always()` upload may contain only the evidence produced before a job failed. A green claim therefore depends on the exact-subject job conclusions and aggregate gate, not merely on an artifact being downloadable.

It does **not** by itself prove:

- every narrative statement in the documentation is implementation-derived or externally verified;
- pixel-equivalent rendering by GitHub.com's current Markdown/Mermaid frontend;
- branch protection or required-check settings are enabled;
- the `credentialed-validation` environment is configured with the intended external protection rules;
- the GitHub-hosted runner image/tool cache is cryptographically attested by this repository;
- manual H-series or credentialed model validation ran for that revision;
- external provider credentials/services were available;
- release signing, publishing, deployment, or production validation occurred.

That distinction prevents historical, partial, artifact-only, build-config-expanded, SBOM-substituted, replacement-object-retargeted, or wrong-subject evidence from becoming merge/release authority it does not possess.

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
