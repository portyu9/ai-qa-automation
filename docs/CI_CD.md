# CI/CD and Repository Governance

> [!IMPORTANT]
> **Workflow definition, workflow execution, status-check identity, and merge enforcement are different authorities.** Automatic CI can produce exact-subject evidence and a stable aggregate gate, and GitHub rulesets can require that status check before merge. A `pull_request` workflow still executes repository-controlled workflow/control code from the pull-request event subject, so an in-repository self-check cannot independently prove that a hostile pull request did not replace the workflow and verifier that emit the same required-check name. Closing that control-plane boundary requires an independently trusted GitHub policy/check outside PR-editable repository code.

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

For a normal pull-request event, `github.sha` is GitHub's prospective merge subject rather than merely the feature-branch head. A green PR run therefore proves the tested event subject, not an arbitrary nearby commit. That subject binding does not make the workflow definition itself external to the pull request; workflow/control-plane provenance is a separate authority boundary described below.

---

## Automatic PR/main gate

The automatic workflow runs these repository-owned gates:

- CPython 3.11.16 and 3.13.15 hash-locked quality/full deterministic pytest lanes;
- the fixed 34-case primary deterministic control evaluation;
- pre-build project-authority verification, supply-chain verification, deterministic documentation authority verification, official digest-pinned Mermaid CLI rendering, runtime dependency audit, CycloneDX SBOM generation, exact-event-subject wheel repeatability, and runtime-container inspection;
- Bandit, hash-bound dependency audit, and secret scanning;
- deterministic Playwright reference-SUT execution against the hosted image's already-installed Chrome runtime.

Each automatic job verifies the exact GitHub event revision before installing or executing project code. Dependency-install authority is established before the repository-controlled lock graph is consumed: `scripts/verify_build_authority.py` is standard-library-only and requires the `requirements/` directory to expose exactly the five reviewed lock files, with each file byte-for-byte bound to its reviewed Git blob identity. The directory is enumerated through bounded descriptor-relative no-follow operations with a 32-entry ceiling, each reviewed lock is bounded to 1 MiB, symlink/special-file substitution is rejected, and file/directory identity is revalidated around ingestion. Every one of the five automatic `python -m pip install --require-hashes -r ...` sites is immediately preceded by that authority check and followed by another authority check before project installation or later repository tool execution. A pull request therefore cannot first alter a hash-locked graph to install a new same-name console script and only then ask the repository verifier to approve the already-mutated environment.

Project build/install authority is the next explicit boundary. Immediately before every automatic `pip install --no-deps --no-build-isolation .`, the same verifier requires the reviewed static Hatchling configuration; distribution name `ai-qa-automation`; sole console script `ai-qa = ai_qa_automation.cli:app`; absence of project GUI/entry-point groups; the exact file-valued inputs `README.md` and `LICENSE`; and a bounded symlink-free `src/ai_qa_automation` package tree containing only regular files/directories. README/LICENSE are each capped at 2 MiB, each selected source file at 8 MiB, aggregate selected source bytes at 32 MiB, and actual package-tree ingestion at 1024 entries. The verifier also rejects any installed `hatch` entry point discovered through standard-library distribution metadata. This prevents the project build/install path from silently introducing extra executables that shadow later CI tools, installing a newly declared project-owned Hatch plugin, replacing an unrelated locked distribution by name, or exhausting the build path with a small number of oversized repository files while still preserving verifier `PASS`.

The supply-chain job additionally persists `build-authority-verification.json` from its pre-install observation, then repeats the same lock/build/plugin authority check after the locked verification graph is installed and immediately before the project build. The verifier does not load Hatch plugin code while inspecting entry-point metadata, and its bounded filesystem observation is not claimed to create a privileged immutable snapshot after verification. Its byte ceilings constrain repository-controlled dependency/build ingestion; they do not make the hosted runner or build tools resource-immutable.

Automatic browser validation has its own authority boundary. The reference-SUT job does **not** run `playwright install`, `--with-deps`, `sudo`, `apt-get`, or `apt install`. Instead it requires `/usr/bin/google-chrome` to already be executable on the hosted `ubuntu-24.04` image, records `/usr/bin/google-chrome --version`, and runs the reference test with the narrow `BrowserProbe(use_system_chrome=True)` option, which maps only to Playwright's `chrome` channel. The runtime API does not expose an arbitrary browser executable path or arbitrary channel. `scripts/verify_ci_contract.py` requires the exact hosted-Chrome observation step and deterministically rejects those privileged browser/OS installation tokens. Missing or incompatible hosted Chrome is therefore a failed/incomplete browser gate, not authorization to mutate the runner as root or download a replacement browser during an untrusted PR run.

The hosted browser is still a platform input, not repository-pinned supply-chain evidence. The `ubuntu-24.04` runner family can advance to a different image/browser build. Recording the observed Chrome version proves what executable the job selected at that time; it does not cryptographically attest that browser or promise the same version on a later hosted image.

After structural command/step checks, `scripts/verify_ci_contract.py` binds the complete automatic `ci.yml` bytes to the reviewed Git blob identity and requires all five dependency-install sites to retain their exact pre/post authority bracket. This rejects accidental or unreviewed workflow drift—including an additional semantically equivalent project-install command—inside the definition being validated. The whole-file identity check is **in-run self-consistency evidence**, not an independently trusted merge-policy root: because both `ci.yml` and its repository verifier are part of the pull-request subject, a hostile pull request can in principle change both unless an external GitHub control prevents that change or supplies an independently trusted required check. This is the residual workflow-governance boundary identified by the Phase 4 adversarial audit.

The reproducible-wheel step archives the event subject itself rather than mutable `HEAD`. CI creates fresh random build directories plus a fresh bare Git view with an empty template under `RUNNER_TEMP`, runs Git under an empty environment containing only `PATH` plus the reviewed Git safety variables, and points that view only at the checked-out repository's content-addressed object store. Both archives name `$GITHUB_SHA` and set `core.attributesFile=/dev/null`; extraction uses `/usr/bin/tar` under a clean environment. The isolated view therefore does not consult checkout-local `.git/info/attributes`, checkout Git configuration, or ambient user/system Git attributes. Committed `.gitattributes` in the exact event tree remains repository-owned source authority. After extraction, the checkout-owned build-authority verifier inspects each archive root immediately before its corresponding wheel build, persists `build-authority-archive-a.json` and `build-authority-archive-b.json`, and requires those deterministic results—including the observed entry/byte counts and reviewed byte ceilings—to be byte-identical. The build manifest receives the same `$GITHUB_SHA` as its explicit expected source.

The runtime-container build uses a separate fresh bare Git view and empty template under `RUNNER_TEMP` rather than Docker context `.` from the mutable checkout. Git again runs through the clean environment, shares only the checked-out content-addressed object store, disables replacement-object rewriting, and archives exact `$GITHUB_SHA` with `core.attributesFile=/dev/null`; that tar stream is piped directly to `docker build --tag "$image" -`. Later worktree changes and checkout-local `.dockerignore` or Git metadata therefore cannot silently retarget the repository bytes handed to Docker. This binds repository context to the event subject; it does not attest Docker/BuildKit, the hosted runner, external registries, or byte-identical container-image reproducibility.

The runtime CycloneDX SBOM also has explicit lineage. Immediately after the hash-locked runtime audit, CI records its SHA-256 into the GitHub step environment. The reproducible-build step requires that digest to match before wheel generation, after both wheel builds, and again after manifest generation. The manifest generator also requires that parent-owned digest and rejects a structurally valid SBOM whose observed digest differs. Later build activity therefore cannot silently replace the earlier audited SBOM subject while preserving a green supply-chain result.

The documentation verifier is an explicit required step in the supply-chain job rather than an indirect consequence of the pytest suite. It validates bounded public-document ingestion, local links and anchors, documentation navigation, Mermaid accessibility metadata, prohibited project-progress headings, setup-snippet policy, and selected implementation-coupled README facts. The exact Claude Agent SDK pin, default model identifier, and internal QA-tool count are derived from bounded repository source inputs. The Skill claim is derived from the literal `ClaudeAgentOptions.skills` runtime allowlist and is accepted only when that allowlist matches the safely inspected `.claude/skills` directory set exactly. The resulting `documentation-integrity.json` is persisted with the revision-bound supply-chain evidence.

The Mermaid renderer is part of the required supply-chain job rather than an optional documentation side job. It discovers Mermaid blocks across the public Markdown corpus under bounded ingestion, invokes the official Mermaid CLI image by immutable OCI digest with network disabled and reduced container authority, bounds each renderer-created file to 16 MiB, requires every discovered block to produce the expected SVG output, rejects remaining unrendered Mermaid blocks, and emits `mermaid-validation.json` as revision-bound supply-chain evidence. This proves parser/render success under the pinned CLI subject; it does not claim pixel-identical behavior with GitHub.com's evolving frontend renderer.

### Stable aggregate check

The final job is deliberately named:

```text
Required PR Gate
```

It uses `if: ${{ always() }}` and depends on every automatic gate. Its result-check step is an exact reviewed script block that succeeds only when every required dependency reports `success`; shell short-circuit additions such as `|| true` are rejected by the repository CI-contract verifier. A skipped, cancelled, timed-out, or failed prerequisite therefore cannot be hidden behind partial green **when the reviewed automatic workflow is the definition actually executing**.

This stable aggregate is the repository-owned status-check interface used for GitHub required-check enforcement. It avoids coupling branch policy to every matrix job name. Requiring the check name is meaningful merge enforcement, but the check context alone does not cryptographically or immutably bind the implementation that produced it to the trusted default-branch copy of `ci.yml`. Therefore the aggregate result must not be described as independently immutable workflow provenance.

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

The verifier fails closed unless the workflow definitions in the source subject preserve the intended repository authority model. Among other invariants, it requires:

- exactly `ci.yml` and `manual-validation.yml` as workflow YAML files;
- bounded, descriptor-pinned, no-follow workflow ingestion;
- automatic triggers exactly `pull_request`, `push`, and `merge_group`;
- manual trigger exactly `workflow_dispatch`;
- workflow permissions exactly `contents: read`;
- no `pull_request_target`, secrets, workflow inputs, or `continue-on-error: true` in automatic CI;
- no automatic `playwright install`, `sudo`, `apt-get`, or `apt install` authority;
- the exact `Verify hosted Chrome runtime` step, requiring `/usr/bin/google-chrome` and recording its version before reference-SUT browser execution;
- only reviewed immutable GitHub Action SHAs;
- every checkout bound to `github.sha`, with persisted credentials disabled and exact-revision verification;
- exact supported Python patch versions and hash-required dependency installation;
- no editable/live dependency-resolution shortcuts in CI;
- exactly five reviewed automatic hash-locked dependency-install sites, each immediately preceded and followed by `verify_build_authority.py`, so exact reviewed lock bytes are established before repository dependency ingestion and revalidated afterward;
- exactly the reviewed five automatic project-install sites, with static build-authority revalidation immediately before every project install;
- the complete automatic `ci.yml` bytes to match the reviewed Git blob identity after structural verification, so unmodeled extra commands or alternate install spellings cannot coexist with verifier `PASS` inside that running definition;
- the supply-chain static build-authority verifier as an exact evidence-producing pre-install step and an immediate revalidation before the supply-chain project build;
- safety-critical ordering of build authority → project install → repository verification → runtime SBOM → reproducible wheel build;
- the runtime SBOM audit as an exact reviewed digest-exporting step and the later wheel-build block as an exact SHA-256-bracketed consumer;
- the documentation verifier and Mermaid renderer as exact reviewed, unconditional script steps in the required supply-chain job;
- the reproducible-wheel block as an exact reviewed event-subject-bound step: fixed source-date epoch, fresh random build directories, a fresh bare Git view initialized from an empty template, a clean Git environment, the checked-out repository object store as the only shared Git object authority, replacement-object/lazy-fetch/optional-lock controls, global attributes redirected to `/dev/null`, clean `/usr/bin/tar` extraction, both archives from `$GITHUB_SHA`, per-archive build-authority verification immediately before wheel creation, identical archive-authority JSON results, and the manifest's explicit expected source equal to `$GITHUB_SHA`;
- the runtime-container build context as exact `$GITHUB_SHA` from a separate fresh bare Git view/empty template under the same clean Git authority, streamed directly to Docker instead of mutable checkout `.`;
- the supply-chain evidence step as the exact reviewed immutable `actions/upload-artifact` invocation, including checkout and both archive build-authority JSON files, the complete expected path set, `if-no-files-found: error`, and bounded retention;
- the stable `Required PR Gate`, `if: always()`, complete dependency set, and an exact fail-closed result-check script for every required job.

The build-authority regression suite separately exercises exact-lock-byte mutation, unexpected lock-set expansion, symlinked lock substitution, distribution-name collision, extra console scripts that could shadow later CI tools, GUI/project entry-point expansion, installed Hatch plugin metadata, README/license/`license-files` authority expansion, package-root and nested-package symlinks, special-node rejection, requirements/package directory-entry exhaustion, oversized lock/project file inputs, oversized individual source files, and aggregate selected-source byte exhaustion. Browser-runtime regressions require the default Playwright-managed behavior to remain unchanged, constrain the CI-only system-browser mode to the exact `chrome` channel, reject arbitrary path-like mode expansion, reject reintroduction of Playwright's privileged browser bootstrap, and require the exact hosted-Chrome observation step. Workflow/adversarial tests additionally cover removal or reordering of either side of the dependency-install authority bracket, trigger/comment spoofing, write permission, secret introduction, automatic-trigger leakage into the manual workflow, unexpected workflow files, symlinked workflow paths/directories, unbound checkout, build-authority removal/reordering, unguarded automatic project installation, additional semantically equivalent project-install spellings, removal or divergence of per-archive build-authority checks/evidence, runtime-SBOM digest lineage removal, mutable-`HEAD` reproducible archives, re-enabled Git replacement objects, loss of the clean Git environment, loss of the fresh bare Git view/object-directory/empty-template isolation, reintroduction of ambient archive attributes, dirty tar extraction authority, replacement of the exact-event runtime-container archive with mutable checkout `docker build ... .`, a build manifest subject derived from mutable `HEAD`, documentation/Mermaid fail-open changes, evidence upload weakening, aggregate dependency/result-check corruption, and the credentialed model job's environment/main-ref/step-local-secret scope.

Those repository tests and the exact-workflow blob check are strong protections against accidental drift and reviewed-code regressions, but they are not an external trust anchor for themselves. A pull request that can replace both automatic workflow code and its verifier remains outside what repository-local execution can independently certify. Phase completion must represent that case as an environment/policy boundary unless a separately trusted GitHub control is established and re-fetched as evidence.

The automatic supply-chain job emits `build-authority-verification.json`, both `build-authority-archive-*.json` files, `ci-contract-verification.json`, `documentation-integrity.json`, and the other supply-chain evidence. Its upload step deliberately uses `if: always()` so failure diagnostics can survive a red job. Consequently, an uploaded artifact or a successful upload step is **not** proof that the supply-chain job passed or that every listed evidence file existed; closure requires the supply-chain job itself, and then the aggregate `Required PR Gate`, to succeed for the exact subject. Even that green aggregate does not by itself close the independently trusted workflow-definition boundary described above.

---

## Immutable and bounded inputs

Workflow code continues the Phase 4 supply-chain contract:

- GitHub Actions use reviewed 40-character commit SHAs rather than mutable tags;
- the five managed dependency locks are byte-bound to exact reviewed Git blob identities before every automatic repository-controlled dependency installation, with bounded no-follow ingestion;
- the complete automatic workflow definition is bound to a reviewed Git blob identity **inside the running repository verifier**, providing definition self-consistency rather than external workflow immutability;
- the automatic reference-SUT browser consumes observed hosted `/usr/bin/google-chrome` without automatic browser/OS installation; its version is logged but remains an environment-owned input;
- the official Mermaid CLI renderer is selected by an exact OCI SHA-256 digest rather than a mutable image tag;
- CPython versions are exact patch versions;
- Python dependency graphs are hash locked;
- project build configuration, distribution/console-script/entry-point metadata, bounded file-valued metadata inputs, the bounded selected package tree, and installed Hatch plugin metadata are checked before automatic project builds;
- README/LICENSE build inputs are capped at 2 MiB each, selected package files at 8 MiB each, total selected package bytes at 32 MiB, actual package-tree ingestion at 1024 entries, managed lock files at 1 MiB each, and requirements-directory ingestion at 32 entries;
- project installation occurs only after the reviewed locked graph has been prevalidated/revalidated where applicable and uses `--no-deps --no-build-isolation`;
- reproducible source archives name the exact GitHub event object, explicitly disable replacement-object rewriting, use an isolated bare Git view so checkout-local/ambient Git attribute or configuration metadata is not archive authority, and revalidate the exact extracted build-source authority immediately before each wheel;
- the runtime-container build consumes an exact-event tar stream from its own isolated bare Git view rather than mutable checkout `.`, so checkout worktree and local `.dockerignore` drift are not container-context authority;
- the runtime-SBOM subject is SHA-256 bracketed across later wheel/manifest activity and accepted by the manifest only when it matches the parent CI-owned digest;
- the runner family is `ubuntu-24.04`, not `ubuntu-latest`.

`ubuntu-24.04` is still a hosted-runner family label, not an immutable runner-image digest. GitHub's tool cache, bootstrap `pip`, hosted Chrome executable/version, runner image, network availability, external package infrastructure, container-registry availability, Docker/BuildKit implementation, and external workflow-governance configuration remain platform boundaries rather than repository-certified facts.

---

## Branch protection / ruleset boundary

Repository API inspection on August 27, 2026 reported the active `Protect Main` ruleset applied to the default branch with pull requests required, review-thread resolution required, deletion and non-fast-forward updates blocked, strict `Required PR Gate` status-check enforcement, and no bypass actors. That is real external merge enforcement and must be re-fetched during any later completion audit rather than inferred from workflow YAML or historical evidence.

It does **not** close the workflow-definition provenance problem by itself. A required status-check context identifies the check interface/integration accepted by branch policy; it does not make the PR's `.github/workflows/ci.yml` or repository verifier immutable. Because normal `pull_request` execution can evaluate repository-controlled workflow/control code from the prospective merge subject, a hostile change to the control-plane files can attempt to emit the same required check under changed logic. Repository-local assertions cannot authoritatively certify that their own definition was not replaced.

For this single-contributor repository, useful enforcement therefore remains narrow and technical rather than ceremonial:

- keep changes flowing through pull requests;
- require `Required PR Gate` before merge;
- prevent force pushes and branch deletion on `main`;
- require review-thread resolution without inventing an impossible second-person approval requirement;
- where platform/account capabilities permit, add an independently trusted workflow/check or external policy that prevents PR-editable control-plane code from being the sole authority for the required status result;
- use merge-queue support only if the repository actually enables it.

Until that independent control is established and observed, finding 13 remains an explicit environment-owned limitation. The repository can be fully green and still must not claim that `Required PR Gate` is backed by an immutable workflow definition against arbitrary hostile workflow edits.

---

## Fork and secret posture

Automatic CI is designed for non-privileged execution:

- top-level token permission is read-only;
- checkout credentials are not persisted;
- no automatic job references repository secrets;
- `pull_request_target` is forbidden;
- automatic browser validation observes the hosted Chrome runtime and cannot invoke Playwright browser installation, `sudo`, or APT installation through the reviewed workflow contract;
- model credentials remain manual-only, main-subject-gated, environment-bound, and step-scoped.

This limits repository-token/secret and host-mutation authority if a pull request contains hostile code. It does not replace GitHub's platform isolation, organization policy, runner/browser trust, environment protection, independently trusted workflow policy, or general secure-review requirements.

---

## Release and deployment authority

This phase does not add publishing, package registry, image registry, deployment, production mutation, signing-key, or destructive infrastructure authority.

If those capabilities are added later, credentialed/destructive jobs should remain explicit, manual and environment-protected, least-privilege, subject-bound, and separate from ordinary untrusted PR execution.

A green automatic CI run is not a release signature, deployment approval, or proof that a production environment was modified.

---

## What green proves

A successful automatic run proves that the automatic jobs defined by the executed pull-request subject completed successfully for the exact GitHub event subject they each verified. A successful supply-chain run additionally proves that, **within that executing definition**, the complete automatic workflow matched its embedded reviewed Git blob identity; exact reviewed lock bytes were established before each automatic dependency installation and revalidated afterward; the reviewed build-authority check passed before its verification-environment installation; the project distribution name, sole reviewed console script, and absence of project GUI/entry-point groups matched the reviewed installation-metadata policy; README/LICENSE and the selected package-tree shape were observed without symlinks/special nodes and within their reviewed entry/per-file/aggregate byte ceilings; the installed verification graph exposed no `hatch` entry points when rechecked before the project build; every automatic project install remained immediately guarded by the build-authority verifier; the automatic browser path retained the exact hosted-Chrome observation step with privileged browser/OS installer authority denied; each exact-event archive was independently revalidated for the same build/install/resource authority immediately before its wheel build and the two persisted archive-authority results matched; the runtime-SBOM digest remained stable across later wheel/manifest activity and matched the parent-owned digest accepted by the manifest; the reproducible wheel archives named the event subject through the isolated bare Git view with replacement-object rewriting and checkout-local/ambient attribute sources excluded from archive authority; the runtime-container build context was separately archived from that exact event subject instead of mutable checkout state; and the manifest's recorded Dockerfile/pyproject/lock bytes matched blobs in that exact commit. The documentation and Mermaid evidence proves their corresponding bounded structural/render contracts for that checked-out subject.

A successful browser-reference job additionally proves that the hosted `/usr/bin/google-chrome` executable existed, its version was observed in the job log, and the deterministic localhost reference-SUT Playwright operation completed under the selected `chrome` channel without the workflow acquiring root/APT/Playwright-browser-install authority.

Artifact presence by itself is diagnostic evidence, not terminal authority. In particular, a failure-path `if: always()` upload may contain only the evidence produced before a job failed. A green claim therefore depends on the exact-subject job conclusions and aggregate gate, not merely on an artifact being downloadable.

It does **not** by itself prove:

- the required status check was produced by an externally immutable or default-branch-trusted workflow/control definition rather than PR-editable workflow code;
- the hosted Chrome binary/version or runner image was cryptographically attested, immutable, or stable across later jobs/runs;
- every narrative statement in the documentation is implementation-derived or externally verified;
- pixel-equivalent rendering by GitHub.com's current Markdown/Mermaid frontend;
- current branch/ruleset settings still match a prior API observation without re-fetching them;
- the `credentialed-validation` environment is configured with the intended external protection rules;
- the GitHub-hosted runner image/tool cache or Docker/BuildKit implementation is cryptographically attested by this repository;
- the build-source filesystem remained immutable after each bounded build-authority observation;
- the hosted build tools cannot consume resources outside the repository-controlled input ceilings;
- manual H-series or credentialed model validation ran for that revision;
- external provider credentials/services were available;
- release signing, publishing, deployment, or production validation occurred.

That distinction prevents historical, partial, artifact-only, build-config-expanded, install-metadata-expanded, dependency-lock-retargeted, executable-shadowed, resource-exhaustion, plugin-expanded, source-symlink-expanded, privileged-browser-bootstrap, SBOM-substituted, replacement-object-retargeted, checkout-Git-metadata-retargeted, workflow-command-surface-expanded, self-certifying-workflow, mutable-container-context, or wrong-subject evidence from becoming merge/release authority it does not possess.

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