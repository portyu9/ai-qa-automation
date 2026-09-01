# Release Candidate Integrity

> [!IMPORTANT]
> A release candidate is **package evidence for one exact source revision**. It is not a Git tag, GitHub Release, package publication, signature, deployment approval, or production change.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Supply chain](SUPPLY_CHAIN.md) · [CI/CD](CI_CD.md) · [Verification boundaries](VERIFICATION_BOUNDARIES.md)

---

## Purpose

`.github/workflows/release-candidate.yml` provides a manual, non-publishing preparation path for deterministic package evidence. It exists because ordinary CI and `Trusted PR Gate` answer different questions:

```text
merge evidence / merge authorization
≠ release package identity
≠ publisher identity
≠ deployment evidence
```

The workflow has no release/package write permission and receives no publishing or signing credential.

## Admission contract

A candidate is accepted only when all of these are true:

- execution was explicitly dispatched from `refs/heads/main`;
- `RELEASE_SUBJECT_SHA` is the workflow's exact `github.sha`;
- the checkout resolves to that exact commit;
- the explicit release tag is stable `vMAJOR.MINOR.PATCH` syntax;
- the tag is exactly `v` plus the static `[project].version` in `pyproject.toml`;
- project identity remains exactly `ai-qa-automation`;
- tracked or staged worktree drift is absent before release evidence is derived;
- reviewed build authority passes before dependency installation;
- build dependencies come only from the hash-locked `requirements/build-py311.lock` graph;
- two fresh archives are constructed from the exact source object using an isolated Git view;
- each extracted archive independently passes build-authority verification immediately before build;
- each archive produces exactly one expected wheel;
- both wheels have the expected distribution/version filename and are byte-identical.

Any ambiguity is a failed release-candidate run, not permission to publish from weaker evidence.

## Evidence

A successful run uploads one `release-candidate-evidence` artifact containing:

- pre-install build-authority evidence;
- independent build-authority evidence for archive A and archive B;
- `release-identity.json` binding tag, static project version, exact source SHA/tree, and `pyproject.toml` Git-blob identity;
- `release-manifest.json` extending that identity with the reproducible wheel filename, size, SHA-256, and build count;
- `release-checksums.sha256` over the retained wheel and release JSON evidence; and
- one retained wheel copied from the two byte-identical builds.

The canonical manifest explicitly records `publishing_authority: none` and `signature_claim: none`.

## Authority separation

The workflow is `workflow_dispatch` only and top-level GitHub permissions are exactly `contents: read`. Repository CI contract verification rejects trigger broadening, write permissions, secrets, `id-token: write`, package/release tooling, mutable runner aliases, dependency caching, editable installs, and removal of exact-main/source/build/reproducibility checks.

The path deliberately does **not**:

- create or move a Git tag;
- create a GitHub Release;
- upload to PyPI or another registry;
- mint OIDC identity;
- sign or notarize package bytes;
- deploy an artifact;
- satisfy `Trusted PR Gate`; or
- convert historical CI success into release authority.

A future publishing/signing system must be separately designed as a credentialed manual authority with independent target/repository/version checks and evidence bound to the package bytes produced or revalidated by that system.

## Operator sequence

1. Merge the intended release source through the normal protected-branch process.
2. Confirm `main` is the intended exact release source and `[project].version` is already correct.
3. Manually dispatch **Release Candidate Evidence** from `main` with the exact matching `vMAJOR.MINOR.PATCH` value.
4. Require terminal workflow success; do not treat a partial artifact upload after failure as PASS.
5. Retain the workflow run identity, exact `main` SHA, artifact identity/digest, manifest, and checksums as release-preparation evidence.
6. If any source/version/package byte changes, run the candidate process again. Older evidence does not certify the new bytes.

---

[← CI/CD](CI_CD.md) · [Supply chain →](SUPPLY_CHAIN.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
