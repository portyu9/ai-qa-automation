# Temporary Development Governance Window

> [!IMPORTANT]
> This document records a **temporary development-mode exception**, not the intended final production governance state.

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md) · [CI/CD](CI_CD.md) · [Production readiness](PRODUCTION_READINESS.md)

---

## Purpose

During the remaining implementation, enhancement, architecture, hardening, and review cycle, changes under the following repository roots are temporarily admitted through the routine GitHub-only trusted PR path instead of requiring the external protected-maintenance service:

- `.github`
- `scripts`
- `tests`

This exception exists only to avoid repeatedly activating the external maintenance path while the repository is still undergoing active engineering changes.

The protected branch still requires the App-bound `Trusted PR Gate`. Routine admission remains owner-only, same-repository, open/non-draft PR only and remains bound to current `main`, the exact PR head, the exact prospective merge commit, ordered `(base, head)` merge parents, and the remaining protected Git objects. Candidate validation remains read-only and secret-free before the final trusted reporter.

## What is not being removed

The independently deployed external gate keeps its broader protected-root vocabulary, including `.github`, `scripts`, and `tests`. The temporary exception changes routing in the repository-owned routine admission path; it does not redefine the external service's historical protected-object vocabulary and does not require AWS mutation or redeployment.

All other protected roots retain their current fail-closed treatment.

## Restoration authority

Issue **#129 — Re-enable external protected maintenance after final hardening audits** is the authoritative restoration tracker.

The temporary exception must be removed only after the remaining engineering program is complete, including:

1. implementation and enhancement work;
2. architecture review;
3. eval-fidelity review;
4. security and supply-chain review;
5. CI/CD and SDLC review;
6. documentation/README review;
7. iterative adversarial/red-team review;
8. remediation and exact-revision revalidation; and
9. the final completion audit.

The restoration PR must re-add `.github`, `scripts`, and `tests` to every routine protected-root definition and focused contract test. Because those roots are still exempt before that restoration PR merges, the restoration itself can be validated through the routine GitHub-only path. After merge, a negative admission test must prove that changes to each of the three roots are again rejected by routine admission and require protected maintenance.

## Safety invariant during the temporary window

This exception does **not** authorize bypassing deterministic CI, weakening assertions or thresholds, changing protected branch rules, publishing `Trusted PR Gate` from an untrusted token, or treating ordinary CI as merge authority. The dedicated App-bound trusted status and exact-subject validation remain mandatory.

---

[← Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md) · [Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
