# Deterministic security-alert routing

> **Scope:** this document describes the repository-owned routing policy core introduced for issue #212. It does **not** claim that the live Security Auto-Heal controller consumes the router yet. Until explicit controller integration is merged and revalidated, the existing controller remains authoritative for live remediation.

## Purpose

Security findings must not choose their own remediation authority. The routing core converts an exact CodeQL alert observation plus code-owned policy into one bounded, provenance-bound decision.

The routing chain is:

**exact current-main alert → deterministic metadata validation → protected-path classification → reviewed strategy selection → strategy-scoped attempt budget → external-evidence requirement → canonical routing record**

Model text, alert descriptions, review comments, SARIF content, or actor-like fields in the alert payload cannot select an authority lane.

## Inputs and authority

A route is bound to:

- exact repository identity `portyu9/ai-qa-automation` and base branch `main`;
- exact CodeQL tool identity;
- alert number and state;
- rule id and security severity;
- canonical repository-relative Python path and start line;
- exact `refs/heads/main` instance SHA;
- exact current-main SHA;
- deterministic alert fingerprint binding alert number, rule, normalized security severity, path, line, message text, and current-main SHA;
- versioned routing policy;
- the existing automatic security-severity floor, which may not be configured below 7;
- exact remediation strategy/version;
- the existing per-strategy attempt ceiling, which remains within the reviewed 1..3 bound;
- strategy-version-scoped attempt count;
- bounded CodeQL Autofix availability evidence when the model/autofix lane is considered.

Malformed or ambiguous identity, unsafe paths, invalid SHAs, oversized alert messages, ambiguous deterministic strategies, and malformed attempt accounting fail closed without manufacturing a routing record. File-backed alert/config ingestion also resolves every parent component with no-follow directory semantics and requires the final input file to be process-owned and not writable by group or other users before its bytes can influence routing.

## Decision matrix

| Decision | Meaning | Mutation authority |
|---|---|---|
| `ordinary-deterministic-autoheal` | A reviewed deterministic strategy exactly matches the ordinary source path/rule. | existing deterministic Security Auto-Heal lane |
| `ordinary-bounded-autofix` | A reviewed ordinary model path has live Autofix availability and remaining strategy budget. | existing bounded CodeQL Autofix lane |
| `protected-independent-remediation` | The finding targets a never-modify/control-plane path. | independent protected remediation only; issue #211 |
| `unsupported-rule` | Rule is outside the code-owned allowlist. | none |
| `unsupported-path` | Path has no reviewed remediation surface/strategy. | none |
| `below-severity-floor` | Finding severity is below the configured automatic floor. | none |
| `stale-alert` | State, ref, SHA, fingerprint, or expected strategy no longer matches the current subject. | none |
| `attempt-budget-exhausted` | The exact strategy/version has consumed its bounded attempt budget. | none |
| `blocked-external-evidence` | A model/autofix route lacks live affirmative Autofix availability. | none |

Protected classification occurs before ordinary mutation admission. A protected finding cannot fall through to model/autofix authority even if its rule would otherwise be supported. For routing purposes, the protected set is deliberately stricter than the live controller's historical `neverModifyPaths`: it also includes the five authority-bearing verifier/status files currently listed under `deterministicOnlyPaths`. That keeps trusted status and validation code on #211's independent-authoring path when this router is later integrated, without changing the live controller in this policy-core PR.

## Current rule coverage

The routing policy is stored under `routingPolicy` in `.github/security-autoheal.json`. Tests bind it to the current Security Auto-Heal strategy constants so duplicated policy cannot silently drift.

Current explicit classes include:

- `py/reflective-xss` on `examples/reference_sut/app.py` → deterministic reference-SUT repair;
- `py/overly-permissive-file` under `tests/` → deterministic permission repair;
- `py/clear-text-logging-sensitive-data` on the authority-bearing verifier/status files currently listed under `deterministicOnlyPaths` → independent protected remediation;
- other reviewed rules under `src/`, `examples/`, or `tests/` → bounded Autofix only when live availability evidence exists;
- any supported finding under `.github/`, another `neverModifyPaths` entry, or one of those verifier/status paths → independent protected remediation.

This explicitly represents the ordinary class demonstrated by alert #7 and the protected-control-plane class demonstrated by alert #17 without granting the normal auto-healer authority over `.github/`.

## Attempt epochs

Attempt accounting is keyed by the exact strategy string/version. Exhaustion of `strategy-v1` cannot be reset by replaying the same strategy. A materially different reviewed strategy may start a distinct epoch only because its version is explicitly different in code-owned policy; the routing record exposes the exact strategy and count used.

## Routing records

Each successful classification emits a bounded canonical JSON record containing the exact repository/base-branch identity, subject and alert state, decision, reason, authority, strategy/version, attempt count, routing-policy version, a SHA-256 digest of the exact normalized routing-policy inputs, and a SHA-256 record digest. A threshold or attempt-policy change therefore changes the policy digest even when the schema/version label remains the same.

`security_alert_routing.persist_record` publishes that evidence without overwrite:

- every parent path component is opened with no-follow directory semantics;
- the final parent and any pre-existing record must be owned by the routing process and not writable by group/other users;
- an existing different record is a conflict, not an overwrite;
- an identical existing record is idempotent only after ownership, mode, bounded-read, and digest checks succeed;
- publication uses an owner-only fsynced temporary file and atomic hard-link creation;
- symlink parents/targets, parent traversal, concurrent conflicting publication, and read-back drift are rejected.

The record explains deterministic routing truth. It is **not** itself merge authority, validation proof, or a terminal remediation certificate.

## Resource and concurrency bounds

One routing batch is limited to 100 distinct alert identities. Duplicate alert numbers fail closed. Attempt state is limited to 16 strategy epochs per alert and bounded integer counts. Alert message ingestion and persisted record bytes are explicitly bounded.

API enumeration/pagination remains an integration concern: live controller integration must preserve existing bounded GitHub pagination and exact-current-main re-fetch semantics rather than treating this pure routing module as network evidence.

## Integration boundary

The current PR intentionally does not modify `.github/scripts/security_autoheal.py` or any workflow. Before #212 can close, a later exact-main integration must:

1. obtain live current-main alerts through the existing bounded GitHub API layer;
2. build/persist the routing record before mutation admission;
3. make the controller obey the route rather than recomputing implicit path/rule authority;
4. preserve the normal lane's never-modify boundary;
5. connect `protected-independent-remediation` only to the independent authority built under #211;
6. bind terminal outcome back to the same routing record and exact revision;
7. add interruption/recovery and pagination tests at the integrated controller level.

Until those steps are merged and proven, this module is a deterministic policy foundation, not an active autonomous routing authority.

---

[← Documentation home](README.md) · [Security architecture](SECURITY.md) · [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md)
