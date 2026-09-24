# Deterministic security-alert routing

> **Scope:** this document describes the repository-owned routing policy and its live Security Auto-Heal integration. The controller persists an exact-run route plan before new repair mutation, revalidates that plan against live current-main evidence before acting, and carries the originating route provenance into durable terminal closure. Protected remediation authoring remains a separate follow-on authority boundary.

## Purpose

Security findings must not choose their own remediation authority. The routing core converts an exact CodeQL alert observation plus code-owned policy into one bounded, provenance-bound decision.

The routing chain is:

**exact current-main alert → deterministic metadata validation → protected-path classification → reviewed strategy selection → strategy-scoped attempt budget → external-evidence requirement → canonical routing record**

Model text, alert descriptions, review comments, SARIF content, or actor-like fields in the alert payload cannot select an authority lane.

## Inputs and authority

A route is bound to:

- exact repository identity `portyu9/ai-qa-automation` and base branch `main`;
- exact CodeQL tool identity;
- alert number plus agreeing top-level and most-recent-instance state;
- rule id and security severity;
- canonical repository-relative Python path and complete start/end line-and-column region;
- exact `refs/heads/main` instance SHA;
- exact current-main SHA;
- deterministic alert fingerprint binding alert number, rule, normalized security severity, complete location region, message text, and current-main SHA;
- versioned routing policy;
- the existing automatic security-severity floor, which may not be configured below 7;
- exact remediation strategy/version;
- the existing per-strategy attempt ceiling, which remains within the reviewed 1..3 bound;
- strategy-version-scoped attempt count;
- bounded CodeQL Autofix availability evidence when the model/autofix lane is considered.

Malformed or ambiguous identity, disagreeing alert/instance state, boolean or non-finite severity, unsafe/control-character paths, invalid SHAs, oversized alert messages, ambiguous deterministic strategies, non-object batch entries, and malformed attempt accounting fail closed without manufacturing a routing record. File-backed alert/config ingestion resolves every parent component with no-follow directory semantics, opens the final target with no-follow/non-blocking semantics, requires a bounded regular file owned by the routing process and not writable by group or other users, and re-proves both the live target-name identity and live parent-path identity after the bounded read before its bytes can influence routing.

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

Protected classification occurs before ordinary mutation admission. A protected finding cannot fall through to model/autofix authority even if its rule would otherwise be supported. The live controller treats `protected-independent-remediation` as non-mutating routing truth: it reports the route but does not author protected code. The protected set is deliberately stricter than the historical `neverModifyPaths`: it also includes the five authority-bearing verifier/status files under `deterministicOnlyPaths`, preserving #211's independent-authoring boundary.

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
- existing records are opened non-blocking and must remain bounded regular files whose live target-name identity still matches the verified descriptor;
- an identical existing/concurrent record is idempotent only after ownership, mode, bounded-read, digest, exact target-file fsync, parent-directory fsync, post-sync name→inode revalidation, and live parent-path identity checks succeed, so neither unflushed file data nor a prior post-link durability failure can silently become accepted evidence;
- publication uses an owner-only fsynced temporary file and atomic hard-link creation;
- symlink parents/targets, special-file blocking, parent traversal, concurrent conflicting publication, name/inode swaps, parent-path swaps, and read-back drift are rejected.

The record explains deterministic routing truth. It is **not** itself merge authority, validation proof, or a terminal remediation certificate.

## Resource and concurrency bounds

One routing batch is limited to 100 distinct alert identities. Duplicate alert numbers fail closed. Attempt state is limited to 16 strategy epochs per alert and bounded integer counts. Alert message ingestion and persisted record bytes are explicitly bounded.

The live controller preserves bounded GitHub pagination and exact-current-main re-fetch semantics around the pure router. One route plan accepts at most 100 open alert identities, is bound to one Security Auto-Heal workflow run/attempt and exact main SHA, and is rejected if the open-alert set, route bytes, attempt accounting, Autofix evidence state, or current main drifts before mutation.

## Live controller integration

The Security Auto-Heal workflow uses an evidence-first two-phase boundary for **new repair creation**, with the phases separated by job-level capabilities:

1. a trusted-default-branch `route-plan` job has read-only GitHub authority (`actions`, `contents`, `pull-requests`, and `security-events` read) and fetches exact current main plus bounded open CodeQL alerts;
2. the deterministic router computes canonical route records, including strategy-scoped prior-attempt state and GET-only Autofix availability evidence where relevant;
3. that read-only job writes one canonical run-bound route plan only under absolute runner-owned `$RUNNER_TEMP`, creates the child directory/file exclusively through no-follow descriptor-relative APIs with private 0700/0600 modes, and fsyncs the file plus child and runner-temp directories;
4. the read-only job uploads that exact plan with the repository-pinned `actions/upload-artifact` revision and exposes only the resulting artifact id/digest as job outputs;
5. only after the planning job succeeds does the write-capable `reconcile` job start; it restores the same-run artifact with the repository-pinned `actions/download-artifact` revision;
6. reconcile requires the artifact id, name, and GitHub-reported digest, re-fetches the artifact and exact Security Auto-Heal run, re-fetches main/alerts/attempt state, and requires canonical route bytes to match the persisted plan;
7. only `ordinary-deterministic-autoheal` and `ordinary-bounded-autofix` may create repair branches/commits/PRs;
8. generated repair commits immutably bind both the route-record digest and route-plan digest in validated commit-message trailers, while generated repair markers bind those same digests plus routing-policy version, originating workflow run/attempt, artifact identity/digest, and the Autofix evidence state used by the route;
9. later repair admission recomputes the same live route, rejects missing route provenance, requires the immutable repair-commit trailers to equal the revalidated route-record and marker plan digests, and requires successful originating controller-run/artifact provenance before existing diff, CodeQL, trusted-gate, and merge guards apply;
10. durable terminal closure re-verifies those immutable commit digests and the successful originating route artifact/run, then emits schema-v2 terminal evidence carrying the same route-record digest, route-plan digest, route run/attempt, artifact identity/digest, decision, authority, policy version, and Autofix evidence alongside exact post-merge CI, CodeQL, trusted-gate, merge, and fixed-alert evidence.

The route-planning job has no GitHub write permission. The later mutation job cannot run unless planning and artifact publication succeed, and current-main plus canonical route truth are re-proved after artifact restoration. Thus a planning bug cannot gain repository mutation authority merely because it executes in the same workflow.

For model routes whose proposal is not yet available, provider submission uses a separate non-authoritative GitHub Actions check-run intent bound to exact main, alert fingerprint, route digest, strategy, and attempt. The neutral check cannot satisfy the App-bound `Trusted PR Gate`. It exists only to suppress provider replay: once exact intent exists, later controller cycles are GET-only until provider evidence becomes affirmative or the subject changes.

Existing stale-supersession and post-merge validation paths remain governed by their existing exact-subject evidence. Terminal closure now additionally fails closed unless the merged repair commit and originating route artifact reproduce the marker’s persisted route provenance. The integration does not give `protected-independent-remediation` code-authoring authority.

## Remaining #212 boundaries

The following are deliberately not claimed complete by this integration:

1. `protected-independent-remediation` still requires #211's distinct authoring identity and authority, separate from the Trusted PR Gate certifier;
2. a fresh autonomous acceptance cycle is still required to prove the complete route-plan → repair → scheduled trusted gate → merge → resulting-main CodeQL/CI → route-bound terminal-certificate chain without manual substitution.

Until that live acceptance is observed, the implementation provides deterministic route-bound mutation and terminal-certification logic, but repository history does not yet prove a fresh unattended end-to-end closure under this exact integration.

---

[← Documentation home](README.md) · [Security architecture](SECURITY.md) · [Trusted PR control plane](TRUSTED_PR_CONTROL_PLANE.md)
