# Trusted PR control plane

This document defines trusted pull-request validation and terminal merge-status authority for **ƳƤ AI QA Automation Framework**. The design separates candidate-controlled development feedback from the deterministic paths allowed to request the dedicated merge-status identity.

Repository source defines contracts and reviewed implementation. GitHub App installation state, webhook configuration, deployment state, credential custody, Actions Policy, and the branch ruleset are external authorities and must be observed independently. Source must never report those controls as active merely because code is designed to use them.

## Core invariant

A stable status name is not a trust boundary. A same-repository pull request can modify workflow YAML, tests, verifier scripts, dependency locks, or other control-plane bytes. Therefore ordinary `pull_request` CI is development evidence only. It cannot by itself authorize a protected merge.

The terminal status context is `Trusted PR Gate`, but the context string alone is insufficient. `Protect Main` must bind that context to the dedicated **ƳƤ Trusted PR Gate GitHub App** integration. A candidate-controlled workflow may manufacture another same-named status, but it must not satisfy the App-bound rule.

Model output has no authorization role in either trusted path.

## Two admission classes

Routine source changes and protected maintenance intentionally use different trust roots.

### Routine source-only automatic path

The routine chain is:

**ordinary PR CI completion → default-branch `workflow_run` wake-up → live deterministic admission → exact prospective merge + protected-object guard → deterministic validation → fresh admission revalidation → dedicated App token → live PR/merge-ref revalidation → App status → strict protected-branch enforcement**

The `workflow_run` payload is a wake-up signal only. `scripts/auto_trusted_preflight.py` independently re-fetches the triggering run, current `main`, the live PR, `refs/pull/<number>/merge`, ordered merge parents, and recursive Git trees.

Automatic admission requires all of the following:

1. exact reviewed ordinary CI workflow ID/name/path;
2. completed successful `pull_request` event;
3. expected repository, same head repository, repository owner actor, and triggering actor;
4. exactly one open non-draft same-repository PR for the head SHA targeting `main`;
5. PR base equals current `main`;
6. prospective merge has exactly two ordered parents `(base, head)`;
7. every automatic protected authority root has the same Git object ID at trusted base and prospective merge.

Any API failure, malformed/truncated response, PR-resolution saturation, ambiguity, fork head, stale base, identity drift, merge-parent mismatch, or protected-root change fails closed.

The trusted automatic workflow is selected from the default branch. Before candidate scripts execute it independently verifies the prospective merge parents and protected objects. Validation jobs remain read-only and secret-free. Only the final `trusted-pr-gate` Environment reporter can reference the dedicated App credential. The reporter re-runs live automatic admission on the trusted default-branch checkout before token minting and again uses canonical live PR/head/base/merge resolution immediately before status publication.

### Protected-maintenance external path

A PR that changes a protected authority root is deliberately not eligible for routine automatic authorization.

The steady-state protected-maintenance target is an **independently deployed GitHub App webhook admission service**. It removes routine owner `repository_dispatch` without replacing it with candidate self-certification.

The intended chain is:

**ordinary PR CI completion → external App webhook ingress → exact live PR/head/base/merge resolution → independent protected-object policy admission → exact run/job/artifact verification → terminal live re-resolution → dedicated App status → strict protected-branch enforcement**

The external service implementation is maintained under the already-protected `scripts/trusted_gate_service/` root. That source is a reference/deployment artifact only. Repository presence does not create terminal authority. Authority exists only when an independently administered deployment is pinned to reviewed bytes, holds the dedicated App credential outside candidate Actions, loads an independently administered policy, and is observed publishing through the App integration required by the live ruleset.

Until that deployment and live App-authored status are proven, protected maintenance remains **BLOCKED**, even when the candidate implementation and ordinary CI are green.

## Protected authority roots

The protected-root set is:

- `.github`
- `.claude`
- `.dockerignore`
- `.gitattributes`
- `.mcp.json`
- `.pre-commit-config.yaml`
- `CLAUDE.md`
- `Dockerfile`
- `evals`
- `examples`
- `pyproject.toml`
- `requirements`
- `scripts`
- `tests`
- `src/ai_qa_automation/__init__.py`
- `src/ai_qa_automation/io_safety.py`
- `src/ai_qa_automation/tools/__init__.py`
- `src/ai_qa_automation/tools/execution_env.py`

The automatic source-only path denies any object-ID change in this set. `.gitattributes` is protected because versioned attributes can alter archive/build bytes.

For protected maintenance, the external service derives the complete transition set itself from live base and prospective-merge Git trees. Missing paths use only the literal `MISSING` sentinel after a successful observation proves no object exists. A Git observation failure is not equivalent to absence.

## External App webhook trust boundary

The external deployment should use the existing dedicated App with only the permissions required for admission and status publication:

- Actions: read;
- Contents: read;
- Pull requests: read;
- Commit statuses: read/write;
- Metadata: implicit.

No repository contents write, Actions write, pull-request write, workflow write, administration, deployment, package, or issue authority is required.

Candidate workflows, tests, and scripts must never receive the App private key or terminal status-write token. The following are deployment-owned secrets/state and must not be committed to this repository or exposed to candidate Actions:

- App private key;
- webhook HMAC secret;
- independently administered maintenance policy and its deployment pin;
- durable webhook/publication idempotency database;
- deployment credentials and runtime configuration.

### Webhook admission

The reference service accepts only `workflow_run` `completed` wake-ups. It requires a bounded JSON request, GitHub Hookshot user agent, exact repository and installation identity, bounded delivery ID, and valid `X-Hub-Signature-256` HMAC verified against the raw body with constant-time comparison.

`X-GitHub-Delivery` is persisted as an idempotency key. A delivery ID cannot be reused for another workflow run.

The webhook body never supplies terminal authority. Every PR, ref, commit, tree, workflow, job, artifact, and status fact used for PASS is re-fetched from GitHub.

## Exact external subject resolution

The external service independently requires:

1. reviewed workflow ID, name, path, event, completed status, and successful conclusion;
2. expected repository and same-repository head;
3. expected repository-owner actor and triggering actor;
4. exactly one open, non-draft, same-repository PR for the run head targeting `main`;
5. current `main` equals the PR base;
6. live `refs/pull/<number>/merge` exists;
7. prospective merge has exactly two ordered parents `(base, head)`;
8. the complete protected-root transition set is derived from live base and merge trees.

Ambiguity, stale base, fork identity, API truncation/failure, malformed Git data, or merge-parent drift is non-PASS truth.

## Independent one-shot policy

Protected transitions are deny-by-default. The external service must not implement a generic rule equivalent to “owner PR + ordinary CI green + protected manifest = PASS.” That recreates the rejected self-certification loop.

The initial supported maintenance policy is a short-lived **one-shot policy administered outside this repository**. It pins exactly:

- schema version and immutable policy ID;
- repository name and numeric repository ID;
- PR number;
- head SHA;
- current `main` base SHA;
- prospective merge SHA;
- complete protected object transitions;
- UTC activation and expiration.

Illustrative schema only — this example is not authority-bearing:

```json
{
  "schema_version": 1,
  "policy_id": "externally-assigned-policy-id",
  "repository": "portyu9/ai-qa-automation",
  "repository_id": 1341984495,
  "pr_number": 123,
  "head_sha": "0000000000000000000000000000000000000000",
  "base_sha": "1111111111111111111111111111111111111111",
  "merge_sha": "2222222222222222222222222222222222222222",
  "protected_changes": [
    {
      "path": "scripts",
      "base_oid": "3333333333333333333333333333333333333333",
      "subject_oid": "4444444444444444444444444444444444444444"
    }
  ],
  "not_before": "2026-08-31T16:00:00Z",
  "expires_at": "2026-08-31T18:00:00Z"
}
```

The deployment pins the exact SHA-256 of this external file. The service opens it as a bounded no-follow regular file, revalidates file identity during ingestion, checks the deployment-supplied digest, uses duplicate-key-safe JSON parsing, and loads it once at startup.

Changing repository source cannot update an already installed external policy. A base/head/merge or protected-object drift creates a different subject and requires new independent admission.

## Execution evidence after policy admission

Only after exact policy admission may ordinary PR CI be considered execution evidence. The external service requires:

- exact successful reviewed `pull_request` run bound to the live head/ref;
- successful supply-chain, security, Playwright reference SUT, deterministic evaluation, and `Required PR Gate` jobs;
- exactly two successful Python quality/compatibility lanes;
- expected CI-contract verification and aggregate-gate steps;
- candidate workflow exact subject-binding and aggregate structure;
- exactly one unexpired `supply-chain-evidence` artifact for the selected run;
- canonical artifact metadata, run/head/ref binding, size, and SHA-256;
- bounded safe ZIP ingestion with traversal, duplicate, symlink/special-file, encryption, entry-count, archive-size, and uncompressed-size rejection;
- `build-manifest.json` exact schema/kind, prospective merge SHA, merge tree SHA, and clean tracked worktree identity.

Candidate CI therefore proves execution against bytes that an independent policy already authorized. It does not authorize those bytes.

## Publication, idempotency, and recovery

Immediately before publication the service re-resolves the live subject and re-runs the same policy. It durably binds subject, policy ID, and evidence URL, then records `PUBLISHING` **before** attempting the commit-status POST.

Status publication is treated as an irreversible side effect:

- no automatic replay is allowed after publication intent exists;
- ambiguous response or transport failure triggers status read-back reconciliation, not retry;
- recovery re-resolves the exact live subject and re-runs the policy;
- only an existing `success` status with the exact context, evidence URL, and expected dedicated-App creator identity may close the record as `SUCCESS`;
- if the outcome cannot be proven, the delivery remains blocked and the POST is not repeated;
- post-publication subject drift prevents durable success closure.

Transient GitHub failures may be retried only **before** publication begins, with bounded attempts and delay. Authentication, authorization, schema, policy, identity, evidence, and validation failures are non-retryable.

The SQLite delivery store uses an owner-controlled absolute path, regular-file/no-symlink checks, bounded database size/records, mode `0600`, `WAL`, and `synchronous=FULL`. Terminal publication state is durable authority and is not inferred from process memory.

## Reference service deployment contract

The HTTP entrypoint is:

```bash
python -m scripts.trusted_gate_service
```

It exposes:

- `GET /healthz` — low-information liveness;
- `POST /github/webhook` — bounded webhook ingress.

Deployment-owned environment variables are:

| Variable | Purpose |
|---|---|
| `TRUSTED_GATE_APP_ID` | Dedicated GitHub App ID |
| `TRUSTED_GATE_INSTALLATION_ID` | Exact repository installation |
| `TRUSTED_GATE_APP_PRIVATE_KEY` | App private key, outside candidate Actions |
| `TRUSTED_GATE_WEBHOOK_SECRET` | Webhook HMAC secret |
| `TRUSTED_GATE_REPOSITORY` | Must equal `portyu9/ai-qa-automation` |
| `TRUSTED_GATE_APP_BOT_LOGIN` | Expected App creator login for status reconciliation |
| `TRUSTED_GATE_POLICY_PATH` | Absolute external policy path |
| `TRUSTED_GATE_POLICY_SHA256` | Exact deployment-pinned policy digest |
| `TRUSTED_GATE_DB_PATH` | Absolute owner-controlled SQLite path |
| `TRUSTED_GATE_OPENSSL_BIN` | Optional absolute OpenSSL executable, default `/usr/bin/openssl` |
| `TRUSTED_GATE_BIND_HOST` | Optional bind host, default loopback |
| `TRUSTED_GATE_BIND_PORT` | Optional bind port, default `8080` |

The repository implementation deliberately does not claim production TLS termination, ingress rate limits, service supervision, host filesystem isolation, backup/restore, egress restriction, secret-manager guarantees, or deployment artifact integrity. Those are environment-owned requirements for an actual deployment.

## Dedicated App and ruleset contract

The live branch rule must require:

- context `Trusted PR Gate`;
- source/integration: the dedicated ƳƤ Trusted PR Gate App, not GitHub Actions;
- strict/up-to-date status semantics;
- no bypass actors;
- pull-request review-thread resolution;
- merge commits only;
- deletion and non-fast-forward protection.

The integration binding is critical. A same-named status from another actor is not equivalent authority.

For the external webhook service, the dedicated App additionally needs the reviewed `workflow_run` subscription and Actions-read permission. These platform facts must be independently observed after configuration; source cannot attest them.

## Legacy repository-dispatch path

The existing owner `repository_dispatch` maintenance workflow remains repository source during bootstrap, but it is no longer an accepted normal operator step for protected maintenance. It must not be used to manufacture progress merely because the external service is not yet deployed.

Do not remove the legacy path or its Environment-held App credential until the external path has produced live exact-subject evidence through the same dedicated App identity. After that proof, retirement is a separate protected maintenance revision requiring full ordinary CI, external policy admission, exact App status, and completion audit.

## Activation sequence

The external service does not become merge authority when its source lands. Activation requires:

1. comprehensive audit and exact packaging of a service revision;
2. deployment outside the candidate repository's Actions trust domain;
3. minimum App permissions and `workflow_run` webhook subscription;
4. independently installed digest-pinned one-shot policy for the exact protected subject;
5. qualifying ordinary CI evidence for that subject;
6. external service admission and publication;
7. independent read-back proving `Trusted PR Gate: success` on the exact head from the App integration required by the live ruleset;
8. fresh PR/main/merge/ruleset/App/deployment-identity revalidation before merge;
9. merge only the exact validated revision;
10. separate retirement of obsolete repository-dispatch credential/status publication after the external path is already proven.

If any external host, App, webhook, policy, credential, status, or ruleset fact is unavailable or unobserved, terminal truth is **BLOCKED**, not PASS.

## Verification and non-claims

Repository tests for `scripts/trusted_gate_service/` exercise webhook authentication, wrong repository/installation/actor/fork/workflow identity, policy expiry and malformed/duplicate/empty transitions, multi-root protected transitions, replay/idempotency, SQLite ownership, transient-before-publication retries, no-replay publication recovery, lost/ambiguous status responses, post-publication drift, unsafe artifact ZIPs, duplicate JSON, and exact build-manifest binding.

Those tests prove implementation behavior only. They do not prove an external deployment, webhook endpoint, App credential, one-shot policy installation, live integration permissions, ruleset binding, or App-authored status exists.

The terminal evidence rule remains:

**ordinary PR green ≠ protected merge authority**

**repository service source ≠ independently deployed trusted service**

**same status context ≠ required App integration**

**unobserved external control ≠ PASS**

---

[← CI/CD](CI_CD.md) · [Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
