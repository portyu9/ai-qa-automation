# Trusted PR control plane

This document defines trusted pull-request validation and terminal merge-status authority for **ƳƤ AI QA Automation Framework**. Candidate-controlled CI is development evidence; it is never its own merge authority.

Repository source defines reviewed behavior and validation contracts. GitHub App installation state, webhook configuration, deployment state, credential custody, one-shot policy, cloud resource identity, runtime revision, Actions Policy, and branch-ruleset configuration are external authorities and must be observed independently.

## Core invariant

The terminal context is `Trusted PR Gate`, but the context string alone is not authority. The live branch rule must bind that context to the dedicated **ƳƤ Trusted PR Gate GitHub App** integration. A candidate workflow may create a same-named status, but it must not satisfy the App-bound rule.

Model output has no authorization role.

The authority chain is:

**objective → advisory reasoning → deterministic policy → controlled tool → real execution/observation → persisted evidence → deterministic validation → structured terminal report**

## Two admission classes

Routine source changes and protected maintenance intentionally use different trust roots.

### Routine source-only automatic path

The routine chain is:

**ordinary PR CI completion → default-branch `workflow_run` wake-up → live deterministic admission → exact prospective merge + protected-object guard → deterministic validation → fresh admission revalidation → dedicated App token → live PR/merge-ref revalidation → App status → strict protected-branch enforcement**

Automatic admission requires all of the following:

1. exact reviewed ordinary CI workflow identity;
2. completed successful `pull_request` event;
3. expected repository and same-repository head;
4. expected repository owner actor and triggering actor;
5. exactly one open non-draft PR for the head SHA targeting `main`;
6. PR base equals current `main`;
7. prospective merge has exactly two ordered parents `(base, head)`;
8. every protected authority root has the same Git object ID at trusted base and prospective merge.

Any API failure, malformed or truncated response, PR-resolution saturation, ambiguity, fork head, stale base, identity drift, merge-parent mismatch, or protected-root change fails closed.

### Protected-maintenance external path

A PR that changes a protected authority root is deliberately not eligible for routine automatic authorization.

The protected-maintenance chain is:

**ordinary PR CI completion → external App webhook ingress → exact live PR/head/base/merge resolution → independently administered protected-object policy → exact run/job/artifact verification → terminal live re-resolution → dedicated App status → strict protected-branch enforcement**

The external service implementation lives under the already-protected `scripts/trusted_gate_service/` root. Repository presence does not create authority. Authority exists only when an independently administered deployment is pinned to reviewed bytes, holds the App credential outside candidate Actions, loads an independently administered one-shot policy, and is observed publishing through the App integration required by the live ruleset.

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

The external service derives the complete transition set itself from live base and prospective-merge Git trees. Missing paths use only the literal `MISSING` sentinel after a successful observation proves no object exists. Observation failure is not equivalent to absence.

## External App trust boundary

The external deployment should grant the dedicated App only the permissions needed for admission and status publication:

- Actions: read;
- Contents: read;
- Pull requests: read;
- Commit statuses: read/write;
- Metadata: implicit.

Candidate workflows, tests, and scripts must never receive the App private key or a terminal status-write token.

The following are deployment-owned and must not be committed to the repository or supplied to candidate Actions:

- cloud account identifiers and resource ARNs;
- concrete cloud resource names and public endpoint URLs;
- private configuration namespaces and parameter paths;
- App ID, installation ID, bot login, and deployment bindings;
- App private key and webhook HMAC secret;
- independently administered one-shot policy and its deployment digest pin;
- durable webhook/publication state;
- deployment credentials, package digest, and runtime-version identity.

Public source may define **configuration keys and schemas**, but not a real deployment's values.

## Webhook admission

The service accepts only bounded `workflow_run` `completed` wake-ups. It requires the GitHub Hookshot user agent, a bounded delivery ID, exact repository/installation identity, and valid `X-Hub-Signature-256` over the raw body using constant-time comparison.

`X-GitHub-Delivery` is persisted as the idempotency key. A delivery ID cannot be reused for another workflow run.

The webhook body never supplies terminal authority. Every PR, ref, commit, tree, workflow, job, artifact, and status fact used for PASS is independently re-fetched from GitHub.

For the AWS Lambda adapter, unauthenticated requests may read only the deployment-owned webhook secret needed for HMAC verification. App identity, private key, installation identity, repository binding, policy, and GitHub evidence are read only after HMAC admission.

## Exact subject resolution

The external service independently requires:

1. reviewed workflow ID, name, path, event, completion state, and successful conclusion;
2. expected repository and same-repository head;
3. expected repository-owner actor and triggering actor;
4. exactly one open, non-draft, same-repository PR for the run head targeting `main`;
5. current `main` equals the PR base;
6. live `refs/pull/<number>/merge` exists;
7. prospective merge has exactly two ordered parents `(base, head)`;
8. the complete protected-root transition set is derived from live base and merge trees.

Ambiguity, stale base, fork identity, API truncation/failure, malformed Git data, or merge-parent drift is non-PASS truth.

## Independent one-shot policy

Protected transitions are deny-by-default. The service must not implement a generic rule equivalent to “owner PR + ordinary CI green + protected changes = PASS.” That would recreate candidate self-certification.

The supported maintenance policy is a short-lived one-shot policy administered outside the repository. It pins exactly:

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

The deployment pins the exact SHA-256 of the policy. Repository source cannot update an already installed external policy or its deployment pin. Base/head/merge or protected-object drift creates a different subject and requires new independent admission.

## Execution evidence after policy admission

Only after exact policy admission may ordinary PR CI be considered execution evidence. The external service requires:

- exact successful reviewed `pull_request` run bound to the live head/ref;
- successful supply-chain, security, Playwright reference SUT, deterministic evaluation, and `Required PR Gate` jobs;
- exactly two successful Python quality/compatibility lanes;
- expected CI-contract verification and aggregate-gate steps;
- candidate workflow subject-binding and aggregate structure;
- exactly one unexpired `supply-chain-evidence` artifact for the selected run;
- canonical artifact metadata, run/head/ref binding, bounded size, and SHA-256;
- safe bounded ZIP ingestion with traversal, duplicate, symlink/special-file, encryption, entry-count, archive-size, and uncompressed-size rejection;
- `build-manifest.json` exact schema/kind, prospective merge SHA, merge tree SHA, and clean tracked worktree identity.

Candidate CI proves execution against bytes that an independent policy already authorized. It does not authorize those bytes.

## Publication, idempotency, and recovery

Immediately before publication the service re-resolves the live subject and re-runs the same policy. It durably binds subject, policy ID, and evidence URL, then records `PUBLISHING` **before** attempting the commit-status POST.

Status publication is treated as an irreversible side effect:

- no automatic replay is allowed after publication intent exists;
- ambiguous response or transport failure triggers status read-back reconciliation, not retry;
- recovery re-resolves the exact live subject and re-runs the policy;
- only an existing `success` status with the exact context, evidence URL, and expected App creator identity may close the record as `SUCCESS`;
- if the outcome cannot be proven, the delivery remains blocked and the POST is not repeated;
- post-publication subject drift prevents durable success closure.

Transient GitHub failures may be retried only before publication begins, with bounded attempts and delay. Authentication, authorization, schema, policy, identity, evidence, and validation failures are non-retryable.

## Persistence adapters

The persistent reference adapter uses an owner-controlled SQLite file with regular-file/no-symlink checks, bounded database size/records, mode `0600`, `WAL`, and `synchronous=FULL`.

The AWS adapter uses one DynamoDB table whose billing/capacity mode is deployment-owned and independently observed. New delivery creation and the hard record-count increment occur in one transaction. Conditional writes provide single delivery ownership across concurrent Lambda invocations. A duplicate active invocation has no mutation authority; stale pre-publication ownership may be reacquired only after the processing lease and only inside the bounded retry budget. `PUBLISHING` is never reacquired for another POST. Strongly consistent reads reconcile races and recovery.

DynamoDB transport failure is infrastructure failure, not policy truth. Terminal publication state is durable authority and is never inferred from Lambda/process memory.

## Deployment contracts

### Persistent POSIX reference adapter

The HTTP entrypoint is:

```bash
python -m scripts.trusted_gate_service
```

It exposes `GET /healthz` and `POST /github/webhook`. The persistent adapter's concrete environment values are deployment-owned and must not be committed.

### AWS Lambda + DynamoDB adapter

The low-idle-cost AWS entrypoint is:

```text
scripts.trusted_gate_service.aws_lambda.handler
```

The public source defines three deployment binding keys:

| Variable | Purpose |
|---|---|
| `TRUSTED_GATE_CONFIG_PREFIX` | Private SSM namespace chosen by the deployment |
| `TRUSTED_GATE_TABLE_NAME` | Exact deployment-owned DynamoDB state table |
| `TRUSTED_GATE_POLICY_SHA256` | Exact independently pinned policy digest |

The concrete values are private deployment configuration and must not appear in source, tests, PR text, issues, or logs.

Under the private SSM prefix the adapter uses reviewed suffixes for App ID, bot login, installation ID, private key, repository identity, webhook secret, and policy. The code does not contain the deployment's real prefix or those identity values.

The runtime IAM contract is deliberately narrow:

- SSM: only reads required by the private parameter namespace;
- DynamoDB: `GetItem`, `UpdateItem`, and `TransactWriteItems` on the exact state table;
- CloudWatch Logs: stream creation and writes only for the function's own log group.

No VPC, NAT gateway, API Gateway, load balancer, EC2, Fargate, container registry, or repository/cloud administration permission is required by the runtime.

The intended AWS runtime is Python 3.13 on Amazon Linux 2023. The shared App signer requires an addressable inherited-descriptor namespace and an absolute OpenSSL executable. It prefers `/proc/self/fd/<n>` and allows `/dev/fd/<n>` only after deterministic availability checks; activation therefore requires real runtime smoke proof of the selected namespace. Deployment evidence must record the exact reviewed source SHA, deployment ZIP SHA-256, Lambda `CodeSha256`, architecture, runtime, and runtime-version identity. Runtime updates beneath authority-bearing code must be explicit maintenance events.

Cost/resource controls are part of deployment truth. Memory, timeout, reserved concurrency, log retention, DynamoDB billing/capacity mode, deletion protection, Function URL configuration, and no-VPC state must be observed from AWS before activation.

The repository implementation deliberately does not claim an AWS deployment, cloud account identity, endpoint, webhook binding, runtime executable presence, runtime-version pin, backup/restore, secret custody, or deployment artifact integrity until those facts are independently observed.

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

Do not remove the legacy path or its Environment-held App credential until the external path has produced live exact-subject evidence through the same dedicated App identity. Retirement is a separate protected-maintenance revision requiring full ordinary CI, external policy admission, exact App status, and completion audit.

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

For AWS, deployment proof additionally includes exact deployment-ZIP and Lambda code-digest binding, runtime smoke verification, runtime-version control, least-privilege IAM read-back, DynamoDB configuration read-back, Function URL configuration read-back, log-retention read-back, and no-VPC verification before the App webhook is pointed at the endpoint.

If any external host, App, webhook, policy, credential, status, ruleset, runtime, or deployment fact is unavailable or unobserved, terminal truth is **BLOCKED**, not PASS.

## Verification and non-claims

Repository tests exercise webhook authentication, wrong repository/installation/actor/fork/workflow identity, policy expiry and malformed/duplicate/empty transitions, multi-root protected transitions, replay/idempotency, SQLite ownership, DynamoDB concurrent ownership, stale-processing recovery, transaction record bounds, transport/race separation, Lambda request parsing, private SSM configuration binding, HMAC-before-private-key admission, policy digest binding, transient-before-publication retries, no-replay publication recovery, lost/ambiguous status responses, post-publication drift, unsafe artifact ZIPs, duplicate JSON, and exact build-manifest binding.

Those tests prove implementation behavior only. They do not prove an external deployment, webhook endpoint, App credential, one-shot policy installation, live integration permissions, ruleset binding, AWS runtime properties, runtime-version control, or App-authored status exists.

The terminal evidence rule remains:

**ordinary PR green ≠ protected merge authority**

**repository service source ≠ independently deployed trusted service**

**same status context ≠ required App integration**

**unobserved external control ≠ PASS**

---

[← CI/CD](CI_CD.md) · [Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
