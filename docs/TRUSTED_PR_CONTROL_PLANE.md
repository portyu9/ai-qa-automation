# Trusted PR control plane

This document defines trusted pull-request validation and terminal merge-status authority for **ƳƤ AI QA Automation Framework**. Candidate-controlled CI is development evidence; it is never its own merge authority.

Repository source defines reviewed behavior and validation contracts. GitHub App installation state, webhook configuration, deployment state, credential custody, one-shot policy, cloud resource identity, runtime revision, Actions Policy, and branch-ruleset configuration are external authorities and must be observed independently.

## Core invariant

The terminal context is `Trusted PR Gate`, but the context string alone is not authority. The live branch rule must bind that context to the dedicated **ƳƤ Trusted PR Gate GitHub App** integration. A candidate workflow may create a same-named status, but it must not satisfy the App-bound rule.

Model output has no authorization role.

The authority chain is:

**objective → advisory reasoning → deterministic policy → controlled tool → real execution/observation → persisted evidence → deterministic validation → structured terminal report**

## Three admission classes

The control plane distinguishes owner-routine changes, finite governed-bot changes, and unrecognized protected maintenance. The strict App-bound branch rule is unchanged across all three classes.

### Owner-routine automatic path

The owner-routine chain is:

**ordinary PR CI completion → default-branch `workflow_run` wake-up → live deterministic admission → exact prospective merge + zero protected-object drift → deterministic validation → fresh admission revalidation → dedicated App token → exact subject-bound App status → strict protected-branch enforcement**

Owner-routine admission requires exact reviewed pull-request CI identity, expected repository-owner actor and triggering actor, one open same-repository PR targeting `main`, current-base equality, exact ordered prospective-merge parents `(base, head)`, and identical Git object IDs for every routine-protected authority root.

### Governed-bot automatic path

The repository automatically admits exactly three governed bot lanes:

1. canonical Dependabot GitHub Actions updates under the reviewed `dependabot/github_actions/...` namespace;
2. GitHub Actions dependency promotions under `automation/dependency-promotion-...`;
3. GitHub Actions CodeQL auto-heal repairs under `automation/codeql-autoheal-...`.

Bot identity alone is not authority. A serialized five-minute schedule running trusted default-branch bytes discovers at most one bounded governed-bot candidate per reconciliation pass. Discovery is same-repository and exact-current-main scoped, prioritizes security auto-heal before Dependabot Actions and dependency promotions, and fresh-GETs each candidate before selection. A candidate must be open, non-draft, definitively mergeable, and match the canonical bot identity plus reviewed branch grammar before subject resolution proceeds.

The gate then runs lane-specific deterministic policy from trusted `main`: exact bot numeric identity, same-repository branch ownership, reviewed branch grammar, source PR or CodeQL-alert lineage, current-base binding, exact merge parents, and allowed change semantics. Dependency promotions are regenerated from the signed Dependabot intent under trusted Python interpreters. Security auto-heal rebinds the marker to the exact live CodeQL alert; deterministic-only verifier repairs must reproduce the code-owned transformation byte-for-byte.

After lane proof, the full trusted validation graph executes against the exact prospective merge. For governed bots, the subject guard additionally proves that the governed head tree is identical to the prospective-merge tree, then a bot-only CodeQL job analyzes the exact governed head ref/SHA with only `actions: read`, `contents: read`, and `security-events: write`. The aggregate requires that CodeQL job to succeed for bot lanes and to be skipped for owner-routine admission. Before App publication, the gate fresh-resolves admission and re-runs terminal bot policy, including live CodeQL remediation proof for security auto-heal. Candidate validation remains secret-free and read-only except for the narrowly scoped CodeQL result upload; only the terminal reporter can obtain the dedicated App credential.

The resulting `Trusted PR Gate` status is not head-only evidence. Its target binds the exact PR number, base SHA, head SHA, prospective merge SHA, and trusted-gate workflow run. Merge controllers do not possess App status-write authority. They independently require that exact App-authored binding, re-fetch the live PR/merge ref/ordered parents, and re-run their lane policy before merge.

Any API failure, malformed/truncated response, ambiguity, stale base, non-definitive mergeability, identity drift, branch/source mismatch, merge-parent/tree mismatch, failed trusted validation/CodeQL, or terminal subject drift fails closed.

### Unrecognized protected-maintenance external path

A protected change that does not match one of the finite governed-bot policies is not eligible for repository-hosted automatic authorization.

Its chain is:

**ordinary PR CI completion → external App webhook ingress → exact live PR/head/base/merge resolution → independently administered protected-object policy → exact run/job/artifact verification → terminal live re-resolution → dedicated App status → strict protected-branch enforcement**

The external service implementation lives under `scripts/trusted_gate_service/`. Repository presence does not create authority. External authority exists only when an independently administered deployment is pinned to reviewed bytes, holds its App credential outside candidate Actions, loads an independently administered one-shot policy, and is observed publishing through the App integration required by the live ruleset.

Repository `repository_dispatch` is not a protected-maintenance authority and no normal-use dispatch path remains in `ci.yml`.

## Protected authority roots

The owner-routine automatic guard protects these authority roots from candidate change. Governed bot lanes may cross only the roots permitted by their lane-specific deterministic policy:

- `.github`
- `scripts`
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
- `src/ai_qa_automation/__init__.py`
- `src/ai_qa_automation/io_safety.py`
- `src/ai_qa_automation/tools/__init__.py`
- `src/ai_qa_automation/tools/execution_env.py`

The external protected-maintenance service deliberately retains a broader protected-root vocabulary. Its set is the owner-routine set above plus `tests`. That superset lets the independently deployed service reason about test transitions whenever break-glass admission is invoked, while test-only owner maintenance remains eligible for routine automatic admission.

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

Lambda failure diagnostics are deliberately bounded and non-authoritative. The adapter emits only the fixed stage identifier and exception class for `webhook_auth`, `static_config`, `policy_load`, `service_construct`, or `delivery_acquire_or_handle`; it never logs exception messages, request bodies, headers/signatures, parameter names, policy bytes/digests, private configuration values, or cloud resource identity. The existing 403/400/503 response semantics remain unchanged, and a diagnostic stage is never evidence of PASS.

## Exact subject resolution

The external service independently requires:

1. reviewed workflow ID, name, path, event, completion state, and successful conclusion;
2. expected repository and same-repository head;
3. expected repository-owner actor and triggering actor;
4. exactly one open, non-draft, same-repository PR for the run head targeting `main`;
5. current `main` equals the PR base;
6. live `refs/pull/<number>/merge` exists;
7. prospective merge has exactly two ordered parents `(base, head)`;
8. the complete external protected-root transition set is derived from live base and merge trees.

Ambiguity, stale base, fork identity, API truncation/failure, malformed Git data, or merge-parent drift is non-PASS truth.

The candidate `ci.yml` must bind `CI_SUBJECT_SHA` directly to `github.sha`. The external service independently verifies that binding before accepting ordinary CI as execution evidence; candidate event payloads cannot select an alternate merge subject.

## Independent one-shot policy

External protected transitions are deny-by-default. The service must not implement a generic rule equivalent to “owner PR + ordinary CI green + protected changes = PASS.” That would recreate candidate self-certification.

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
      "path": "requirements",
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
- candidate workflow subject binding and aggregate structure;
- exactly one unexpired `supply-chain-evidence` artifact for the selected run;
- canonical artifact metadata, run/head/ref binding, bounded size, and SHA-256;
- safe bounded ZIP ingestion with traversal, duplicate, symlink/special-file, encryption, entry-count, archive-size, and uncompressed-size rejection;
- `build-manifest.json` exact schema/kind, prospective merge SHA, merge tree SHA, and clean tracked-worktree identity.

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
- DynamoDB: direct `GetItem` for strongly consistent reads and direct `UpdateItem` for conditional state transitions on the exact state table;
- DynamoDB creation: `PutItem` on that exact table only when `dynamodb:EnclosingOperation` equals `TransactWriteItems`, because `_create()` uses a transaction containing the bounded counter `Update` and new-delivery `Put`;
- DynamoDB exclusions: standalone `PutItem`, `DeleteItem`, `Query`, `Scan`, table administration, wildcard actions/resources, and other broad DynamoDB authority remain denied; a generic `dynamodb:TransactWriteItems` IAM action is not a substitute for the underlying item permissions and is not required by this implementation;
- CloudWatch Logs: stream creation and writes only for the function's own log group.

`scripts.trusted_gate_service.iam_contract.validate_dynamodb_runtime_policy` provides a deterministic repository-side linter for reviewed policy-document shape. It accepts an externally supplied policy document and exact table resource identifier, rejects authority expansion or a missing transaction-only `PutItem`, and deliberately does **not** claim to evaluate effective IAM. Deployment activation and revalidation still require live IAM read-back/simulation against the real execution principal and exact table: direct `GetItem`/`UpdateItem` must be allowed, transaction-enclosed `PutItem` must be allowed, standalone `PutItem` must be denied, and the forbidden/broad actions above must remain denied.

Candidate-controlled workflows have no authority to administer this external runtime IAM policy. Repository tests and the linter can constrain reviewed source behavior; they cannot mutate or attest the independently administered deployment.

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

## Repository-dispatch retirement

The former repository-owned protected-maintenance paths are retired:

- `ci.yml` has no `repository_dispatch` trigger, client-payload subject selector, protected-manifest admission block, or repository-hosted maintenance status reporter;
- the superseded `trusted-pr-evidence.yml` workflow and `trusted_pr_evidence.py` verifier are absent;
- `trusted_pr_control.py` retains only shared bounded GitHub/subject primitives used by the routine automatic reporter; its former owner-dispatch CLI/status publisher is absent;
- CI-contract tests fail closed if repository dispatch, client-payload subject authority, legacy reporter jobs, or App credentials are reintroduced into ordinary CI.

The `trusted-pr-gate` Environment and its App credential are **not** retired by this change. They remain required by the live routine `trusted-pr-auto.yml` reporter. Removing them while that path depends on them would disable a proven trust root. Credential retirement requires a separate independently validated replacement for the automatic reporter.

## Maintenance sequence

Changes that are neither owner-routine eligible nor recognized by a governed-bot policy follow this protected-maintenance order:

1. keep the candidate exact and review its protected transition set;
2. run ordinary exact-revision CI as development/execution evidence;
3. independently install a short-lived one-shot external policy bound to the exact PR/head/base/prospective-merge/protected transitions;
4. let the external App service re-fetch and validate the exact run, jobs, artifact, manifest, and candidate workflow binding;
5. observe exact App-authored `Trusted PR Gate: success` from the integration required by the live ruleset;
6. revoke the one-shot policy in fail-closed order before merge;
7. re-fetch PR identity, prospective merge, ruleset, App/deployment identity, and status immediately before merge;
8. merge only the exact validated revision with merge-commit semantics;
9. verify the resulting exact `main` SHA/tree and post-merge CI;
10. confirm the external gate has returned to its fail-closed idle policy state.

Owner test-only maintenance under `tests` does not execute this external activation sequence. Recognized governed-bot changes under `.github`, `scripts`, dependency authority, or auto-heal-owned paths use the autonomous lane only when every lane-specific provenance, trusted validation, exact-head CodeQL, and terminal-reproof invariant succeeds. Other changes under protected admission-control roots, including owner-authored `.github` or `scripts` changes, execute the external activation sequence. All classes still require App-authored `Trusted PR Gate: success`, strict branch enforcement, exact-head merge, and post-merge verification.

For AWS, deployment proof additionally includes exact deployment-ZIP and Lambda code-digest binding, runtime smoke verification, runtime-version control, least-privilege IAM read-back, DynamoDB configuration read-back, Function URL configuration read-back, log-retention read-back, and no-VPC verification before the App webhook is treated as live authority.

If an external-maintenance change requires an external host, App, webhook, policy, credential, status, ruleset, runtime, or deployment fact that is unavailable or unobserved, terminal truth is **BLOCKED**, not PASS.

## Verification and non-claims

Repository tests exercise webhook authentication, wrong repository/installation/actor/fork/workflow identity, policy expiry and malformed/duplicate/empty transitions, multi-root protected transitions, replay/idempotency, SQLite ownership, DynamoDB concurrent ownership, stale-processing recovery, transaction record bounds, transport/race separation, the exact DynamoDB IAM contract, Lambda request parsing, private SSM configuration binding, HMAC-before-private-key admission, policy digest binding, secret-safe fixed-stage Lambda failure diagnostics, transient-before-publication retries, no-replay publication recovery, lost/ambiguous status responses, post-publication drift, unsafe artifact ZIPs, duplicate JSON, exact build-manifest binding, routine automatic admission, and shared live merge-ref resolution.

Those tests prove implementation behavior and reviewed policy shape only. They do not prove effective deployed IAM, an external deployment, webhook endpoint, App credential, one-shot policy installation, live integration permissions, ruleset binding, AWS runtime properties, runtime-version control, or App-authored status exists. Effective AWS authority still requires live deployment observation and IAM simulation/read-back when the external path is invoked.

The terminal evidence rule remains:

**ordinary PR green ≠ protected merge authority**

**repository service source ≠ independently deployed trusted service**

**same status context ≠ required App integration**

**unobserved required control ≠ PASS**

---

[← CI/CD](CI_CD.md) · [Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
