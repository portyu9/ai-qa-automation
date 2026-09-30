# Trusted PR control plane

This document defines trusted pull-request validation and terminal merge-status authority for **ƳƤ AI QA Automation Framework**. Candidate-controlled CI is development evidence; it is never its own merge authority.

Repository source defines reviewed behavior and validation contracts. GitHub App installation state, credential custody, Environment policy, Actions policy, and branch-ruleset configuration are external authorities and must be observed independently. The optional external compatibility service additionally depends on its separately observed webhook/deployment/cloud state; that service is not required by the GitHub-native routine or protected-owner paths described below.

## Core invariant

The terminal context is `Trusted PR Gate`, but the context string alone is not authority. The live branch rule must bind that context to the dedicated **ƳƤ Trusted PR Gate GitHub App** integration. A candidate workflow may create a same-named status, but it must not satisfy the App-bound rule.

Model output has no authorization role.

The authority chain is:

**objective → advisory reasoning → deterministic policy → controlled tool → real execution/observation → persisted evidence → deterministic validation → structured terminal report**

## Three admission classes

The control plane distinguishes owner-routine changes, finite governed-bot changes, and explicit owner-protected maintenance. The strict App-bound branch rule is unchanged across all three classes.

### Owner-routine automatic path

The owner-routine chain is:

**ordinary PR CI completion → default-branch `workflow_run` wake-up → live deterministic admission → exact prospective merge + zero protected-object drift → deterministic validation → fresh admission revalidation → dedicated App token → exact subject-bound App status → strict protected-branch enforcement**

Owner-routine admission requires exact reviewed pull-request CI identity, expected repository-owner actor and triggering actor, one open same-repository PR targeting `main`, current-base equality, exact ordered prospective-merge parents `(base, head)`, and identical Git object IDs for every routine-protected authority root.

### Owner-protected maintenance path

Once this policy is accepted on `main`, owner-authored changes that cross a protected authority root use an explicit trusted-main maintenance authorization comment rather than becoming routine automatic admissions. The authorization chain is:

**exact owner PR → ordinary exact-revision development CI → accepted-main `trusted-pr-auto.yml` exact-owner `issue_comment` → exact owner/current-main/comment/subject re-resolution → prospective-merge validation → full trusted validation + exact candidate CodeQL → fresh trusted-main comment/subject revalidation → dedicated App token → dedicated-App comment/subject revalidation → exact subject-bound App status → strict protected-branch enforcement**

The authorization is one exact newly created pull-request comment by the repository owner: `/trusted-maintenance authorization=protected-control-plane-maintenance pr=<PR> head=<HEAD> base=<BASE> merge=<MERGE>`. The comment is a binding claim, never proof. GitHub runs `issue_comment` from the default branch SHA/ref; trusted-main preflight additionally requires the canonical repository, exact owner sender/comment/actor identity, a pull-request conversation, an unchanged live comment record with the same ID/body/issue URL, first run attempt only, the exact owner-authored same-repository PR, current-base equality, definitive mergeability, ordered prospective-merge parents, exact command/live SHA agreement, and at least one protected-object transition. Rerunning the same workflow attempt is non-authoritative; a later authorization requires a fresh owner comment and still must bind the unchanged live subject.

This lane does not enter governed-bot provenance authority. The bot-authority job must remain skipped. The exact prospective merge is nevertheless checked against the owner head, the full secret-free validation graph executes, and candidate CodeQL is required. Only after final trusted-main revalidation may the terminal reporter enter the `trusted-pr-gate` Environment and mint the existing dedicated App token. For protected-owner maintenance, trusted-main preflight then runs once more using that dedicated App token, re-fetching the unchanged owner comment and exact PR/base/head/merge/protected-transition subject before publication; candidate bytes never receive the token. Immediately around its final exact PR/merge resolution, the App reporter independently re-reads `refs/heads/main` and requires it to remain the authorized base SHA, so a concurrent default-branch advance cannot produce stale success evidence. Candidate bytes never receive the App private key, cannot select the status writer, and cannot convert a different PR or later revision into PASS.

This mechanism is a **future accepted-main maintenance path**, not authority for the PR that introduces it. An owner-protected bootstrap PR that changes this policy cannot certify itself before these reviewed bytes are accepted on `main`; that initial transition remains fail-closed behind the independently bound App status requirement.

### Governed-bot automatic path

The repository automatically admits exactly four governed bot lanes:

1. canonical Dependabot GitHub Actions updates under the reviewed `dependabot/github_actions/...` namespace;
2. exact independent-App dependency promotions under `automation/dependency-promotion-...`, with pre-migration GitHub Actions promotion subjects accepted only for bounded legacy lifecycle cleanup;
3. GitHub Actions CodeQL auto-heal repairs under `automation/codeql-autoheal-...`;
4. exact dedicated-App protected security remediations under `automation/protected-security-remediation-...`.

Protected remediation does not rely solely on best-effort scheduled execution. A successful `Security Auto-Heal` completion may wake the independent author lane only when the upstream run is successful, originates from this repository, and its head SHA exactly equals the trusted default-branch workflow SHA. Pull-request self-test runs therefore cannot reach the credential-bearing reconcile job. The five-minute schedule remains an independent fallback. Both triggers are liveness only: before the independent author token is minted, trusted default-branch code proves that the executing control SHA still equals live `main`; the controller repeats that control-revision proof before authority-bearing creation, PR-lifecycle, and merge mutations. Once an exact rollback or stale-cleanup transition has begun, rollback authority is retained only for that immutable App-authored subject until durable closure: the controller re-proves the exact PR presentation, route, plan, historical source and repaired bytes, one-file diff, commit provenance, branch SHA, and absence of a new open-PR claim before cleanup, but it cannot create, retarget, or merge another subject. If control moves after an exact generated branch is published but before PR creation, rollback deletes only the unchanged, unclaimed exact branch. The controller still re-resolves current `main`, the live alert route, author identity, attempt budget, source bytes, and exact repair plan before new authoring.

#### GitHub Advanced Security reporting boundary

`github-advanced-security[bot]` is **not** a governed admission, mutation, status-publication, or merge actor in this repository. Live repository evidence on 2026-09-23 showed GitHub Advanced Security participating as CodeQL finding/review reporting on PR #230 and automatically resolving that review after exact-head CodeQL cleared the finding. It did not author the repair PR or commit, originate the validating workflow, publish `Trusted PR Gate`, or merge the subject.

That observed reporting role does not create repository authority. The automatic admission policy therefore has no `github-advanced-security[bot]` lane, does not treat a GitHub-owned bot family as interchangeable, and does not infer trust from the login string alone. Finding titles, descriptions, review comments, SARIF-derived text, and other scanner output remain untrusted evidence. A future capability for this actor requires separate live provenance, an immutable numeric identity, a narrowly defined event/capability, exact subject binding, deterministic tests, and an explicit reviewed policy change. Until then it cannot satisfy or synthesize `Trusted PR Gate` and cannot bypass any CI, CodeQL, protected-path, revision, or guarded-merge requirement.

Bot identity alone is not authority. A serialized five-minute schedule running trusted default-branch bytes remains the bounded polling fallback and discovers at most one governed-bot candidate per reconciliation pass. Exact Dependabot Actions PRs additionally have an event-driven liveness path: a successful live-refetched CI `workflow_run` is accepted only when both actor identities are the canonical Dependabot bot and its exact head resolves to one open same-repository PR whose live lane is `dependabot-actions`. That CI result only wakes trusted validation; it cannot publish terminal status or authorize merge. Scheduled discovery is same-repository and exact-current-main scoped, prioritizes protected/security remediation before Dependabot Actions and dependency promotions, and fresh-GETs each candidate before selection. A candidate must be open, non-draft, definitively mergeable, and match the canonical bot identity plus reviewed branch grammar before subject resolution proceeds.

Dependency-governance candidate validation and privileged reconciliation are physically separated. `.github/workflows/dependency-governance-pr.yml` is the only pull-request self-test surface; it is exact `pull_request`-only, `contents: read`, secret-free, variable-free, mutation-free, and runs candidate bytes with `PYTHONSAFEPATH=1` plus the explicit narrow `PYTHONPATH=.github/scripts`. The privileged `.github/workflows/dependency-governance.yml` has no `pull_request` or candidate-ref trigger at all, so a candidate cannot alter that credential-bearing workflow's own event/job guards and then execute those candidate bytes as its PR workflow. Its credential-bearing governance job runs only from accepted default-branch workflow bytes on the serialized five-minute schedule or completed CI/CodeQL wakes whose head repository is this repository. Fork-origin workflow completions cannot enter that job; they remain non-authoritative workflow-level wake noise. A stale default-branch wake records a safe no-op before any secret or mutation-capable step. This source separation does **not** replace Environment protection: the remediation App key must remain environment-scoped and unavailable to candidate refs, because a same-repository PR can propose changes to other `pull_request` workflow YAML before those changes are merged. Environment configuration is therefore an independent required credential boundary, not a fact repository source can self-attest.

Security Auto-Heal uses the same source-level candidate/authority separation. `.github/workflows/security-autoheal-pr.yml` is the only Security Auto-Heal `pull_request` workflow and is exact `pull_request`-only, `contents: read`, secret-free, variable-free, mutation-free, and explicit about `PYTHONSAFEPATH=1` plus `PYTHONPATH=.github/scripts`. The write-capable `.github/workflows/security-autoheal.yml` has no `pull_request` trigger; it executes accepted-main bytes only on reviewed workflow-run/schedule/manual wakes, and workflow-run jobs additionally require the upstream head repository to equal this repository. The read-only route-plan artifact must still succeed before its separate write-capable reconcile job can start. Thus a same-repository candidate cannot alter Security Auto-Heal's privileged job guard and execute those candidate workflow bytes during that PR.

The governance job also binds `GOVERNANCE_CONTROL_SHA` to its trusted event revision. General Dependabot governance, bounded recovery, and dependency-promotion reconciliation re-read live `main` against that exact control SHA at mutation boundaries; if `main` advances after initial admission, further side effects fail closed and the next trusted wake resumes from the newer control plane. Post-certification dependency convergence has a second accepted-main path in `dependency-trusted-merge.yml`: a successful completed Trusted PR Auto `workflow_run` may wake one exact subject, but its resolver job is restricted to `actions: read`, `contents: read`, `pull-requests: read`, and `statuses: read`, has no Environment or secret authority, and binds `GOVERNANCE_CONTROL_SHA` to the exact accepted-main workflow revision. It re-fetches the upstream trusted run and same-repository identities, requires current-main equality, and exports only an exact dependency lane plus positive PR number through inherited runner file descriptor 3. The downstream merge job is the only write ceiling; it validates that closed output and invokes the existing target-specific controller, which requires the control revision to remain current and independently re-proves the App status, live actor/provenance policy, current-main base, prospective merge, ordered parents, and tree immediately before mutation. Immediately after exact gate revalidation, that controller also publishes or reuses a durable exact-head `APPROVE` review from canonical `github-actions[bot]`, re-reads the review, and refuses mutation if its PR/base/head/prospective-merge/trusted-run/status binding is wrong, malformed, or not durably observable. This review publication depends on the independently administered repository setting that allows GitHub Actions to create and approve pull requests; source code cannot self-attest that setting. The five-minute governance schedule remains an independent fallback.

New dependency promotions are authored by the already-reviewed independent non-certifying author App, not by the repository `GITHUB_TOKEN`. The author token is minted only in the trusted default-branch governance job, requests only contents-write and pull-requests-write, is bound to the configured immutable bot identity, and is passed only to deterministic promotion creation. It cannot publish `Trusted PR Gate`, and the merge controller continues under the separate repository token only after exact App-owned gate evidence. The App creates the exact generated branch/commit plus an exact temporary `automation/dependency-promotion-base-...` ref pinned to reviewed current `main`, opens the promotion PR against that non-main base, re-proves App/head/base/control identity, then retargets the same PR to `main`. Every repository `pull_request` workflow is base-filtered to `main`, so the initial staging-base `opened` event cannot start candidate CI or CodeQL; the retarget is intentionally outside the subscribed PR activity types, and accepted-main governance initiates exact generated-subject qualification instead. The temporary base is liveness plumbing only: it cannot satisfy validation, status, review, or merge authority, and it is deleted only after exact-ref ownership checks prove no open PR still claims it. Ambiguous or interrupted transitions retain exact refs for deterministic recovery/orphan pruning rather than manufacturing success. Pre-migration GitHub-Actions-authored promotion subjects remain cleanup-only and are regenerated under the independent App; there is no GitHub-Actions authoring fallback.

Promotion pull-request CI/CodeQL remains development evidence, not merge authority. When an exact promotion lacks terminal App-owned gate evidence, trusted default-branch dependency governance may publish one neutral `Dependency Promotion Qualification Wake` check bound to the promotion head, current-main base, governance run ID, and run attempt. Only after that exact governance run completes successfully may the default-branch Trusted PR Auto workflow consume its `workflow_run` event; failed runs, non-neutral checks, wrong App provenance, stale subjects, and ambiguous matches remain non-admissible. The five-minute schedule remains an independent fallback.

Whether awakened by that reviewed governance event or by the schedule, Trusted PR Auto re-proves the governed-bot identity and signed Dependabot lineage, validates the exact prospective merge, executes the full trusted validation graph including bot CodeQL, supply chain, security gates, Python 3.11/3.14, deterministic controls, and the Playwright reference SUT, and only then publishes the dedicated-App `Trusted PR Gate`. That App-owned status remains terminal exact-subject evidence; repository merge controllers cannot publish it and no GitHub `status` event is trusted as a merge wake. Post-certification dependency liveness is deliberately two-path: the serialized five-minute accepted-main governance schedule can discover a still-open qualified dependency subject, and a completed successful Trusted PR Auto run can wake `Dependency Trusted Merge — ƳƤ AI QA Automation Framework`. The latter is one-way and accepted-main-only. Its read-only resolver re-fetches the exact trusted workflow ID/name/path/event/attempt, repository and head-repository identities, current `main`, live PR presentation, merge ref/parents/tree, and the exact dedicated-App status target. A candidate matches only when that status is bound to the same completed trusted run; zero matches are a safe no-op and multiple matches fail closed. Only the closed lane (`dependency-promotion` or `dependabot-actions`) and positive PR number cross the resolver boundary, through inherited runner file descriptor 3 with no stdout subject logging. A separate merge job owns the sole contents/PR write ceiling, has no author-App credential and no check/status-write authority, validates that lane/PR pair again, crosses the exact `github-actions[bot]` review barrier, and invokes the target-specific merger for fresh current-main, actor/provenance, gate, merge-ref, ordered-parent, tree, and expected-head revalidation immediately before mutation. Dependency convergence remains acyclic: governance may issue a neutral qualification wake consumed by Trusted PR Auto, and Trusted PR Auto may wake `dependency-trusted-merge.yml`, but Trusted PR Auto does not listen to the dependency merger.

After that path merges, it re-fetches the merged PR and live `main`, verifies the exact base/head parents plus canonical GitHub merge author/committer/signature, and emits only the `governed-post-merge-validation` repository-dispatch wake bound to the previous control SHA and accepted-main merge SHA. The five-minute governance path independently watches the exact current dependency merge before any further mutation; if canonical post-merge validation is absent, it emits the same bounded wake and blocks additional dependency mutation until a first-attempt `Post-Merge Required Gate` executes and succeeds. `post-merge-ci.yml` accepts this single dispatch type alongside its reviewed controller `workflow_run` lanes. The dispatch payload is not evidence: the bridge requires its subject to equal `github.sha`, re-reads live `main`, and revalidates the canonical lane-specific two-parent signed merge before reusable CI and CodeQL can run. The bridge has no merge, status, check, App-token, secret, or deployment authority. The dispatch cannot synthesize green evidence; it only restores liveness where nested workflow-run triggering is unavailable. The neutral wake, App status, approval review, post-merge dispatch, and legacy staging metadata remain bounded evidence/liveness records and cannot independently authorize mutation.

The gate then runs lane-specific deterministic policy from trusted `main`: exact bot numeric identity, same-repository branch ownership, reviewed branch grammar, source PR or CodeQL-alert lineage, current-base binding, exact merge parents, and allowed change semantics. Dependency promotions are regenerated from the signed Dependabot intent under trusted Python interpreters. Security auto-heal rebinds the marker to the exact live CodeQL alert and to a code-owned remediation-strategy identity. Automatic attempts are bounded per strategy: exhausted Copilot or deterministic strategies stay exhausted, while a materially new reviewed strategy may start its own bounded epoch. A repair superseded only because `main` advanced is closed with exact `main-advanced` metadata and an unedited exact-identity `github-actions[bot]` supersession certificate bound to that PR/base/head and the exact Security Auto-Heal workflow id/run/attempt; only that certificate plus the final bot closure may exclude a future attempt from the strategy budget. Pre-migration exclusions are limited to the two code-owned historical stale repairs (#207 and #216), with exact base/head/fingerprint/closure facts pinned in code and bounded issue-timeline proof. Deterministic repairs must reproduce the code-owned transformation byte-for-byte; strategy or generator drift fails closed.

After lane proof, the full trusted validation graph executes against the exact prospective merge. For governed bots and explicit owner-protected maintenance, the subject guard additionally proves that the admitted head tree is identical to the prospective-merge tree, then the exact-subject CodeQL job analyzes the admitted head ref/SHA with only `actions: read`, `contents: read`, and `security-events: write`. The aggregate requires that CodeQL job to succeed for governed bots and protected-owner maintenance and to be skipped only for owner-routine admission. Before App publication, the gate fresh-resolves admission. Governed bots also re-run their terminal lane policy; protected-owner maintenance instead re-proves the exact main-bound owner comment, live comment provenance, subject SHAs, and non-empty protected transition set. Candidate validation remains secret-free and read-only except for the narrowly scoped CodeQL result upload; only the terminal reporter can obtain the dedicated App credential. Both owner lanes intentionally leave governed-bot authority skipped; downstream jobs explicitly override GitHub's transitive skipped-`needs` propagation with `!cancelled()` and exact direct-prerequisite success checks. This keeps the full validation graph live without allowing failed prerequisites or cancellation to become PASS.

The resulting `Trusted PR Gate` status is not head-only evidence. Its target binds the exact PR number, base SHA, head SHA, prospective merge SHA, and trusted-gate workflow run. Merge controllers do not possess App status-write authority. They independently require that exact App-authored binding, re-fetch the live PR/merge ref/ordered parents, and re-run their lane policy before merge.

Any API failure, malformed/truncated response, ambiguity, stale base, non-definitive mergeability, identity drift, branch/source mismatch, merge-parent/tree mismatch, failed trusted validation/CodeQL, or terminal subject drift fails closed.

### Protected-maintenance compatibility boundary

The GitHub-native owner-protected lane is intentionally explicit rather than autonomous: accepted trusted `main` supplies policy, the exact owner pull-request comment supplies a one-subject authorization event, and the dedicated App remains the terminal status writer. A candidate cannot gain authority merely because it changes a protected path, because ordinary owner `workflow_run` admission continues to return `eligible=false` whenever protected objects drift.

The repository still contains an independently administered external-App compatibility implementation under `scripts/trusted_gate_service/`. It is optional compatibility/fallback and is not a dependency of normal Dependabot, dependency-promotion, Security Auto-Heal, protected-remediation, or the accepted-main GitHub-native protected-owner maintenance lane. If that external compatibility path is used, its chain remains:

**ordinary PR CI completion → external App webhook ingress → exact live PR/head/base/merge resolution → independently administered protected-object policy → exact run/job/artifact verification → terminal live re-resolution → dedicated App status → strict protected-branch enforcement**

Repository presence does not create external authority. An external deployment is authoritative only when independently administered, pinned to reviewed bytes, holding its App credential outside candidate Actions, loading a narrow exact-subject one-shot policy, and observed publishing through the App integration required by the live ruleset.

Repository `repository_dispatch` and `workflow_dispatch` are not protected-maintenance authorities. The reviewed GitHub-native path is an exact-owner `issue_comment` event, which GitHub binds to the default branch SHA/ref. Candidate refs therefore cannot select the credential-bearing workflow bytes. The command is exact-subject bound, live-comment revalidated, first-attempt-only, and cannot carry candidate-selected policy.

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

After the GitHub-native protected-owner policy is accepted on `main`, owner changes that are neither owner-routine eligible nor a governed-bot subject follow this order:

1. keep the candidate exact and review the protected transition set;
2. run ordinary exact-revision CI as development evidence;
3. resolve the live PR number, exact head SHA, exact current-main base SHA, and exact prospective merge SHA;
4. create one exact owner comment on that PR: `/trusted-maintenance authorization=protected-control-plane-maintenance pr=<PR> head=<HEAD> base=<BASE> merge=<MERGE>`;
5. require trusted preflight to re-prove the canonical repository, exact owner sender/actor identities, `refs/heads/main`, current trusted-main SHA/workflow ref, first run attempt, live owner PR, exact SHAs, ordered merge parents, and at least one protected transition;
6. require the exact prospective-merge subject guard plus the complete trusted supply-chain, Python, deterministic-control, security, browser, and candidate CodeQL validation graph to succeed;
7. require terminal trusted-main preflight to re-fetch the same immutable comment authorization and exact subject before the `trusted-pr-gate` Environment can expose the dedicated App credential, then revalidate it again with the minted App token before publication;
8. observe exact App-authored `Trusted PR Gate: success` from the integration required by the live ruleset;
9. re-fetch PR identity, prospective merge, ruleset, status, and review-thread state immediately before merge, then merge only the exact validated revision;
10. verify the resulting exact `main` SHA/tree and post-merge CI.

A failed or rerun maintenance authorization workflow is not reusable authority. `GITHUB_RUN_ATTEMPT` must be exactly 1; a later authorization requires a newly created exact owner comment bound to whatever exact subject is live at that later time. Test-only owner changes under `tests` remain owner-routine because `tests` is not in the routine protected-root set. Recognized governed-bot changes continue to use their autonomous lane only when every lane-specific provenance, trusted validation, exact-head CodeQL, and terminal-reproof invariant succeeds. All classes still require App-authored `Trusted PR Gate: success`, strict branch enforcement, exact-head merge, and post-merge verification.

The external compatibility service remains available as a separately administered fallback. If it is invoked, its older one-shot policy/deployment sequence and all external read-back requirements still apply. AWS is not required for routine bot operation or for the GitHub-native protected-owner maintenance path.

If an external compatibility transaction requires a host, App, webhook, policy, credential, status, ruleset, runtime, or deployment fact that is unavailable or unobserved, terminal truth is **BLOCKED**, not PASS.

## Verification and non-claims

Repository tests exercise the GitHub-native maintenance comment's exact command shape and SHA claims, fixed authorization value, exact owner sender/comment/PR identity, live-comment revalidation, current-main ref/SHA/workflow binding, first-attempt replay guard, protected-transition requirement, subject drift rejection, candidate-secret isolation, post-mint App revalidation, dedicated reporter mode, and shared live merge-ref resolution. They also continue to exercise the optional external compatibility service's webhook authentication, wrong repository/installation/actor/fork/workflow identity, policy expiry and malformed/duplicate/empty transitions, multi-root protected transitions, replay/idempotency, SQLite ownership, DynamoDB concurrent ownership, stale-processing recovery, transaction record bounds, transport/race separation, exact DynamoDB IAM contract, Lambda request parsing, private SSM configuration binding, HMAC-before-private-key admission, policy digest binding, secret-safe fixed-stage Lambda failure diagnostics, transient-before-publication retries, no-replay publication recovery, lost/ambiguous status responses, post-publication drift, unsafe artifact ZIPs, duplicate JSON, and exact build-manifest binding.

Those tests prove implementation behavior and reviewed policy shape only. They do not prove the dedicated App installation/credential, Environment configuration, live integration permissions, branch-ruleset binding, or an App-authored status exists; those remain live platform facts. They also do not prove effective deployed IAM, an external deployment, webhook endpoint, external one-shot policy installation, AWS runtime properties, or runtime-version control. Effective AWS authority still requires live deployment observation and IAM simulation/read-back only when the optional external path is invoked.

The terminal evidence rule remains:

**ordinary PR green ≠ protected merge authority**

**repository service source ≠ independently deployed trusted service**

**same status context ≠ required App integration**

**unobserved required control ≠ PASS**

---

[← CI/CD](CI_CD.md) · [Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
