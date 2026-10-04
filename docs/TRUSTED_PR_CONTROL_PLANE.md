# Trusted PR control plane

This document defines trusted pull-request validation and terminal merge-status authority for **ƳƤ AI QA Automation Framework**. Candidate-controlled CI is development evidence; it is never its own merge authority.

Repository source defines reviewed behavior and validation contracts. GitHub App installation state, credential custody, Environment policy, Actions policy, and branch-ruleset configuration are platform authorities and must be observed independently. The production control plane is GitHub-native: no external webhook or cloud runtime is required or accepted as protected-merge authority.

## Core invariant

The terminal context is `Trusted PR Gate`, but the context string alone is not authority. The intended protected-branch rule binds that context to the dedicated **ƳƤ Trusted PR Gate GitHub App** integration; live ruleset state is externally administered and must be observed separately before claiming enforcement. A candidate workflow may create a same-named status, but it must not satisfy the App-bound rule when that rule is deployed.

Model output has no authorization role.

The authority chain is:

**objective → advisory reasoning → deterministic policy → controlled tool → real execution/observation → persisted evidence → deterministic validation → structured terminal report**

## Three admission classes

The control plane distinguishes owner-routine changes, finite governed-bot changes, and explicit owner-protected maintenance. The source-level admission and dedicated-App terminal-status contract is unchanged across all three classes; live ruleset enforcement is a GitHub platform condition and cannot be inferred from repository source.

### Owner-routine automatic path

The owner-routine chain is:

**ordinary PR CI completion → default-branch `workflow_run` wake-up → live deterministic admission → exact prospective merge + zero protected-object drift → deterministic validation → fresh admission revalidation → dedicated App token → exact subject-bound App status → strict protected-branch enforcement**

Owner-routine admission requires exact reviewed pull-request CI identity, expected repository-owner actor and triggering actor, one open same-repository PR targeting `main`, current-base equality, exact ordered prospective-merge parents `(base, head)`, and identical Git object IDs for every routine-protected authority root.

### Owner-protected maintenance path

Once this policy is accepted on `main`, owner-authored changes that cross a protected authority root use an explicit trusted-main maintenance authorization comment rather than becoming routine automatic admissions. The authorization chain is:

**exact owner PR → ordinary exact-revision development CI → durable exact owner authorization comment → reviewed trusted-main reconciliation wake → exact owner/current-main/comment/subject re-resolution → prospective-merge validation → full trusted validation + exact candidate CodeQL → fresh trusted-main comment/subject revalidation → dedicated App token → dedicated-App exact pending-authorization/current-main/subject reproof → exact subject-bound App status → strict protected-branch enforcement**

The authorization is one exact newly created pull-request comment by the repository owner: `/trusted-maintenance authorization=protected-control-plane-maintenance pr=<PR> head=<HEAD> base=<BASE> merge=<MERGE>`. The comment is a binding claim, never proof. Its durability is intentionally separated from liveness: any already-reviewed successful `workflow_run` wake accepted by trusted preflight may cause the controller to look for a pending authorization, and the serialized accepted-main schedule remains an independent fallback. None of those wakes chooses the protected subject or contributes authorization. Trusted reconciliation is serialized per accepted-main SHA with `cancel-in-progress: false`, so redundant wakes for one control revision cannot run competing authority graphs. Trusted-main preflight instead re-fetches the canonical repository, unchanged live comment ID/body/issue URL and exact owner identity, then independently resolves the owner-authored same-repository PR, current-base equality, definitive mergeability, ordered prospective-merge parents, exact command/live SHA agreement, and a non-empty protected-object transition. The trusted reconciliation run must be its first attempt. A later authorization still requires a fresh owner comment bound to the unchanged live subject.

This lane does not enter governed-bot provenance authority. The bot-authority job must remain skipped. The exact prospective merge is nevertheless checked against the owner head, the full secret-free validation graph executes, and candidate CodeQL is required. Only after final trusted-main revalidation may the terminal reporter enter the `trusted-pr-gate` Environment and mint the existing dedicated App token. The wake has already served its only role—liveness—so the narrow publication App deliberately does not re-read Actions wake provenance and does not require `actions: read`. Instead, using only its existing contents-read, pull-requests-read, and statuses-write scope, the App reporter independently re-reads current `main`, discovers exactly one still-pending immutable owner authorization, and re-proves the exact owner comment plus PR/base/head/merge/protected-transition subject. It performs that durable authorization reproof before and immediately before status publication, around a separate exact PR/merge/current-main resolution, so a concurrent default-branch advance, authorization consumption, ambiguity, or subject drift cannot produce stale success evidence. Candidate bytes never receive the App private key, cannot select the status writer, and cannot convert a different PR or later revision into PASS.

This mechanism is a **future accepted-main maintenance path**, not authority for the PR that introduces it. An owner-protected bootstrap PR that changes this policy cannot certify itself before these reviewed bytes are accepted on `main`; that initial transition remains fail-closed behind the independently bound App status requirement.

### Governed-bot automatic path

The repository automatically admits exactly four governed bot lanes:

1. canonical Dependabot GitHub Actions updates under the reviewed `dependabot/github_actions/...` namespace;
2. exact independent-App dependency promotions under `automation/dependency-promotion-...`, with pre-migration GitHub Actions promotion subjects accepted only for bounded legacy lifecycle cleanup;
3. GitHub Actions CodeQL auto-heal repairs under `automation/codeql-autoheal-...`;
4. exact dedicated-App protected security remediations under `automation/protected-security-remediation-...`.

Protected remediation does not rely solely on best-effort scheduled execution. A successful `Security Auto-Heal` completion may wake the independent author lane only when the upstream run is successful, originates from this repository, and its head SHA exactly equals the trusted default-branch workflow SHA. Pull-request self-test runs therefore cannot reach the credential-bearing reconcile job. The five-minute schedule remains an independent fallback. Both triggers are liveness only: before the independent author token is minted, trusted default-branch code proves that the executing control SHA still equals live `main`; the controller repeats that control-revision proof before authority-bearing creation, PR-lifecycle, and merge mutations. New protected repair publication is staged rather than created directly against `main`: the author App creates an exact temporary `automation/protected-security-remediation-base-...` ref at the accepted control SHA, opens the exact generated repair PR against that non-main base, re-proves App/route/plan/head/base identity plus current control, and only then retargets that same PR to `main`. PR creation and retarget are non-replay-safe boundaries: ambiguous transport outcomes converge only through exact read-back; unresolved ambiguity retains the exact staging/generated refs, and a later accepted-main reconciliation either completes the exact staged subject or prunes exact unclaimed retained refs without blindly replaying creation. Staging cleanup re-proves the ref SHA and refuses deletion while any open PR claims the staging ref as head or base. Once an exact rollback or stale-cleanup transition has begun, rollback authority is retained only for that immutable App-authored subject until durable closure: the controller re-proves the exact PR presentation, route, plan, historical source and repaired bytes, one-file diff, commit provenance, branch/staging SHA, and absence of a new open-PR claim before cleanup, but it cannot create, retarget, or merge another subject. If control moves after exact generated/staging refs are published but before durable PR convergence, rollback deletes only unchanged, unclaimed exact refs. The controller still re-resolves current `main`, the live alert route, author identity, attempt budget, source bytes, and exact repair plan before new authoring.

#### GitHub Advanced Security reporting boundary

`github-advanced-security[bot]` is **not** a governed admission, mutation, status-publication, or merge actor in this repository. Live repository evidence on 2026-09-23 showed GitHub Advanced Security participating as CodeQL finding/review reporting on PR #230 and automatically resolving that review after exact-head CodeQL cleared the finding. It did not author the repair PR or commit, originate the validating workflow, publish `Trusted PR Gate`, or merge the subject.

That observed reporting role does not create repository authority. The automatic admission policy therefore has no `github-advanced-security[bot]` lane, does not treat a GitHub-owned bot family as interchangeable, and does not infer trust from the login string alone. Finding titles, descriptions, review comments, SARIF-derived text, and other scanner output remain untrusted evidence. A future capability for this actor requires separate live provenance, an immutable numeric identity, a narrowly defined event/capability, exact subject binding, deterministic tests, and an explicit reviewed policy change. Until then it cannot satisfy or synthesize `Trusted PR Gate` and cannot bypass any CI, CodeQL, protected-path, revision, or guarded-merge requirement.

Bot identity alone is not authority. A serialized five-minute schedule running trusted default-branch bytes remains the bounded polling fallback and discovers at most one governed-bot candidate per reconciliation pass. Exact Dependabot Actions PRs additionally have an event-driven liveness path: a successful live-refetched CI `workflow_run` is accepted only when both actor identities are the canonical Dependabot bot and its exact head resolves to one open same-repository PR whose live lane is `dependabot-actions`. That CI result only wakes trusted validation; it cannot publish terminal status or authorize merge. Scheduled discovery is same-repository and exact-current-main scoped, prioritizes protected/security remediation before Dependabot Actions and dependency promotions, and fresh-GETs each candidate before selection. A candidate must be open, non-draft, definitively mergeable, and match the canonical bot identity plus reviewed branch grammar before subject resolution proceeds.

Dependency-governance candidate validation and privileged reconciliation are physically separated. `.github/workflows/dependency-governance-pr.yml` is the only pull-request self-test surface; it is exact `pull_request`-only, `contents: read`, secret-free, variable-free, mutation-free, and runs candidate bytes with `PYTHONSAFEPATH=1` plus the explicit narrow `PYTHONPATH=.github/scripts`. The privileged `.github/workflows/dependency-governance.yml` has no `pull_request` or candidate-ref trigger at all, so a candidate cannot alter that credential-bearing workflow's own event/job guards and then execute those candidate bytes as its PR workflow. Its credential-bearing governance job runs only from accepted default-branch workflow bytes on the serialized five-minute schedule or completed CI/CodeQL wakes whose head repository is this repository. Fork-origin workflow completions cannot enter that job; they remain non-authoritative workflow-level wake noise. A stale default-branch wake records a safe no-op before any secret or mutation-capable step. This source separation does **not** replace Environment protection: the remediation App key must remain environment-scoped and unavailable to candidate refs, because a same-repository PR can propose changes to other `pull_request` workflow YAML before those changes are merged. Environment configuration is therefore an independent required credential boundary, not a fact repository source can self-attest.

Security Auto-Heal uses the same source-level candidate/authority separation. `.github/workflows/security-autoheal-pr.yml` is the only Security Auto-Heal `pull_request` workflow and is exact `pull_request`-only, `contents: read`, secret-free, variable-free, mutation-free, and explicit about `PYTHONSAFEPATH=1` plus `PYTHONPATH=.github/scripts`. The write-capable `.github/workflows/security-autoheal.yml` has no `pull_request` trigger; it executes accepted-main bytes only on reviewed workflow-run/schedule/manual wakes, and workflow-run jobs additionally require the upstream head repository to equal this repository. The read-only route-plan artifact must still succeed before its separate write-capable reconcile job can start. Thus a same-repository candidate cannot alter Security Auto-Heal's privileged job guard and execute those candidate workflow bytes during that PR.

The governance job also binds `GOVERNANCE_CONTROL_SHA` to its trusted event revision. General Dependabot governance, bounded recovery, and dependency-promotion reconciliation re-read live `main` against that exact control SHA at mutation boundaries; if `main` advances after initial admission, further side effects fail closed and the next trusted wake resumes from the newer control plane. Post-certification dependency convergence has a second accepted-main path in `dependency-trusted-merge.yml`: a successful completed Trusted PR Auto `workflow_run` may wake one exact subject, but its resolver job is restricted to `actions: read`, `contents: read`, `pull-requests: read`, and `statuses: read`, has no Environment or secret authority, and binds `GOVERNANCE_CONTROL_SHA` to the exact accepted-main workflow revision. It re-fetches the upstream trusted run and same-repository identities, requires current-main equality, and exports only an exact dependency lane plus positive PR number through inherited runner file descriptor 3. A separate owner-review job then enters only Environment `portyu9-review-identity`, keeps the workflow token read-only, verifies that `PORTYU9_BOT_REVIEW_TOKEN` resolves to the exact repository-owner user `portyu9`, re-resolves the current-main/PR/App-gate tuple, rejects a manual exact-head `CHANGES_REQUESTED` veto, and publishes or reuses exactly one gate-bound `APPROVE` review on the validated head. Ambiguous review submission is recoverable only when one durable matching owner review is observed. The owner credential is not exposed to the downstream merger. The merge job remains the sole contents/PR write ceiling; it requires successful owner review, invokes the existing target-specific controller, requires that exact durable owner review as evidence, and independently re-proves current control revision, App status, live actor/provenance policy, current-main base, prospective merge, ordered parents, and tree immediately before mutation. Environment existence, token custody, and the token's live GitHub permissions are independently administered platform facts; repository source can constrain their use but cannot self-attest their configuration. The five-minute governance schedule remains an independent fallback.

New dependency promotions are authored by the already-reviewed independent non-certifying author App, not by the repository `GITHUB_TOKEN`. The author token is minted only in the trusted default-branch governance job, requests only contents-write and pull-requests-write, is bound to the configured immutable bot identity, and is passed only to deterministic promotion creation. It cannot publish `Trusted PR Gate`, and the merge controller continues under the separate repository token only after exact App-owned gate evidence. The App creates the exact generated branch/commit plus an exact temporary `automation/dependency-promotion-base-...` ref pinned to reviewed current `main`, opens the promotion PR against that non-main base, re-proves App/head/base/control identity, then retargets the same PR to `main`. Every repository `pull_request` workflow is base-filtered to `main`, so the initial staging-base `opened` event cannot start candidate CI or CodeQL; the retarget is intentionally outside the subscribed PR activity types. After exact controller-side retarget validation, the **same accepted-main dependency-governance run** publishes one neutral qualification check whose external identity binds the promotion head, current-main base, governance run id, and attempt; Trusted PR Auto may consume it only after that exact governance run completes successfully. The temporary base is liveness plumbing only: it cannot satisfy validation, status, review, or merge authority, and it is deleted only after exact-ref ownership checks prove no open PR still claims it. Ambiguous or interrupted transitions retain exact refs for deterministic recovery/orphan pruning rather than manufacturing success. Pre-migration GitHub-Actions-authored promotion subjects remain cleanup-only and are regenerated under the independent App; there is no GitHub-Actions authoring fallback.

Promotion pull-request CI/CodeQL remains development evidence, not merge authority. When an exact promotion lacks terminal App-owned gate evidence, trusted default-branch dependency governance may publish one neutral `Dependency Promotion Qualification Wake` check bound to the promotion head, current-main base, governance run ID, and run attempt. Only after that exact governance run completes successfully may the default-branch Trusted PR Auto workflow consume its `workflow_run` event; failed runs, non-neutral checks, wrong App provenance, stale subjects, and ambiguous matches remain non-admissible. The five-minute schedule remains an independent fallback.

Whether awakened by that reviewed governance event or by the schedule, Trusted PR Auto re-proves the governed-bot identity and signed Dependabot lineage, validates the exact prospective merge, executes the full trusted validation graph including bot CodeQL, supply chain, security gates, Python 3.11/3.14, deterministic controls, and the Playwright reference SUT, and only then publishes the dedicated-App `Trusted PR Gate`. That App-owned status remains terminal exact-subject evidence; repository merge controllers cannot publish it and no GitHub `status` event is trusted as a merge wake. Post-certification dependency liveness is deliberately two-path: the serialized five-minute accepted-main governance schedule can discover a still-open qualified dependency subject, and a completed successful Trusted PR Auto run can wake `Dependency Trusted Merge — ƳƤ AI QA Automation Framework`. The latter is one-way and accepted-main-only. Its read-only resolver re-fetches the exact trusted workflow ID/name/path/event/attempt, repository and head-repository identities, current `main`, live PR presentation, merge ref/parents/tree, and the exact dedicated-App status target. A candidate matches only when that status is bound to the same completed trusted run; zero matches are a safe no-op and multiple matches fail closed. Only the closed lane (`dependency-promotion` or `dependabot-actions`) and positive PR number cross the resolver boundary, through inherited runner file descriptor 3 with no stdout subject logging. The isolated owner-review job must then publish or reuse the exact `portyu9` review bound to that same App-gate evidence; a separate merge job owns the sole contents/PR write ceiling, has no owner-review or author-App credential and no check/status-write authority, requires that owner review, and invokes the target-specific merger for fresh current-main, actor/provenance, gate, merge-ref, ordered-parent, tree, and expected-head revalidation immediately before mutation. Dependency convergence remains acyclic: governance may issue a neutral qualification wake consumed by Trusted PR Auto, and Trusted PR Auto may wake `dependency-trusted-merge.yml`, but Trusted PR Auto does not listen to the dependency merger.

After that path merges, it re-fetches the merged PR and live `main`, verifies the exact base/head parents plus canonical GitHub merge author/committer/signature, and emits only the `governed-post-merge-validation` repository-dispatch wake bound to the previous control SHA and accepted-main merge SHA. The five-minute governance path independently watches the exact current dependency merge before any further mutation; if canonical post-merge validation is absent, it emits the same bounded wake and blocks additional dependency mutation until a first-attempt `Post-Merge Required Gate` executes and succeeds. `post-merge-ci.yml` accepts this single dispatch type alongside its reviewed controller `workflow_run` lanes. The dispatch payload is not evidence: the bridge requires its subject to equal `github.sha`, re-reads live `main`, and revalidates the canonical lane-specific two-parent signed merge before reusable CI and CodeQL can run. The bridge has no merge, status, check, App-token, secret, or deployment authority. The dispatch cannot synthesize green evidence; it only restores liveness where nested workflow-run triggering is unavailable. The neutral wake, App status, approval review, post-merge dispatch, and legacy staging metadata remain bounded evidence/liveness records and cannot independently authorize mutation.

The gate then runs lane-specific deterministic policy from trusted `main`: exact bot numeric identity, same-repository branch ownership, reviewed branch grammar, source PR or CodeQL-alert lineage, current-base binding, exact merge parents, and allowed change semantics. Dependency promotions are regenerated from the signed Dependabot intent under trusted Python interpreters. Security auto-heal rebinds the marker to the exact live CodeQL alert and to a code-owned remediation-strategy identity. Automatic attempts are bounded per strategy: exhausted Copilot or deterministic strategies stay exhausted, while a materially new reviewed strategy may start its own bounded epoch. A repair superseded only because `main` advanced is closed with exact `main-advanced` metadata and an unedited exact-identity `github-actions[bot]` supersession certificate bound to that PR/base/head and the exact Security Auto-Heal workflow id/run/attempt; only that certificate plus the final bot closure may exclude a future attempt from the strategy budget. Pre-migration exclusions are limited to the two code-owned historical stale repairs (#207 and #216), with exact base/head/fingerprint/closure facts pinned in code and bounded issue-timeline proof. Deterministic repairs must reproduce the code-owned transformation byte-for-byte; strategy or generator drift fails closed.

After lane proof, the full trusted validation graph executes against the exact prospective merge. For governed bots and explicit owner-protected maintenance, the subject guard additionally proves that the admitted head tree is identical to the prospective-merge tree, then the exact-subject CodeQL job analyzes the admitted head ref/SHA with only `actions: read`, `contents: read`, and `security-events: write`. The aggregate requires that CodeQL job to succeed for governed bots and protected-owner maintenance and to be skipped only for owner-routine admission. Before App publication, the gate fresh-resolves admission. Governed bots also re-run their terminal lane policy; protected-owner maintenance instead re-proves the exact main-bound owner comment, live comment provenance, subject SHAs, and non-empty protected transition set. Candidate validation remains secret-free and read-only except for the narrowly scoped CodeQL result upload; only the terminal reporter can obtain the dedicated App credential. Both owner lanes intentionally leave governed-bot authority skipped; downstream jobs explicitly override GitHub's transitive skipped-`needs` propagation with `!cancelled()` and exact direct-prerequisite success checks. This keeps the full validation graph live without allowing failed prerequisites or cancellation to become PASS.

The resulting `Trusted PR Gate` status is not head-only evidence. Its target binds the exact PR number, base SHA, head SHA, prospective merge SHA, and trusted-gate workflow run. Merge controllers do not possess App status-write authority. They independently require that exact App-authored binding, re-fetch the live PR/merge ref/ordered parents, and re-run their lane policy before merge.

Any API failure, malformed/truncated response, ambiguity, stale base, non-definitive mergeability, identity drift, branch/source mismatch, merge-parent/tree mismatch, failed trusted validation/CodeQL, or terminal subject drift fails closed.

### Protected-maintenance boundary

The GitHub-native owner-protected lane is intentionally explicit rather than autonomous: accepted trusted `main` supplies policy, the exact owner pull-request comment supplies a one-subject authorization event, and the dedicated App remains the terminal status writer. A candidate cannot gain authority merely because it changes a protected path, because ordinary owner `workflow_run` admission continues to return `eligible=false` whenever protected objects drift.

Repository `repository_dispatch`, `workflow_dispatch`, and direct `issue_comment` workflow execution are not protected-maintenance authorities. The exact owner pull-request comment is durable authorization data only. Accepted-main trusted reconciliation discovers and revalidates that immutable exact-subject comment after a successful reviewed `workflow_run` wake or the serialized schedule fallback. The legacy comment-trigger wake is retired because GitHub produced zero-job `startup_failure` runs before jobs instantiated, including for unrelated issue comments. Candidate refs therefore cannot select credential-bearing trusted workflow bytes, and failed/no-job comment delivery can neither grant authority nor create false-green evidence.

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

## Protect Main ruleset administration

Repository source now defines the reviewed desired state and the only admitted one-shot transition for live ruleset `21201916` (`Protect Main`):

- `.github/rulesets/repository-rulesets-v1.json` requires the existing deletion, non-fast-forward, merge-only pull-request, zero-bypass, strict/up-to-date rules unchanged and adds exactly one required status: `Trusted PR Gate` bound to integration `4766700`;
- `.github/rulesets/ruleset-transitions-v1.json` binds the exact observed predecessor with an empty required-status list to that exact successor by canonical SHA-256 digests. Any other live state is neither predecessor nor successor and is non-mutable truth;
- `.github/workflows/ruleset-reconciler.yml` runs only from accepted `main` push/schedule/manual recovery. Its plan job is secret-free/read-only and may use a non-authoritative predecessor/successor hint when GitHub redacts `bypass_actors`; the separate `ruleset-admin-identity` job then uses the dedicated Ruleset Administration App to re-prove the exact live state, and only an exact predecessor is mutable;
- the Ruleset Administration App is independently required to be installed only for `portyu9/ai-qa-automation` with repository Administration write plus implicit Metadata read. Its token is constrained to that one repository, re-proves current `main`, re-reads the exact predecessor, performs at most one PUT to the exact ruleset endpoint, and requires exact-successor read-back;
- an ambiguous PUT response is never blindly replayed. Read-back may prove that the single attempt applied; otherwise the run remains failed/blocked. A non-secret subject/run/digest receipt is retained as an Actions artifact after a proven transition;
- `.github/workflows/ruleset-drift-sentinel.yml` is secret-free and environment-free. Its native contents-read token performs only read-only GETs, requires the observable exact successor, and binds that projection to `.github/rulesets/ruleset-drift-witness-v1.json`, whose ruleset object identity and revision timestamps were independently certified with zero bypass actors after the accepted-main reconciliation. Timestamp binding accepts either the exact certified instant or GitHub's documented whole-second UTC read-only projection; any full-precision disagreement, different observed second, visible policy drift, or object-identity drift fails closed. Mutation methods remain forbidden.

GitHub does not expose `bypass_actors` to every read-only ruleset caller, so redacted observable state is not itself proof of zero bypass actors. The periodic sentinel preserves least privilege by pinning the last independently certified full-state revision instead of minting an Administration-write-capable observer token. The read-only repository-ruleset API may normalize timestamp precision to whole seconds; the sentinel therefore permits only the exact UTC second projection of the independently certified timestamp when the observed representation is the documented no-fraction `...Z` form. A different second or any conflicting full-precision timestamp is a blocking revision mismatch. A sub-second-only hidden edit that GitHub does not expose to the read-only caller is an explicit platform observability boundary rather than fabricated evidence; detecting it would require a different independently justified authority surface.

The status App and ruleset-admin App are deliberately distinct. **ƳƤ Trusted PR Gate** keeps only validation/status authority and never receives repository Administration permission. The ruleset-admin identity receives no status, contents-write, pull-request, checks, security-event, external-cloud, or OIDC authority. Candidate PR bytes cannot invoke either administrative transition: the reconciler executes only after those reviewed bytes are accepted on `main`.

Repository contracts cannot prove live Environment protection, App installation/permissions, or the successful ruleset mutation. Those remain environment-owned facts that require a live accepted-main run and live ruleset read-back before enforcement is claimed.

## GitHub-native trust boundary

The production trust boundary is entirely GitHub-native. Accepted-`main` workflows own deterministic admission and revalidation; protected Environments isolate credentials; dedicated GitHub Apps provide distinct status, ruleset-administration, protected-repair, and authoring identities; and the active ruleset binds terminal merge authority to the exact **ƳƤ Trusted PR Gate** integration.

Candidate workflows, tests, and scripts must never receive the terminal App private key or status-write token. GitHub Actions must not acquire AWS or other external-cloud credentials. The former `scripts/trusted_gate_service/` runtime is retired and intentionally absent; `scripts/verify_fork_cloud_authority.py` fails closed if that runtime returns or if workflow cloud-authentication authority appears.

The dedicated Trusted PR Gate App does not require an active webhook for the production path. Its credential is minted only inside the reviewed terminal reporter after exact accepted-main admission and validation have succeeded. Repository source cannot self-attest the live App installation, Environment restrictions, or ruleset integration binding; those remain live GitHub platform facts.

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
4. create one exact owner comment on that PR: `/trusted-maintenance authorization=protected-control-plane-maintenance pr=<PR> head=<HEAD> base=<BASE> merge=<MERGE>`; the comment is durable authorization data, not an execution trigger;
5. require a successful reviewed accepted-main workflow completion or the serialized accepted-main schedule to supply liveness, then require trusted preflight to independently re-discover and re-prove the canonical repository, exact owner/comment identity, current trusted-main SHA, live owner PR, exact SHAs, ordered merge parents, and at least one protected transition;
6. require the exact prospective-merge subject guard plus the complete trusted supply-chain, Python, deterministic-control, security, browser, and candidate CodeQL validation graph to succeed;
7. require terminal trusted-main preflight to re-fetch the same immutable comment authorization and exact subject before the `trusted-pr-gate` Environment can expose the dedicated App credential; after App mint, require the reporter to independently re-resolve exactly one still-pending durable owner authorization plus current-main/exact-subject evidence with the narrow App token immediately before publication, without re-reading wake provenance;
8. observe exact App-authored `Trusted PR Gate: success` from the integration required by the live ruleset;
9. re-fetch PR identity, prospective merge, ruleset, status, and review-thread state immediately before merge, then merge only the exact validated revision;
10. verify the resulting exact `main` SHA/tree and post-merge CI.

A failed, stale, or rerun trusted reconciliation is not reusable authority. `GITHUB_RUN_ATTEMPT` must be exactly 1; a later authorization requires a newly created exact owner comment bound to whatever exact subject is live at that later time. Test-only owner changes under `tests` remain owner-routine because `tests` is not in the routine protected-root set. Recognized governed-bot changes continue to use their autonomous lane only when every lane-specific provenance, trusted validation, exact-head CodeQL, and terminal-reproof invariant succeeds. All classes still require App-authored `Trusted PR Gate: success`, strict branch enforcement, exact-head merge, and post-merge verification.

## Verification and non-claims

Repository tests exercise the GitHub-native maintenance comment's exact command shape and SHA claims, owner/comment/PR identity, current-main binding, first-attempt replay guard, protected-transition requirement, candidate-secret isolation, dedicated reporter mode, App identity/status binding, and shared live merge-ref resolution. The cloud-authority verifier also rejects AWS/OIDC credential paths and fails if the retired external trusted-gate runtime reappears.

Those tests prove repository behavior and reviewed policy shape only. They do not prove the live dedicated App installation/credential, Environment configuration, effective App permissions, Actions policy, or branch-ruleset binding; those remain live GitHub platform facts.

The terminal evidence rule remains:

**ordinary PR green ≠ protected merge authority**

**candidate validation ≠ terminal App authority**

**same status context ≠ required App integration**

**unobserved required control ≠ PASS**

---

## Exact CodeQL result authority

`Trusted PR Gate` does not equate a successful CodeQL workflow conclusion with absence of findings. The accepted-main controller analyzes the exact prospective merge with the reviewed CodeQL bundle, retains the generated SARIF, and then requires a zero-findings result before the aggregate trusted validation may succeed.

The SARIF verifier is loaded from the exact accepted-main control SHA through read-only repository contents access. Candidate bytes therefore cannot weaken, replace, or bypass the verifier that decides whether CodeQL evidence is admissible. Any missing or malformed evidence, scanner-identity drift, resource-bound violation, filesystem indirection, or non-empty CodeQL result set is a blocking security outcome.

Ordinary PR CodeQL uses the same zero-findings rule for immediate developer feedback. The accepted-main trusted controller remains the authority-bearing enforcement surface.

[← CI/CD](CI_CD.md) · [Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
