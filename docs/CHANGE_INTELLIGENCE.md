# Change intelligence

The runtime can reason about a pull-request or feature-branch delta without treating the current working tree as the whole change.

## Explicit baseline

Set a trusted Git baseline before the live run:

```bash
export AI_QA_BASE_REF=origin/main
```

The repository inspector validates the ref, resolves it to an immutable commit, computes its merge base with `HEAD`, and combines committed changes since that merge base with any current dirty/untracked worktree changes. The resolved baseline SHA and merge-base SHA are persisted as observed evidence.

The baseline is never inferred from target-repository instructions. If it cannot be resolved, bootstrap records the resolution error and makes that limitation visible to the model rather than silently substituting another branch.

## Change-risk assessment

The combined change set is passed through deterministic risk heuristics for security/authentication, data integrity, API contracts, infrastructure, dependencies, UI, and configuration. The assessment produces risk domains, recommended test layers/tags, confidence, and rationale.

## CODEOWNERS

The runtime searches the normal CODEOWNERS locations in precedence order and resolves changed files with last-match-wins semantics for the supported root/directory/`*`/`**`/`?` grammar. Unsupported patterns are reported explicitly rather than guessed.

Ownership is context for review/routing; it does not grant runtime permission.

## OpenAPI/Swagger drift

Changed OpenAPI/Swagger JSON or YAML contracts are compared against the merge-base version when available. The conservative compatibility analyzer detects examples such as:

- path or HTTP operation removal;
- newly required parameters or request bodies;
- successful response removal;
- new security requirements;
- schema/type changes;
- required-property additions;
- property/schema removal; and
- enum narrowing.

Results are classified `BREAKING`, `RISKY`, `NON_BREAKING`, or `NOT_ANALYZED`. The analyzer is intentionally conservative and is a regression-risk signal rather than a formal proof of protocol compatibility.

A standalone deterministic comparison is also available:

```bash
ai-qa contract-diff --baseline old-openapi.yaml --current new-openapi.yaml
```

## Why this is separate from model reasoning

Baseline resolution, Git merge-base computation, file ownership, and structural contract changes are deterministic observations. Claude receives a bounded summary of those facts and can decide how they affect investigation or testing, but it cannot redefine the baseline or turn an unanalyzed contract into a compatible one.
