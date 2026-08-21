# Operations

## Local deterministic gate

```bash
make quality
make test
make eval
make security
```

If optional tools are unavailable, `ai-qa doctor` reports them as `NOT_VERIFIED` rather than PASS.

## Run artifacts
Every execution uses `artifacts/<run_id>/`. Evidence manifests are sanitized and artifacts are content-hashed. Retention policy is environment-specific and should be configured before production deployment.

## Live agent
Use an isolated target worktree/clone. Do not point the trusted control root at the SUT. Provide credentials through an approved secret manager/environment injection, not tracked configuration.

## Incidents/outages
Distinguish code defects, configuration defects, authentication failures, rate limits, network failures, provider outages, and unknown causes. External integration failure must not fabricate external evidence or block unrelated deterministic local testing.

## CI
The checked-in workflow is manual-only initially. Enable automatic triggers only after repository settings/secrets and branch-protection policy are reviewed.
