# Limitations and Productionization Checklist

This is a production-shaped portfolio implementation, not a claim that an employer's production environment has been deployed.

## Intentionally NOT_VERIFIED without external infrastructure
- live Claude model execution and model-backed holdouts
- authenticated GitHub MCP calls
- authenticated Atlassian Rovo MCP calls
- Playwright browser binary/runtime on a target application
- k6 against an approved staging workload
- Appium device/emulator/device-cloud execution
- hardened container/VM isolation and infrastructure-level egress policy
- enterprise secret manager and identity policy
- organization-specific compliance mappings and retention

## What production adoption adds
- threat-model review against the actual SUT/data classification
- workload-specific network allowlists/proxy controls
- protected branches + CODEOWNERS for governance paths
- authenticated least-privilege external MCP tool inventory
- persistent telemetry backend and SLOs
- calibrated model-backed eval thresholds and holdout set
- human-approval UX for high-risk writes
- disaster recovery/cancellation/concurrency soak testing

The architecture prefers a truthful `NOT_VERIFIED` over a demo-friendly fabricated green state.
