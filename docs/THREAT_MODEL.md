# Threat Model

## Assets
- model/API credentials
- source and test code
- external engineering-system credentials/data
- runtime policy and evaluation thresholds
- generated patches and test evidence
- production/staging systems

## Primary threats and controls

| Threat | Control |
|---|---|
| Prompt injection from SUT/DOM/logs/MCP | lower-trust content classified as data; narrow tools; policy hooks; adversarial evals |
| Secret exfiltration | no generic read/web tools; `.env` protected; recursive redaction; secrets not logged |
| Runtime self-policy weakening | governance paths protected; runtime has no general write tool |
| Destructive Git mutation | command deny rules; runtime no Bash; isolated workspace expectation |
| False PASS | explicit validation statuses; model completion alone => `NOT_VERIFIED` |
| False self-heal | semantic uniqueness + risk threshold + unsafe diff checks + post-repair validations |
| Regression under-selection | mandatory test invariant; uncertainty broadens selection |
| Rogue MCP | first-party identity allowlist + strict runtime MCP config |
| Production load incident | deterministic production-target denial by default |
| Cross-run artifact contamination | run-scoped artifact/evidence directories |

## Residual risks

Prompt policy is not a sandbox. Production autonomous operation still needs hardened container/VM boundaries, non-root execution, network egress restrictions, resource limits, enterprise secrets, and organization-specific access controls. The showcase does not claim those infrastructure controls were deployed.
