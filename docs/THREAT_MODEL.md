# Threat Model

## Assets

- model/API credentials
- source and test code
- external engineering-system credentials/data
- runtime policy and evaluation thresholds
- generated patches and test evidence
- target and performance-test systems

## Primary threats and controls

| Threat | Current control |
|---|---|
| Prompt injection from SUT/DOM/logs/MCP | lower-trust content treated as data; narrow tools; deterministic policy hooks; adversarial evals |
| Secret exfiltration | no generic runtime read/web tools; protected secret paths; recursive redaction; sanitized pytest output |
| Runtime self-policy weakening | governance paths protected; no generic runtime write tool; unknown tools fail closed |
| Destructive Git mutation | command deny rules; no runtime Bash; protected control-plane paths |
| False PASS | model completion alone is insufficient; non-empty all-PASS deterministic validation required |
| False self-heal | semantic uniqueness/risk checks; patch-quality gate; post-change validation requirement |
| Regression under-selection | mandatory-test invariant; uncertainty broadens selection |
| Rogue MCP | approved vendor identities; strict MCP config; unknown MCP namespaces denied |
| External write without approval | write operations require approval and fail closed unattended |
| Browser/API egress | explicit host allowlist; browser subrequest routing; API method policy |
| Production load incident | production performance targets denied; script target binding required |
| Cross-run artifact contamination | run-scoped artifact/evidence directories |
| Artifact/evidence tampering in regulated mode | append-only hash chain records event order and prior-event hash |

## Residual boundaries

Prompt policy is not an infrastructure sandbox. The repository does not itself prove operating-system/container isolation, non-root enforcement in every deployment, outbound proxy/firewall controls, organization identity/secret systems, or application-specific authorization boundaries. Those remain environment evidence rather than assumptions in agent results.
