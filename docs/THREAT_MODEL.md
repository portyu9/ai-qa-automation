# Threat Model

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

This threat model assumes the ƳƤ AI QA Automation Framework can encounter malicious or misleading content in the target repository, rendered application, test output, API responses, and external engineering systems. The design therefore treats **prompt injection and model error as expected threat inputs**, not exceptional events.

## Security objective

The primary security goal is not “the model never makes a mistake.” It is:

> **A model mistake, malicious target input, broken integration, or partial runtime failure must not silently widen authority, corrupt the target, exfiltrate secrets, weaken test intent, or manufacture a verified PASS.**

## Assets

- model/API credentials;
- source and test code;
- external engineering-system credentials and data;
- runtime policy, hooks, Skills, and evaluation thresholds;
- canonical state and evidence;
- generated/repaired tests;
- target worktrees and developer changes;
- performance-test targets;
- run artifacts, screenshots, logs, and audit records;
- provider/tool authorization boundaries.

## Trust boundaries

| Zone | Trust posture |
|---|---|
| Control plane | Trusted configuration/code: runtime package, policy, hooks, Skills, thresholds, explicit integration config |
| Target/SUT | Untrusted data: source, tests, target instructions/config, DOM, logs, API responses, files |
| External integrations | Provider identity explicitly approved; returned content still untrusted evidence |
| Deployment infrastructure | Outside repository trust proof; OS/container/network/identity controls require environment evidence |

## Primary threats and controls

| Threat | Deterministic / architectural control |
|---|---|
| Prompt injection from SUT/DOM/logs/MCP | lower-trust content treated as data; narrow tools; deterministic policy/hooks; adversarial evaluations |
| Target `CLAUDE.md` / `.claude` / `.mcp.json` authority injection | disjoint trusted control root; strict explicit runtime configuration; target config not inherited |
| Secret exfiltration | no generic runtime read/web authority; protected paths; credential-minimal subprocess environments; recursive redaction; bounded network hosts |
| Runtime self-policy weakening | governance paths protected; no generic runtime write tool; workflow/hook controls; unknown tools fail closed |
| Destructive Git/system mutation | no runtime Bash; command/tool policy; target-path confinement; autonomous writes restricted to approved tests |
| Filesystem traversal / symlink redirection | resolved path confinement plus explicit rejection of mutation traversal/absolute/symlink components; artifact/run-root confinement |
| False product-defect attribution | evidence-weighted classification; insufficient-evidence state; model interpretation alone cannot prove defect class |
| False PASS | model completion insufficient; deterministic validation lineage required; same-revision contradictions remain `NOT_VERIFIED` |
| False self-heal | browser-observed uniqueness; semantic proposal rules; hash/path binding; narrow locator mutation; post-change validation |
| Test-intent weakening | patch-quality rules block skip/xfail/sleep/timeout/assertion weakening/suppression patterns; AST-based test-quality review |
| Meaningless generated tests | observed-coverage provenance + plan binding + meaningful assertion checks + execution validation |
| Regression under-selection | mandatory-test preservation; change-risk signals; low confidence/truncation broadens selection |
| Concurrent agent corruption | OS-backed workspace lease + Git/worktree fingerprint check before mutation |
| Crash overwrites human work | pending transaction checkpoint + fingerprint-gated stale rollback; mismatch blocks for manual review |
| Rollback backup substitution | trusted rollback-directory confinement + original-content hash verification before restoration |
| Rogue/community MCP | provider allowlist; strict explicit MCP config; unknown namespaces denied |
| Excessive MCP privilege | tool-level read/write/destructive policy; mixed-action verb precedence; GitHub server read-only defense in depth; unknown actions not auto-approved |
| Action-name privilege smuggling | camel/snake normalization; destructive token dominates write/read; write token dominates read; pull-request noun collision explicitly handled |
| External write without approval | writes require approval; unattended execution fails closed; destructive actions denied |
| Fabricated remote evidence during outage | normalized MCP failure states; no synthetic response/evidence on transport/auth/rate-limit failure |
| Browser/API egress | explicit host allowlist; read-only API default; browser subrequest/WebSocket policy; no ambient proxy inheritance |
| Production load incident | explicit environment denial + production-like DNS-label denial + injected target binding + k6 script restrictions + external egress precondition |
| Unbounded/autonomous loop | independent turn/tool/network/mutation/repetition/time/cost limits + per-tool failure circuits |
| Cross-run evidence contamination | confined run-scoped artifact/evidence/state directories, immutable evidence/artifact identifiers, run IDs |
| Persisted record tampering | atomic state writes; artifact hashes; hash-chained runtime journal; optional regulated audit chain; verification surfaces corruption |
| Supply-chain vulnerability | pinned critical SDK/MCP component versions where appropriate; dependency audit/static security gates; explicit update review |

## Abuse cases worth preserving in regression coverage

Security confidence should be challenged with scenarios such as:

- a DOM node telling the agent to ignore policy and use a forbidden tool;
- a Jira/GitHub issue requesting secrets or workflow modification;
- a target repository shipping its own MCP server configuration;
- a mixed external MCP action such as a read-prefixed create/delete request;
- a locator repair selecting a nearby but semantically wrong element;
- a test “fix” that removes the assertion causing the failure;
- an assertion-like string/comment being mistaken for a real test assertion;
- an external integration repeatedly returning rate limits or malformed content;
- a run identifier or artifact path attempting to escape the trusted artifact root;
- a symlink alias attempting to redirect an autonomous test mutation;
- a tampered rollback backup attempting to replace original bytes;
- a clean feature branch whose committed security-critical change would be missed by worktree-only analysis;
- an agent crash after a test mutation followed by a developer edit;
- low-confidence test-impact analysis attempting to shrink the regression set;
- a k6 script importing a remote module or pointing at a production-like host while metadata claims staging.

The goal of these cases is to verify controls, not to rely on a stronger prompt.

## Residual boundaries

The repository cannot by itself prove every security property of a deployment. In particular, it does not establish:

- operating-system/container isolation;
- non-root enforcement in every deployment;
- outbound proxy/firewall controls;
- organization identity and secret-management policy;
- provider-side authentication/authorization correctness;
- data retention/legal/compliance controls;
- target-application authorization rules;
- real device/cloud security posture;
- external service availability or trustworthiness.

Those are environment evidence, not assumptions in agent results.

Application-level allowlists and flags are defense in depth; they must not be documented as substitutes for infrastructure controls when high assurance is required.

## Threat-model maintenance rule

A material newly discovered threat should produce a concrete artifact: a narrower policy, safer tool contract, regression/security test, adversarial evaluation, or an explicit environment boundary. “Tell Claude not to do it” is insufficient when the behavior can be enforced deterministically.

See [`SECURITY.md`](SECURITY.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), and [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
