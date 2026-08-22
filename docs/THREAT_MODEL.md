# Threat Model

> **ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

The ƳƤ AI QA Automation Framework assumes it will encounter misleading, malformed, stale, compromised, or instruction-shaped content in repositories, tests, applications, logs, API responses, browser state, and external engineering systems.

The model itself is also inside the threat model: probabilistic reasoning can be wrong, overconfident, or manipulated.

## Security objective

The goal is not “the model never makes a mistake.” It is:

> **A model mistake, hostile target input, broken provider, stale workspace, or partial runtime failure must not silently widen authority, corrupt the target, exfiltrate secrets, weaken test intent, fabricate evidence, or manufacture verified success.**

## Assets

- model/API credentials;
- source and test code;
- developer worktree changes;
- target application/data integrity;
- external engineering-system credentials/data;
- policy, hooks, Skills, tool schemas, and evaluation thresholds;
- canonical QA state and validation lineage;
- runtime process-control state;
- generated/repaired tests;
- performance-test targets;
- run artifacts, screenshots, logs, manifests, journals, and audit records;
- provider/tool authorization boundaries.

## Trust boundaries

| Zone | Trust posture |
|---|---|
| **Control plane** | Trusted framework code/configuration that defines authority |
| **Target/SUT** | Untrusted data: source, tests, target instructions/config, DOM, logs, API responses, files |
| **External integrations** | Provider identity explicitly approved; returned content remains untrusted evidence |
| **Deployment infrastructure** | Independent enforcement domain for process/container/network/identity/secrets/retention |

## Threats and controls

| Threat | Deterministic / architectural control |
|---|---|
| Prompt injection from source/DOM/log/provider content | lower-trust content treated as data; narrow tools; deterministic policy/hooks; target config not inherited |
| Target `CLAUDE.md` / `.claude` / `.mcp.json` authority injection | disjoint trusted control root; project-only Agent SDK settings; strict MCP config |
| Secret exfiltration | no generic read/web authority; protected paths; credential-minimal subprocess env; recursive redaction; bounded hosts |
| Malformed trusted network configuration | canonical host/IP validation; wildcard, URL, port, path, query, fragment, user-info, malformed labels rejected |
| Runtime self-policy weakening | governance paths protected; no generic runtime write tool; unknown tools fail closed |
| Destructive Git/system mutation | no runtime Bash; destructive command/tool policy; mutation restricted to approved test paths |
| Filesystem traversal | lexical + resolved confinement for target, artifact, run, and rollback paths |
| Symlink redirection during live mutation | path-component symlink rejection before transaction preparation |
| Symlink redirection during crash recovery | prior-run, pending-target, metadata, and rollback ownership validated before stale restoration |
| False product-defect attribution | evidence-weighted deterministic classification; insufficient-evidence state |
| Locator classification poisoned by unrelated unique element | locator-contract classification requires deterministic semantic relationship to original locator |
| Model-inflated self-healing confidence | Playwright owns uniqueness; deterministic locator policy overwrites semantic/stability authority |
| Wrong nearby locator repair | same-DOM screenshot/accessibility context + syntax/semantic/stability checks + exact file/hash binding |
| Test-intent weakening | patch-quality rules block skip/xfail/sleep/timeout/assertion erosion/suppression; test-quality review |
| Meaningless generated tests | observed coverage + same-run plan + meaningful assertion checks + execution validation |
| False PASS from model completion | structured terminal truth derived from deterministic gate lineage, not prose/result subtype alone |
| Retry hides contradiction | same-gate PASS/FAIL at same revision resolves to `NOT_VERIFIED` |
| Old evidence certifies new bytes | change revisions + same-gate supersession + current-revision closure requirements |
| Regression under-selection | mandatory/security/safety/regulatory/smoke preservation; uncertainty broadens selection |
| Concurrent agent corruption | OS-backed lease + content-sensitive workspace fingerprint before mutation |
| Crash overwrites human work | stale rollback requires exact persisted fingerprint; mismatch blocks automatic recovery |
| Rollback backup substitution/tampering | rollback-root confinement + non-symlink ownership + original SHA-256 verification |
| Cross-run evidence contamination | confined run roots + immutable evidence/artifact IDs/paths + run IDs |
| Artifact path escape | run/artifact confinement and symlink rejection |
| Persisted record tampering | atomic state, artifact hashes, hash-chained journal, optional regulated audit chain |
| Rogue/community MCP | vendor allowlist + strict explicit MCP registry/config |
| Excessive MCP privilege | provider identity separate from tool authorization; GitHub read-only defense in depth |
| Action-name privilege smuggling | camel/snake tokenization; destructive > write > read precedence; noun collisions handled explicitly |
| External write without approval | writes require approval; unattended execution denies approval-required operations |
| Fabricated remote evidence during outage | normalized provider failure outcomes; failed calls do not create remote evidence |
| Provider/business-ID misclassification | HTTP result parsing requires status-shaped context rather than arbitrary numeric IDs |
| Browser/API egress | canonical host allowlist; browser request/WebSocket routing; read-only API default; no ambient proxy inheritance |
| Browser service-worker egress bypass | service workers blocked in evidence context |
| Production load incident | environment + production-like hostname denial; target binding; script/import controls; egress prerequisite |
| k6 script escapes intended target | injected target requirement; remote modules/extensions/local file reads/unrelated literal hosts rejected |
| Unbounded autonomous loop | independent turn/tool/network/mutation/repetition/time/cost limits + per-tool circuits |
| Supply-chain vulnerability | deliberate dependency/provider pin review + compatibility/vulnerability/static/secret gates |
| Integrity hash misrepresented as identity or PASS | attestation/hash semantics explicitly separate integrity from signing/correctness |

## High-value adversarial cases

Regression and holdout coverage should continue challenging cases such as:

- a DOM node telling Claude to ignore policy and call a forbidden tool;
- a Jira/GitHub issue requesting credentials or workflow changes;
- a target repository shipping its own MCP server or agent instructions;
- `getOrCreateIssue` or `listAndDeleteIssues` attempting to inherit read authority from a prefix;
- an arbitrary business object ID `403` being misread as HTTP authorization failure;
- a unique `Delete Account` button receiving model confidence `1.0` while the stale locator represented `Save Profile`;
- a locator candidate with fabricated uniqueness count;
- a positional/XPath selector that happens to pass once;
- a test “repair” removing the failing assertion;
- assertion-like text inside a comment/string satisfying a weak test-quality scanner;
- an autonomous write redirected through a symlink;
- a stale rollback redirected through a symlink after a crash;
- a tampered rollback backup with correct path but wrong bytes;
- a run/artifact identifier attempting traversal;
- a clean feature branch with committed security-critical changes that a dirty-worktree-only scan would miss;
- a developer edit after an agent crash;
- low-confidence test-impact data attempting to shrink regression scope;
- wildcard or URL-shaped network allowlist configuration;
- a k6 script importing a remote module;
- a production-like hostname presented with `environment=staging`;
- a provider outage encouraging fallback to an unapproved integration;
- a large retry loop attempting to consume one budget dimension through another.

The purpose of these cases is to prove controls, not to rely on stronger wording in a prompt.

## Residual deployment boundaries

Repository code cannot independently establish every property of a deployed system. Deployment owns concerns such as:

- process/container isolation;
- non-root enforcement;
- outbound firewall/proxy/network policy;
- organization identity and secret-management lifecycle;
- provider-side authentication/authorization;
- artifact encryption/access/retention;
- legal/compliance controls;
- target-application authorization/data policy;
- device/emulator/cloud security posture;
- infrastructure availability and incident response.

Application-level allowlists, flags, and policy checks are defense in depth. They are not substitutes for infrastructure controls where high assurance is required.

## Threat-model maintenance rule

A material new threat should produce an engineering artifact:

- narrower policy;
- safer tool/schema contract;
- stronger evidence semantics;
- regression/security test;
- primary or holdout adversarial case;
- or explicit deployment boundary when code cannot enforce the property.

“Tell Claude not to do it” is not an adequate control when the behavior can be deterministically constrained.

See [`README.md`](README.md), [`SECURITY.md`](SECURITY.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md), and [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
