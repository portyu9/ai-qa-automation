# Browser Validation Authority

> [!IMPORTANT]
> **A browser validation PASS proves completion of one deterministic browser operation for its exact bound request subject. It does not, by itself, prove that the page is healthy, correct, secure, accessible, or free of console/network defects.**

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Result contract](RESULT_CONTRACT.md) · [Security](SECURITY.md) · [Runtime control](RUNTIME_CONTROL.md)

---

The live browser surface is evidence-producing infrastructure. Browser observations can support later deterministic or model-assisted QA decisions, but collecting evidence is not equivalent to asserting an application-level outcome.

This document defines the authority, subject identity, failure semantics, runtime selection, and redaction boundary for the internal Playwright tools.

## Browser operations

The internal browser tools covered by this contract are:

- `inspect_browser` — collect a bounded viewport screenshot, accessibility snapshot, console errors, failed requests, and HTTP error observations for an allowlisted URL;
- `verify_locator_candidates` — bind one exact failing targeted-pytest subject, load an allowlisted URL, and deterministically measure the supplied locator candidates against the current DOM.

Both operations run through the framework's controlled Playwright adapter and network-host policy. Redirects, subresource requests, and WebSocket connections are constrained by the browser allowlist logic.

## Exact subject binding

A generic browser-capability label is not sufficient authority. The framework therefore records browser validation under subject-specific gate IDs.

### Browser inspection

`browser_inspection:<sha256>` binds the complete requested URL supplied to `inspect_browser`.

The SHA-256 digest is computed over canonical operation identity that includes:

- operation name; and
- exact requested URL.

A PASS for URL A cannot satisfy an operator objective contract for URL B.

### Locator verification

`browser_locator_verification:<sha256>` binds the exact browser request supplied to `verify_locator_candidates`:

- operation name;
- exact requested URL;
- exact original locator; and
- ordered candidate request payload.

The candidate request identity includes duplicates and the complete candidate fields supplied to the operation. Reordering candidates or changing an advisory field therefore creates a different browser gate identity rather than silently reusing earlier validation.

This browser gate does **not** make model-supplied locator measurements authoritative and does not authorize a test mutation. Playwright overwrites candidate uniqueness with observed counts, deterministic policy recomputes semantic intent and stability, and locator mutation requires the separate repair authority below.

### Locator repair authority

Autonomous locator repair is authorized only through a content-addressed `locator_repair:<sha256>` validation subject. The subject is created only after the framework can join the browser observation to one exact failing test subject.

Before browser execution, `verify_locator_candidates` requires the exact ID of an executed failing targeted-pytest validation at the current `change_revision`. The runtime derives rather than accepts from the caller:

- the targeted pytest selector and exact test-file path;
- the exact failing pytest node identity;
- the exact observed pytest failure evidence IDs;
- the current Git SHA and complete workspace fingerprint;
- the exact target-file SHA-256;
- the exact supported original locator and its unique occurrence inside that selected Python test node; and
- the current change revision.

File-only targeted selectors are intentionally too ambiguous for autonomous locator repair. The repair path currently requires an explicit Python pytest node selector that can be mapped deterministically to one source test function.

The failing pytest evidence must itself prove that it observed the same Git SHA and workspace fingerprint: its before/after workspace fingerprints must match, workspace integrity must be verified, and its frozen execution-subject Git SHA/source fingerprint must match the subject being repaired. A stale failure record at the same numeric revision therefore cannot be retrospectively attached to newer out-of-band workspace bytes.

After Playwright completes, the repair subject additionally binds:

- the exact `browser_locator_verification` gate;
- the Playwright locator-verification observation;
- the exact same-DOM screenshot and accessibility evidence IDs;
- requested URL and candidate-request hashes from the browser subject;
- the exact requested candidate count, which must equal the number of measured candidate rows; and
- deterministic failure classification/confidence computed **only** from the bound pytest failure evidence plus that exact Playwright verification and same-DOM context.

A truncated, expanded, or otherwise cardinality-inconsistent candidate observation cannot create repair authority, even if individual rows look plausible. If Playwright completed the exact browser operation but later repair-subject construction fails this additional authority validation, the browser gate remains `PASS` for the observation it actually completed while locator repair remains unverified and no repair subject is created.

When a repair subject is created, the browser validation record carries reverse linkage to the repair-subject ID, failing validation/node/path, workspace revision/Git SHA/fingerprint, and target-file digest. Every later repair-subject resolution requires that exact browser metadata and exact browser evidence list to still match the repair subject. A detached or rewritten browser PASS cannot be reattached to a different repair authority.

Run-wide `classify_failure` remains useful diagnostic state, but it cannot grant locator mutation authority. Unrelated evidence elsewhere in the run cannot raise the repair subject's classification confidence. Persisted classification fields are not trusted on reuse: every proposal/apply resolution reruns the deterministic `FailureAnalyzer` over the exact bound evidence subset and requires the stored classification, confidence, and evidence IDs to reproduce exactly.

`propose_locator_heal` accepts only the repair-subject ID and a candidate list. It does not accept a target path, expected file hash, original locator, or arbitrary verification evidence ID. Candidates are eligible only if they resolve uniquely in the repair subject's exact Playwright observation.

`apply_locator_heal` accepts only an approved proposal ID. Before writing it re-resolves the repair subject and revalidates the current revision, Git SHA, complete workspace fingerprint, target-file SHA, original locator occurrence, failing pytest lineage, browser gate/linkage, verification evidence, candidate cardinality, same-DOM context, and replayed deterministic classification. The proposal's mirrored authority fields must still match the canonical subject, and the selected locator must reproduce under deterministic healing policy.

Any intervening authorized mutation or out-of-band workspace change invalidates an unused proposal even if the target file itself is byte-identical. Closing a newer revision cannot reactivate an older proposal. Exact target-file SHA equality is therefore necessary but intentionally insufficient freshness proof for browser/classification evidence.

A successful locator write establishes only deterministic patch-safety evidence for the new revision. It does not certify the changed test or close the mutation transaction. Exact-path targeted pytest with trusted out-of-process executed-test outcome authority and the controller-bound full regression are still required by the runtime result contract. The current live targeted adapter deliberately does not manufacture that trusted outcome authority; until that separate observer exists, a positive autonomous test mutation cannot be promoted to verified closure merely because locator repair was subject-bound.

## Validation outcomes

A browser operation records validation for the current `change_revision`.

| Condition | Validation truth |
|---|---|
| Exact browser operation completes and its evidence is registered | `PASS` |
| Browser runtime/execution cannot complete after the exact subject is established | `NOT_VERIFIED` |
| Request is deterministically denied before a trustworthy browser observation exists | denial/error response; never synthetic PASS |

A browser execution failure is not automatically a product failure. Browser runtime absence, transport/execution uncertainty, or another incomplete observation remains `NOT_VERIFIED`.

For locator healing, `browser_locator_verification=PASS` means only that candidate measurement completed. A separate `locator_repair_subject=PASS` is required before proposal evaluation, and that PASS still authorizes only the bounded repair decision—not post-mutation correctness or revision closure. A browser PASS can therefore coexist with missing locator-repair authority when the browser observation completed but subject correlation, cardinality, context, or classification validation did not.

## Browser runtime authority

`BrowserProbe` keeps Playwright-managed Chromium as its default runtime. A caller can select one additional reviewed mode with `use_system_chrome=True`; that boolean maps only to Playwright's `chrome` channel. The API does not accept an arbitrary executable path or arbitrary browser channel, so enabling the system-browser mode does not become a generic local-process authority expansion.

Permanent automatic reference-SUT CI uses `use_system_chrome=True` and relies on the `ubuntu-24.04` hosted image's preinstalled Google Chrome. Before the browser test, CI requires `/usr/bin/google-chrome` to be executable and prints its observed version. The automatic workflow does **not** run `playwright install`, `--with-deps`, `sudo`, `apt-get`, or `apt install`; `scripts/verify_ci_contract.py` rejects those automatic authority tokens and requires the exact hosted-Chrome observation step.

This removes the previous PR-time path that switched to root, refreshed mutable APT repositories, installed OS packages, and downloaded browser/FFmpeg payloads from the Playwright CDN. It does **not** make the hosted browser immutable: the `ubuntu-24.04` label can advance to a newer runner image and browser build. Browser executable identity/version therefore remains environment-owned evidence observed in the job log, not a repository cryptographic attestation. If the hosted Chrome runtime is absent or incompatible, browser validation must fail/return incomplete truth rather than reinstalling privileged dependencies automatically.

### Stale-green prevention

If the same browser gate has an earlier PASS and a later `NOT_VERIFIED` at the same active revision, terminal truth remains incomplete. The framework does not select the convenient older PASS and discard the newer uncertainty.

The historical generic gate ID `browser_runtime` is explicitly rejected as an unchanged-run objective-closing gate. Recovered legacy state therefore cannot use an unbound browser-capability PASS to manufacture objective success.

## Evidence binding

A successful browser validation carries the evidence IDs produced by that exact operation.

For inspection, this can include:

- viewport screenshot evidence;
- accessibility snapshot evidence; and
- network-error evidence when failed requests or HTTP error responses were observed.

For locator verification, the validation carries:

- the Playwright locator-verification observation; and
- its same-DOM screenshot/accessibility context evidence.

The locator-repair subject then joins those browser evidence IDs to the exact current targeted-pytest failure evidence subset and workspace/file authority. The browser evidence is not detached and reintroduced later through caller-selected identifiers.

Browser execution failures that produce exception evidence register that evidence in canonical run state before the corresponding `NOT_VERIFIED` validation is persisted. A generic browser runtime failure after the exact locator-verification subject is established is likewise persisted as `NOT_VERIFIED`, not misrepresented as a pre-execution policy denial.

## PASS is operation completion, not page health

A `browser_inspection` PASS means the controlled operation completed for its exact request and evidence was captured. It does **not** mean:

- the page returned no HTTP errors;
- console errors were absent;
- every network request succeeded;
- visual content matched a product requirement;
- accessibility requirements passed;
- security requirements passed; or
- business behavior was correct.

Likewise, a `browser_locator_verification` PASS means the requested candidates were deterministically measured. It does **not** mean any candidate is acceptable for autonomous healing.

If an operator objective requires one of those stronger assertions, the objective must identify a deterministic acceptance gate that evaluates the relevant evidence. Evidence collection alone cannot be promoted into a semantic product-health assertion.

## URL confidentiality boundary

Browser/provider diagnostics can contain URLs that embed sensitive values in credentials, paths, query strings, or fragments. Pattern-based secret detection is not sufficient because arbitrary opaque values may not look like known credentials.

Before URL-shaped text is persisted or exposed through model-facing diagnostics, shared structural redaction:

1. removes URL userinfo;
2. removes query strings;
3. removes fragments;
4. replaces every non-root network URL path with an idempotent SHA-256 path marker;
5. preserves only scheme, host, optional port, and the stable path-correlation marker; and
6. collapses `data:` and `blob:` URLs to explicit redacted scheme markers.

Example shape:

```text
https://example.test/_redacted_path_sha256/<sha256>
```

The marker is for deterministic correlation, **not encryption**. A SHA-256 digest of a low-entropy path can be guessable by dictionary comparison. The framework therefore does not claim that path hashing provides cryptographic confidentiality against an attacker who can enumerate candidate paths.

Repeated sanitization is idempotent: an already-generated path marker is not hashed again.

## Raw browser artifacts are a different trust surface

Structural URL redaction does not imply universal PII or secret removal from screenshots or accessibility snapshots. A target application can render sensitive text into the page itself.

Accordingly:

- screenshots are evidence artifacts, not assumed-clean text;
- accessibility snapshots can contain SUT-visible content;
- artifact access and retention remain operational/security responsibilities; and
- no browser PASS certifies that captured page content is free of sensitive information.

This distinction prevents URL sanitation from being misrepresented as whole-artifact data-loss prevention.

## Network authority

Browser URL allowlisting is application-level policy. It constrains the controlled Playwright browser adapter's navigation, subresource, and WebSocket behavior.

It does not prove that the deployment environment itself provides a general network sandbox for arbitrary target-controlled processes. That distinction is the same authority rule documented for target-controlled pytest execution: application policy and deployment isolation are separate trust domains.

## Resource and failure truth

Browser evidence collection remains bounded where the adapter controls resource growth, including bounded event histories, bounded accessibility text, viewport-only screenshots, candidate-count limits, and browser timeouts.

A malformed, denied, oversized, unavailable, or otherwise untrustworthy browser request must remain a denial or incomplete result. Missing browser evidence is never converted to PASS by model interpretation.

## Core invariant

> **Browser evidence collection is not page correctness. Exact-subject completion is not semantic acceptance. Locator repair requires one exact failing-test/workspace/browser subject, not caller-selected path authority. Persisted classification is replayed, not trusted. Candidate rows must match the bound browser request. Target-file SHA alone is not evidence freshness. A stale browser PASS cannot erase later uncertainty. Raw URL secrets are not diagnostic metadata. Automatic PR browser validation may observe a hosted browser but may not install privileged browser/OS dependencies. Only a deterministic gate bound to the intended subject may close an objective.**

---

Related: [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) · [`SECURITY.md`](SECURITY.md) · [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) · [`TRACEABILITY.md`](TRACEABILITY.md)

[← Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
