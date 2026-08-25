# Browser Validation Authority

> [!IMPORTANT]
> **A browser validation PASS proves completion of one deterministic browser operation for its exact bound request subject. It does not, by itself, prove that the page is healthy, correct, secure, accessible, or free of console/network defects.**

**ƳƤ AI QA Automation Framework** · Designed and engineered by **Ƴunior Ƥortal (ƳƤ)**

[Documentation home](README.md) · [Result contract](RESULT_CONTRACT.md) · [Security](SECURITY.md) · [Runtime control](RUNTIME_CONTROL.md)

---

The live browser surface is evidence-producing infrastructure. Browser observations can support later deterministic or model-assisted QA decisions, but collecting evidence is not equivalent to asserting an application-level outcome.

This document defines the authority, subject identity, failure semantics, and redaction boundary for the internal Playwright tools.

## Browser operations

The internal browser tools covered by this contract are:

- `inspect_browser` — collect a bounded viewport screenshot, accessibility snapshot, console errors, failed requests, and HTTP error observations for an allowlisted URL;
- `verify_locator_candidates` — load an allowlisted URL and deterministically measure the supplied locator candidates against the current DOM.

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

`browser_locator_verification:<sha256>` binds the exact request supplied to `verify_locator_candidates`:

- operation name;
- exact requested URL;
- exact original locator; and
- ordered candidate request payload.

The candidate request identity includes duplicates and the complete candidate fields supplied to the operation. Reordering candidates or changing an advisory field therefore creates a different gate identity rather than silently reusing earlier validation.

This does **not** make model-supplied locator measurements authoritative. Downstream locator-healing policy recomputes policy-owned semantic and stability signals deterministically before mutation can be authorized.

## Validation outcomes

A browser operation records validation for the current `change_revision`.

| Condition | Validation truth |
|---|---|
| Exact browser operation completes and its evidence is registered | `PASS` |
| Browser runtime/execution cannot complete after the exact subject is established | `NOT_VERIFIED` |
| Request is deterministically denied before a trustworthy browser observation exists | denial/error response; never synthetic PASS |

A browser execution failure is not automatically a product failure. Browser runtime absence, transport/execution uncertainty, or another incomplete observation remains `NOT_VERIFIED`.

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

Browser execution failures that produce exception evidence register that evidence in canonical run state before the corresponding `NOT_VERIFIED` validation is persisted.

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

> **Browser evidence collection is not page correctness. Exact-subject completion is not semantic acceptance. A stale browser PASS cannot erase later uncertainty. Raw URL secrets are not diagnostic metadata. Only a deterministic gate bound to the intended subject may close an objective.**

---

Related: [`RESULT_CONTRACT.md`](RESULT_CONTRACT.md) · [`SECURITY.md`](SECURITY.md) · [`RUNTIME_CONTROL.md`](RUNTIME_CONTROL.md) · [`TRACEABILITY.md`](TRACEABILITY.md)

[← Documentation home](README.md)

Copyright (c) 2026 Ƴunior Ƥortal (ƳƤ). See [`../LICENSE`](../LICENSE).
