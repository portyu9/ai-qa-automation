# Remote API Mutation Authority

The generic `probe_api` / `ApiProbe` path in **ƳƤ AI QA Automation Framework** is an observation primitive, not a remote mutation primitive. It can collect bounded evidence from policy-approved HTTP observations, but it has no authority to create, update, delete, trigger, reset, deploy, or otherwise mutate remote state.

## Fail-closed contract

Generic API observation admits only `GET`, `HEAD`, and `OPTIONS`. `POST`, `PUT`, `PATCH`, and `DELETE` are deterministically denied even when legacy configuration supplies `AI_QA_ALLOW_MUTATING_API_METHODS=true`. Trusted `Settings` rejects that legacy value during configuration validation, and direct `RuntimeServices` construction rejects it again as defense in depth.

`ApiProbe` also refuses caller-supplied method allowlists that contain any method outside the read-only observation set. A direct library caller therefore cannot widen the transport boundary by constructing `ApiProbe(..., allowed_methods={"POST"})`.

The runtime additionally rejects explicit action semantics encoded in otherwise read-only request URLs. Exact action tokens in path/query semantics—such as `delete`, `reset`, `remove`, or `trigger`—are denied before network transport. Bounded repeated percent-decoding prevents simple encoded action tokens from bypassing this classification. The classifier deliberately uses exact tokens rather than arbitrary substrings so ordinary resource nouns such as `runs` or `updated-items` are not automatically treated as actions.

The final transport request is bound to the authority that was classified. `ApiProbe.request()` does not admit post-classification `params`, request bodies, auth/cookie helpers, extensions, or other arbitrary HTTPX request modifiers. Query parameters must be present in the URL that policy classified. The only retained request customization surface is a bounded header set; `Host`, body-shaping headers, transfer framing, and HTTP method-override headers are rejected before transport, and `Accept-Encoding` is forced to `identity`. This prevents a caller from obtaining approval for one read-only URL/method and then changing the effective target, body, query, or method afterward.

This URL/header classification is defense in depth, not a proof that every possible `GET`, `HEAD`, or `OPTIONS` endpoint is side-effect free. The framework still requires operators to expose observation-safe SUT endpoints and to apply deployment-level egress controls. Resolved-destination authority remains a separate network boundary.

## Why generic mutation is absent

A remote side effect cannot safely inherit observation semantics. Once a mutating request is submitted, a timeout or connection failure does not prove that the server failed to apply the operation. A production-shaped autonomous mutation primitive would therefore need a narrower typed contract that, at minimum, binds:

- exact operation and remote subject/resource identity;
- allowed pre-state and transition;
- idempotency/replay semantics where applicable;
- bounded request/body authority;
- durable `PENDING` / unknown-side-effect state before irreversible submission;
- deterministic reconciliation after ambiguous outcomes;
- bounded rollback or compensating authority;
- exact postcondition validation; and
- provenance/revision evidence that closes the operation before later mutation authority is granted.

The generic HTTP probe has none of those authorities, so it does not submit remote mutations. A future typed remote-mutation tool must implement and independently validate that contract; it must not re-enable generic mutation by widening `probe_api`.

## Preserved observation controls

This hardening does not weaken the existing API observation controls. The adapter still requires explicit host authorization, disallows redirect following, uses `trust_env=False`, forces identity content encoding, applies total timeout and response-size bounds, bounds request and response headers, records transport failures as evidence, and never promotes a response or model interpretation directly to deterministic validation `PASS`.

The runtime authority chain remains:

```text
objective
  -> advisory reasoning
  -> deterministic read-only request + network policy
  -> controlled ApiProbe transport
  -> bounded observation
  -> persisted evidence
  -> deterministic validation
  -> terminal truth
```

The stronger invariant is: **generic HTTP observation cannot become autonomous remote-mutation authority through a method flag, adapter constructor, post-classification request modifier, encoded action URL, method-override header, transport ambiguity, or model output.**
