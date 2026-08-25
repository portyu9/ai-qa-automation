# API Observation Boundary

`ApiProbe` is a controlled SUT observation adapter. Its job is to collect one policy-approved HTTP response without allowing compression, response shape, ambiguous JSON, truncation, malformed bytes, or hostile response metadata to silently become stronger evidence than was actually observed.

This boundary governs **framework interpretation after HTTPX has produced a response object**. It does not grant network authority, certify the remote system, or turn an HTTP response into deterministic validation `PASS`.

## Authority position

The runtime authority chain remains:

```text
objective
  -> model/advisory reasoning
  -> deterministic network + method policy
  -> ApiProbe transport
  -> bounded response observation
  -> persisted evidence
  -> deterministic validation
  -> terminal truth
```

`ApiProbe` can create observed HTTP evidence. It cannot authorize a host or method, validate an objective, certify a response as correct, or produce terminal `SUCCESS` by itself.

## Request-side invariants

At the `ApiProbe` boundary itself, HTTP execution requires:

- `http` or `https` scheme;
- an explicitly supplied allowlisted host;
- an allowlisted HTTP method;
- redirect following disabled.

In the internal agent path, the runtime wrapper separately establishes network/method authorization before it constructs `ApiProbe`. Direct library callers do not inherit that wrapper proof merely by instantiating the adapter; they must supply equivalent trusted authorization context themselves.

`ApiProbe` additionally owns the request's `Accept-Encoding` header and forces it to `identity`, overriding a caller-supplied compression preference. This is a resource-safety invariant, not a claim that the remote server will obey the request.

## Compression and raw-body handling

Transparent decompression is intentionally excluded from the accepted observation path.

1. The request asks for `Accept-Encoding: identity`.
2. Response headers are bounded before body ingestion.
3. If the response still declares any non-identity `Content-Encoding`, the response observation is rejected **before body iteration**.
4. Accepted response bodies are consumed through HTTPX raw-byte iteration, not decoded-byte iteration.
5. The configured response-byte ceiling is enforced against those raw bytes.

The adapter reads in bounded chunks. The default retained body ceiling is 100,000 bytes; callers may configure a smaller value or increase it only up to the source-owned hard maximum of 5,000,000 bytes. A bounded extra chunk may establish that additional bytes exist, but retained body bytes never exceed the configured ceiling.

The default network transaction timeout is 10 seconds and is capped by a source-owned maximum of 900 seconds. The HTTP transaction and raw-body streaming phase is enclosed by `asyncio.timeout` in addition to HTTPX operation timeouts, so a peer cannot keep that phase alive indefinitely by sending progress just often enough to reset per-read timeouts. Timeout expiry is recorded as `NETWORK_ERROR` evidence and retains the attempt evidence ID. Bounded UTF-8/JSON interpretation, sanitization, and evidence persistence happen after transport closure and are not claimed to be covered by this async wall-clock timeout.

## Header boundary

After HTTPX has created the response object, `ApiProbe` rejects the observation when either application-level header limit is exceeded:

| Limit | Ceiling |
|---|---:|
| Header entries | 200 |
| Aggregate header-name/value UTF-8 text | 64,000 bytes |

Header counting uses the multi-value representation so duplicate entries still consume count and byte budgets. Invalid Unicode surrogates are rejected. For accepted responses, the returned header mapping is bounded and sanitized; full response headers are not copied into the persisted HTTP-response evidence record by this adapter.

These are **post-transport application limits**. HTTPX/httpcore and the operating system may already have consumed resources to receive and parse protocol metadata before this code can inspect it. Deployment/network-layer header limits remain infrastructure responsibilities.

## Complete-body and truncation semantics

A retained prefix is never represented as a complete response.

`ApiProbeResult.truncated` and the persisted `truncated` field describe the raw-body observation for accepted responses:

- `false` means the raw response body ended within the configured retained-byte ceiling;
- `true` means additional raw response bytes existed beyond the retained prefix;
- `null` is reserved for a response rejected before body observation, where completeness was not measured.

When `truncated=true`, the retained text is never parsed as JSON, even when the prefix is syntactically valid JSON such as `true`, `null`, `[]`, or `{}`. This prevents a valid prefix of a larger payload from being promoted into a false structured observation.

## UTF-8 truth without amplification

The adapter distinguishes valid text from arbitrary bytes.

- A retained body that decodes strictly as UTF-8 sets `utf8_valid=true`.
- A body containing invalid UTF-8 sets `utf8_valid=false` and **does not persist replacement-decoded payload text**.
- Instead, the body representation becomes a fixed-size framework diagnostic containing only the retained byte count and SHA-256 digest.
- Invalid UTF-8 can never produce `json_parsed=true`.

This avoids both semantic mutation and worst-case text amplification from replacement decoding while preserving a deterministic identity signal for the retained byte sequence.

## Strict JSON promotion

A response body becomes structured JSON only when all of the following are true:

1. the response was not truncated;
2. the retained bytes were valid UTF-8;
3. the complete decoded text passes the framework's strict bounded JSON parser.

The strict parser rejects, among other hostile or ambiguous cases:

- duplicate object keys, including escaped aliases that decode to the same key;
- non-standard `NaN`, `Infinity`, and `-Infinity` constants;
- excessive nesting;
- excessive structural nodes or container width;
- non-finite numeric values and excessively large integers;
- invalid Unicode outside the UTF-8 contract.

If strict JSON parsing does not succeed, valid UTF-8 remains bounded text and `json_parsed=false`. The framework never uses permissive last-key-wins parsing to create an authority-bearing structured observation.

The interpretation flags are separate truths:

```text
truncated    -> completeness of retained raw bytes
utf8_valid   -> whether retained raw bytes decode losslessly as UTF-8
json_parsed  -> whether complete valid-UTF-8 text passed strict bounded JSON parsing
```

`json_parsed=true` therefore requires both `truncated=false` and `utf8_valid=true`.

## Transport failure versus observation rejection

Transport failure and deterministic observation rejection are different truths.

### Transport failure

HTTPX request/transport errors create `NETWORK_ERROR` evidence and raise `ApiProbeTransportError`. The internal `probe_api` adapter reports the existing `NETWORK_ERROR` failure envelope and retains the evidence identifier.

### Observation rejection

A response may be reached while its body cannot safely be admitted under deterministic observation policy. Examples include:

- too many response headers;
- aggregate response-header text above the ceiling;
- a non-identity response content encoding.

For these cases, `ApiProbe`:

1. persists bounded `HTTP_RESPONSE` evidence containing the observed HTTP status when available, a low-information rejection code, `response_body_observed=false`, and elapsed time;
2. persists **no rejected response body**;
3. returns an `ApiProbeResult` whose public HTTP `status_code` is `null`;
4. returns `truncated=null` because body completeness was not observed;
5. returns `body=null` and an empty header mapping.

No framework rejection marker is embedded in the `body` namespace because that namespace is SUT-controlled for accepted responses. This prevents a hostile or coincidental SUT JSON document from colliding with framework metadata. The persisted evidence record is the authority for the low-information rejection reason and any HTTP status observed before rejection.

The existing internal `probe_api` adapter can therefore retain the evidence ID without adding a second exception path. A normal MCP return envelope means only that the controlled tool completed its policy handling; it is **not** a SUT success and cannot certify terminal `PASS`. Within a normal `ApiProbeResult`, `status_code=null` identifies an unaccepted response observation; accepted responses always retain their actual integer HTTP status, even when the SUT body itself contains framework-looking keys or text.

## Evidence semantics

For an accepted observation, persisted `HTTP_RESPONSE` evidence includes:

- actual status code;
- bounded/sanitized body representation;
- elapsed time;
- `truncated`;
- `utf8_valid`;
- `json_parsed`.

For a rejected observation, persisted evidence includes the bounded rejection metadata but no response body. The `ApiProbeResult` carries `status_code=null`, `truncated=null`, `body=null`, and the evidence ID so the internal adapter cannot lose the rejection truth or confuse SUT-controlled body content with framework metadata.

The model-facing internal tool currently exposes status, elapsed time, evidence ID, body representation, and truncation state. `json_parsed` and `utf8_valid` remain explicit in the authoritative `ApiProbeResult`/persisted accepted-response evidence and are not prerequisites for model-side claims of PASS in any case.

A `2xx` response is not automatically PASS. Parsed JSON is not automatically trusted. A tool invocation completing normally is not automatically PASS. Model interpretation remains advisory; a deterministic subject-bound validator must establish any objective-closing truth.

## Confidentiality boundary

Existing evidence redaction/sanitization still applies to retained valid-text/structured response bodies and diagnostic errors. That mechanism is not a universal PII/DLP system and cannot guarantee removal of every sensitive application value from arbitrary SUT payloads.

Operators must treat API response evidence as potentially sensitive test data and apply deployment-appropriate artifact access, retention, and data-classification controls.

## What this boundary does not claim

This implementation deliberately does **not** claim that:

- HTTPX/httpcore cannot allocate or parse protocol data before the application receives a response object;
- the adapter timeout controls DNS/TCP/TLS implementation internals after cancellation beyond requiring the probe coroutine to stop waiting;
- DNS, TLS, sockets, proxies, firewalls, service meshes, or kernel buffers are bounded by this Python adapter;
- `Accept-Encoding: identity` forces a remote server to behave correctly — noncompliant encoded responses are rejected instead;
- body truncation preserves a complete semantic document;
- a SHA-256 diagnostic reconstructs or semantically describes invalid UTF-8 payload bytes;
- strict JSON parsing proves schema correctness or business correctness;
- sanitization removes all sensitive information;
- a normal internal-tool return envelope means the SUT succeeded;
- SUT-controlled response-body keys can act as framework rejection markers;
- successful observation grants network/mutation authority or terminal PASS.

The invariant is narrower and stronger: **after a response reaches the application boundary, encoded, oversized, truncated, malformed, ambiguous, or invalidly decoded observations cannot silently masquerade as complete trusted structured evidence.**
