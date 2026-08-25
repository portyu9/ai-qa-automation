# Agent SDK Result Boundary

The Claude Agent SDK is a reasoning/provider boundary, not a runtime authority boundary. A terminal SDK result may describe what the model believes happened, but it cannot authorize tools, manufacture deterministic evidence, certify a mutation, or produce `SUCCESS` without the existing deterministic validation closure.

## Terminal-result ingestion contract

`run_agent()` accepts provider terminal fields only through `runtime/sdk_result_bounds.py` before retaining them in runtime state or returning model text to the caller.

The boundary requires:

- exactly one `ResultMessage` per completed SDK response stream;
- a terminal `ResultMessage` must be present before a completed SDK response is accepted;
- `result` is `None` or an exact string and is limited to 256,000 UTF-8 bytes;
- `subtype` is an exact string and is limited to 256 UTF-8 bytes;
- `is_error` is an exact boolean; string, numeric, missing, or other coercible representations are rejected;
- `total_cost_usd` is `None`, `int`, or `float`, finite, and non-negative; booleans and string coercion are rejected;
- `usage` is `None` or an exact dictionary with at most 64 keys;
- `input_tokens` and `output_tokens` are exact non-negative integers, individually and collectively bounded to 1,000,000,000 tokens;
- no provider string/numeric/boolean coercion is used to make malformed terminal data look valid.

The result-text limit is a retention/output bound, not a claim that the provider could not allocate a larger object before the framework receives it. It prevents the framework from intentionally retaining, persisting indirectly, or returning an unbounded provider result after receipt.

## Failure semantics

A malformed, oversized, missing, or duplicate terminal result is an SDK/provider protocol failure. The framework:

1. clears any previously retained advisory result and ambiguous cost/token accounting from that response;
2. records only the deterministic reason code in the runtime journal;
3. terminates as `INFRASTRUCTURE_FAILURE`;
4. does not retry because provider submission has already begun;
5. never passes the malformed result to deterministic terminal-success evaluation.

The terminal reason contains the bounded reason code, not rejected provider content.

A structurally valid `ResultMessage` with `is_error=True` is different: it is an explicit SDK/provider execution failure signal rather than malformed protocol data. The framework accepts the bounded terminal metadata for accounting, but normalizes terminal evaluation to failure so `subtype="success"` can never override `is_error=True` and produce framework `SUCCESS`.

## Cost authority

`max_budget_usd` remains supplied to the SDK, but the framework does not rely on that provider-side option as its only cost guard. A structurally valid `ResultMessage` whose reported `total_cost_usd` exceeds trusted `Settings.max_cost_usd` deterministically produces `BUDGET_EXCEEDED` in the framework. Model/provider success text cannot override that state.

## What remains advisory

An accepted `agent_result` is still model output. `ResultMessage.subtype == "success"` together with `is_error is False` is necessary for normal completion but is not sufficient for framework `SUCCESS`; `validation_truth.determine_terminal_outcome()` still requires current, subject-bound deterministic validation evidence and the applicable objective or mutation closure.

Credentialed Claude/provider execution remains environment-owned. Repository tests use a fake SDK stream to prove ingestion and terminal-state semantics without fabricating live-provider evidence.
