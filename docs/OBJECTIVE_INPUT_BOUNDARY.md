# Objective Input Boundary

The operator objective is trusted as the requested QA goal, but it is still runtime input. It must not become an unbounded persistence, prompt-construction, or provider-resource surface merely because it originates outside the target repository.

## Ingestion contract

`run_agent()` validates the objective before runtime side effects through `runtime/objective_bounds.py`.

The boundary requires:

- an exact built-in `str`; bytes, numbers, booleans, string subclasses, and other coercible objects are rejected;
- at least one non-whitespace character;
- valid Unicode without surrogate code points that cannot satisfy the UTF-8 contract;
- at most 64,000 UTF-8 bytes;
- incremental UTF-8 accounting that stops once the ceiling is exceeded instead of first allocating a second full encoded copy;
- exact preservation of accepted objective text; the framework does not trim, rewrite, normalize, or otherwise change the authority-bearing objective.

The limit is measured in UTF-8 bytes rather than Python characters so multibyte text cannot silently exceed the intended persistence/provider input ceiling.

## Ordering invariant

A denied objective fails before:

1. trusted `Settings` construction for the run;
2. workspace resolution and runtime-root validation;
3. dynamic Claude Agent SDK import;
4. `AgentRunState` creation;
5. artifact/runtime-control persistence;
6. workspace lease acquisition or stale-mutation recovery;
7. repository bootstrap/evidence collection;
8. provider prompt construction or query submission.

This ordering prevents malformed or oversized objectives from creating partial authority-bearing run state or consuming provider/runtime resources.

## Failure semantics

Objective-boundary denial is an input-contract exception (`ObjectiveBoundsError`) rather than a fabricated terminal run. Because no run has been durably created yet, the framework does not manufacture an `AgentRunState`, evidence record, journal entry, or terminal status for a request that never crossed the runtime admission boundary.

The exception exposes only a fixed deterministic reason code such as `objective_type`, `objective_empty`, `objective_unicode`, or `objective_bytes`; rejected objective content is not echoed by the boundary.

## What this does not claim

The 64,000-byte ceiling bounds framework ingestion after the caller has already constructed the Python object. It cannot prevent an upstream caller, shell, API gateway, or process from allocating an oversized value before invoking `run_agent()`.

The deterministic bootstrap context appended after the objective is separately produced from bounded repository observations. This change does not claim that the Claude provider or SDK has no independent context/token limits; it ensures the framework itself never intentionally persists or submits an unbounded operator objective.
