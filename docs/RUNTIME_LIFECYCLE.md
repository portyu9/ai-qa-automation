# Runtime Lifecycle and Mutation Closure

## Purpose

This page owns the runtime request, evidence, validation, mutation, and crash-recovery flows that are intentionally too detailed for the repository landing page. The main README keeps only the primary trust-and-authority architecture diagram.

The lifecycle follows one rule throughout: **reasoning proposes; deterministic policy authorizes; controlled tools observe or act; evidence is provenance-bound; subject/revision-bound validation decides terminal truth.**

## Request → authorization → evidence → terminal validation

```mermaid
sequenceDiagram
    accTitle: Bounded agent request, authorization, evidence, and terminal validation sequence
    accDescr: The operator submits an objective to the trusted runtime. Claude proposes actions, deterministic policy authorizes or denies them, controlled tools observe the untrusted target or provider, evidence is persisted, and deterministic validation derives the terminal outcome.
    autonumber

    actor O as Operator

    box rgba(130,80,223,0.08) Advisory reasoning
      participant C as Claude
    end

    box rgba(9,105,218,0.08) Trusted deterministic control plane
      participant R as Trusted runtime
      participant P as Policy + hooks
      participant T as Narrow QA tool
      participant E as Evidence store
      participant V as Deterministic validator
    end

    box rgba(207,34,46,0.08) Untrusted evidence source
      participant U as SUT / provider
    end

    O->>R: Submit bounded objective
    R->>R: Validate trust roots, lease workspace, fingerprint revision
    R->>C: Provide objective + bounded observed context
    C->>P: Request action
    P->>P: Check tool, path, network, budget, circuit, drift

    alt denied or approval unavailable
        P-->>C: DENY / BLOCKED
        P->>E: Persist policy/runtime event
    else explicitly authorized
        P->>T: Execute purpose-built capability
        T->>U: Observe or perform bounded side effect
        U-->>T: Raw result
        T->>E: Persist evidence + provenance
        T-->>C: Return bounded sanitized result
    end

    C-->>R: Agent result
    R->>V: Evaluate active subject/revision-bound gate lineage
    V-->>R: Deterministic terminal outcome
    R-->>O: Structured result + evidence references + provenance
```

The sequence separates provider/model liveness from framework success. A model completion is an input to terminal evaluation; it is never sufficient authority for `SUCCESS`.

## Evidence-first runtime lifecycle

```mermaid
flowchart TD
    accTitle: Evidence-first runtime lifecycle with transactional mutation closure
    accDescr: The runtime acquires and validates workspace ownership, builds deterministic evidence, starts bounded advisory reasoning, authorizes every tool request, persists provenance, and requires exact-path patch safety plus independently trusted targeted and full-regression executed-test semantics before a mutated revision can persist.

    A[Acquire owned workspace lease] --> B[Recover only safely-owned stale mutation]
    B --> C[Capture Git/worktree fingerprint]
    C --> D[Build deterministic repository/change evidence]
    D --> E[Start bounded Agent SDK session]
    E --> F{Tool requested}
    F --> G[Policy + budget + circuit + drift checks]
    G -->|deny| H[Record explicit non-PASS outcome]
    G -->|allow| I[Controlled tool executes]
    I --> J[Persist evidence + provenance]
    J --> K{Mutation?}
    K -->|no| E
    K -->|yes| L[Open rollback-backed transaction]
    L --> M[Patch-safety PASS for exact path]
    M --> N[Exact-path-bound targeted pytest diagnostics]
    N --> O[Independent targeted semantic PASS]
    O --> P[Full-regression execution diagnostics]
    P --> R[Independent regression semantic PASS]
    R --> S[Durably commit revision]
    S --> E
    E --> Q[Derive terminal outcome from validation lineage]

    classDef control fill:#ddf4ff,stroke:#0969da,color:#24292f,stroke-width:2px
    classDef advisory fill:#fbefff,stroke:#8250df,color:#24292f,stroke-width:2px
    classDef decision fill:#f6f8fa,stroke:#57606a,color:#24292f,stroke-width:2px
    classDef denied fill:#ffebe9,stroke:#cf222e,color:#24292f,stroke-width:2px
    classDef evidence fill:#dafbe1,stroke:#1a7f37,color:#24292f,stroke-width:2px
    classDef terminal fill:#dafbe1,stroke:#1a7f37,color:#24292f,stroke-width:3px

    class A,B,C,D,G,I,L control
    class E advisory
    class F,K decision
    class H denied
    class J,M,N,O,P,R,S evidence
    class Q terminal
    linkStyle default stroke:#57606a,stroke-width:1.5px
```

A targeted run against an unrelated file is diagnostic evidence; it cannot certify the pending mutation. Even an exact-path targeted exit `0`, or a reconciled full-regression transcript with exit `0`, cannot positively certify its own execution semantics from inside the target interpreter.

## Transactional mutation and crash recovery

```mermaid
stateDiagram-v2
    direction LR
    accTitle: Transactional mutation and crash-recovery state machine
    accDescr: A mutation starts only from an owned baseline. Exact-path patch safety and targeted/full-regression execution diagnostics require independent semantic proof before commit. Failure or incomplete proof rolls back. A crash can recover automatically only when workspace ownership, fingerprint, paths, and backup integrity remain provable; otherwise the runtime blocks for manual review.

    [*] --> Baseline: owned lease + fingerprint

    Baseline --> Pending: authorized mutation + owned rollback snapshot
    Baseline --> Blocked: drift / policy denial / path ambiguity

    Pending --> PatchSafe: exact-path patch-safety PASS
    Pending --> Rollback: tool failure / terminal without closure

    PatchSafe --> Targeted: exact-path-bound pytest diagnostics
    PatchSafe --> Rollback: safety FAIL / incomplete

    Targeted --> TargetedSemantics: independent targeted semantic PASS
    Targeted --> Rollback: targeted FAIL / unbound / missing authority

    TargetedSemantics --> Regression: full-regression execution diagnostics
    Regression --> Committed: independent regression semantic PASS
    Regression --> Rollback: regression FAIL / missing authority / incomplete

    Rollback --> Baseline: prior bytes restored / new file removed
    Rollback --> IntegrityFailure: restore ownership/integrity uncertain

    Pending --> Crashed: process exit
    PatchSafe --> Crashed
    Targeted --> Crashed
    TargetedSemantics --> Crashed
    Regression --> Crashed

    Crashed --> Recovered: fingerprint + ownership + backup verified
    Recovered --> Baseline: stale mutation reverted
    Crashed --> ManualReview: newer work / ownership ambiguity

    classDef active fill:#ddf4ff,stroke:#0969da,color:#24292f,stroke-width:2px
    classDef verified fill:#dafbe1,stroke:#1a7f37,color:#24292f,stroke-width:2px
    classDef recovery fill:#fbefff,stroke:#8250df,color:#24292f,stroke-width:2px
    classDef blocked fill:#ffebe9,stroke:#cf222e,color:#24292f,stroke-width:2px

    class Baseline,Pending,Regression active
    class PatchSafe,Targeted,TargetedSemantics,Committed verified
    class Rollback,Crashed,Recovered recovery
    class Blocked,IntegrityFailure,ManualReview blocked
```

## Mutation closure contract

For changed test bytes to persist at one revision, the runtime requires all of the following:

1. deterministic patch-safety `PASS` bound to the exact changed path;
2. targeted pytest diagnostics explicitly selecting that same path;
3. independently trusted targeted executed-test semantic `PASS` for the frozen subject/path;
4. full-regression diagnostics for the same change revision;
5. independently trusted full-regression executed-test semantic `PASS` for that revision;
6. no conflicting active validation; and
7. durable transaction metadata that can be safely committed.

Target-controlled collection, output, report, and exit evidence can remain useful diagnostics or fail-safe denial inputs. They cannot manufacture the independent positive semantic authority required to commit an autonomous mutation.

## Recovery ownership

Crash recovery is deliberately conservative. Automatic cleanup is valid only while the framework can re-establish ownership of the prior run, workspace, journal, fingerprint, target path, rollback directory, backup bytes, and transaction state. When newer human or out-of-band work makes ownership ambiguous, the correct outcome is manual review rather than an automated rollback that may destroy newer work.

## Related documentation

- [Architecture](ARCHITECTURE.md) — trust zones and authority ownership.
- [Runtime Result Contract](RESULT_CONTRACT.md) — terminal/validation/provider namespaces and closure rules.
- [Runtime Control](RUNTIME_CONTROL.md) — leases, transaction mechanics, rollback and recovery implementation.
- [Workspace Freshness Boundary](WORKSPACE_FRESHNESS_BOUNDARY.md) — subject fingerprint lineage and result freshness.
- [Pytest Execution Isolation](PYTEST_EXECUTION_ISOLATION.md) — infrastructure prerequisites for target-controlled Python.
- [Traceability](TRACEABILITY.md) — evidence lineage, journal integrity and attestations.
- [Security](SECURITY.md) — deterministic safety boundaries and residual deployment controls.
