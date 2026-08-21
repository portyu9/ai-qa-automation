# Runtime control and recovery

The model-facing QA state and the process-control state are deliberately separate.

## Workspace ownership

A live run acquires an OS advisory lock whose lock file lives under the trusted artifact root, not inside the target repository. Two agent processes cannot hold the same workspace lease at the same time. The OS releases the lock if the owning process exits.

Autonomous writes additionally require a Git-backed isolated worktree. The runtime captures a repository fingerprint that combines `HEAD`, porcelain status, and content hashes for dirty/untracked files. Before a mutation, the universal tool hook recomputes the fingerprint. A mismatch is treated as out-of-band/concurrent drift and blocks the write.

## Mutation transactions

Only one autonomous mutation can be pending at a time. Before the write, the runtime stores a bounded byte-for-byte rollback snapshot outside the SUT. The transaction remains pending until the current change revision has:

- deterministic patch-safety PASS;
- targeted pytest PASS; and
- full-regression pytest PASS.

A tool failure or a run that terminates without verified closure restores the snapshot. A newly created but unverified test is removed. Rollback failure is treated as an infrastructure failure because workspace integrity can no longer be guaranteed.

If a process crashes before its in-process rollback runs, the next process reads the previous lease metadata before replacing it. A pending prior mutation is automatically restored only when the current worktree fingerprint still exactly matches the fingerprint persisted by the crashed run. Any post-crash operator/out-of-band edit blocks automatic recovery, preserving the newer work for manual review.

## Execution budgets and circuits

The Agent SDK already bounds turns, model cost, and global duration. Runtime hooks add non-model circuit breakers:

- total tool calls;
- network-capable tool calls;
- autonomous mutation attempts;
- repeated identical actions; and
- per-tool consecutive failures.

After repeated failures, a tool circuit opens and further calls to that tool are denied. A successful call resets that tool's circuit. This lets the agent use alternative evidence paths without endlessly retrying one broken integration.

## Bootstrap intelligence

Before model execution, deterministic code records:

- repository `HEAD` and worktree fingerprint;
- changed-file impact/risk domains;
- detected languages;
- test-framework surfaces;
- API/database/container/IaC/mobile surfaces;
- CI-system surfaces; and
- dependency-manifest paths, sizes, and content hashes.

The bounded summary inserted into the objective is explicitly labeled observed data, not instructions.

## Journal and recovery

Every run has an append-only `journal.jsonl` with sequence numbers, previous-record hashes, and record hashes. `runtime.json` records the operational checkpoint: lease ID, workspace fingerprint, budget snapshot, tool circuits, pending mutation metadata, and journal head.

`ai-qa recover <run-dir>` verifies persisted state and the journal chain, reports whether the last change revision was closed, detects any pending mutation transaction, and indicates whether it is safe to start a new agent session from the persisted evidence. It does **not** claim to replay or continue the prior model conversation.
