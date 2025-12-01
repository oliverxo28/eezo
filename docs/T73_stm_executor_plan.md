# T73.0 — Block-STM Executor Integration Design

This document outlines the plan for integrating a Block-STM (Software Transactional Memory) executor into the EEZO node, using the backup reference files in `crates/node/src/stm_backup/` as inspiration. This is a **design-only** task; no Rust source code changes are made in T73.0.

---

## 1. Current Executor Architecture

### 1.1 File Layout

The current executor subsystem is located at:

```
crates/node/src/executor/
  mod.rs       # Module entry point
  types.rs     # Core trait and types: Executor, ExecInput, ExecOutcome
  single.rs    # SingleExecutor: serial execution fallback
  parallel.rs  # ParallelExecutor: Sealevel-style wave scheduling
```

### 1.2 Core Types (`types.rs`)

| Type | Purpose |
|------|---------|
| `ExecInput` | Input to executor: a batch of `SignedTx` plus the target block height |
| `ExecOutcome` | Output: `Result<Block, String>`, elapsed time, and tx count |
| `Executor` trait | Abstract interface requiring `execute_block(&self, node: &mut SingleNode, input: ExecInput) -> ExecOutcome` |

The `Executor` trait is `Send + Sync` to support parallel execution patterns.

### 1.3 SingleExecutor (`single.rs`)

- Delegates to `eezo_ledger::consensus_api::run_one_slot()`.
- Executes transactions sequentially.
- Used as a safe fallback when parallel execution is disabled.
- Records metrics: block/tx execution time, inferred TPS.
- Calls into T72.0 perf metric helpers: `observe_exec_block_prepare_seconds()`, `observe_exec_block_apply_seconds()`, etc.

### 1.4 ParallelExecutor (`parallel.rs`)

Implements a **Sealevel-style wave scheduler**:

1. **Prepare phase**: Precompute access lists and bucket assignments for all transactions in parallel (`rayon`).
2. **Wave building**: Greedily partition txs into conflict-free waves based on `AccessTarget` (accounts, buckets, supply).
3. **Wave compaction**: Merge adjacent waves when possible to reduce scheduling overhead.
4. **Small-wave fusion**: Fuse very small waves into predecessors if conflict-free.
5. **Hybrid balancing**: Split oversized waves for better CPU utilization.
6. **Parallel apply**: Execute each wave using `rayon::par_iter()` with bucket-scoped locking via `BlockBuildContext::apply_tx_parallel_bucketed()`.
7. **Finalize**: Call `ctx.finish()` to produce the final `Block`.

Key data structures:
- `PreparedTx<'a>`: Caches tx reference, precomputed access list, and bucket.
- Uses `SmallVec<[Access; 4]>` to avoid heap allocation for typical access lists.

### 1.5 Executor Wiring in `consensus_runner.rs`

The executor is selected at startup based on environment variables:

```rust
let exec_mode_parallel = std::env::var("EEZO_EXECUTOR_MODE")
    .map(|v| matches!(v.to_ascii_lowercase().as_str(), "parallel" | "p"))
    .unwrap_or(true);

let exec: Box<dyn Executor> = if exec_mode_parallel {
    Box::new(ParallelExecutor::new(exec_threads))
} else {
    Box::new(SingleExecutor::new())
};
```

The executor is invoked inside the slot loop:
```rust
let exec_input = ExecInput::new(txs, next_height);
let exec_outcome = exec.execute_block(&mut guard, exec_input);
```

---

## 2. Target STM Architecture

### 2.1 Reference Files in `stm_backup/`

The backup files serve as **design references only** and are not compiled:

```
crates/node/src/stm_backup/
  mvhashmap_backup.rs   # Multi-version hashmap for speculative state
  stm_backup.rs         # STM executor logic with sync mutex access
```

### 2.2 MVHashMap Role (`mvhashmap_backup.rs`)

The multi-version hashmap (`MVHashMap<K, V>`) provides:

1. **Versioned storage**: Each key maps to a `Versioned<V>` enum:
   - `Committed { ver, v }`: Finalized value at a specific commit version.
   - `Speculative { owner, attempt, v }`: Tentative write by a transaction being executed.

2. **Key operations**:
   - `read_committed(&self, k: &K) -> Option<V>`: Read last committed value.
   - `write_spec(&self, k: K, owner: u32, attempt: u16, v: V)`: Stage a speculative write.
   - `commit<I>(&self, writes: I, commit_ver: u64)`: Promote writes to committed.

3. **Concurrency**: Uses `DashMap` for lock-free concurrent access.

### 2.3 STM Executor Role (`stm_backup.rs`)

The STM executor in the backup provides:

1. **State context**: Uses `std::sync::Mutex` around `Accounts` and `Supply` for synchronized access.
2. **Serial apply baseline**: Currently applies transactions sequentially as a safe foundation.
3. **Sender derivation**: Derives sender from `pubkey` via `sender_from_pubkey_first20()`.
4. **Validation + apply**: Calls `validate_tx_stateful()` then `apply_tx()` for each tx.
5. **Skip-on-error semantics**: Invalid txs are skipped (logged) rather than aborting the block.
6. **Metrics**: Records apply time, skipped tx counts by reason.

### 2.4 Block-STM Design Goals

A full Block-STM executor for EEZO should:

1. **Accept ordered tx list**: Given a list of `SignedTx` for a block (from mempool or DAG candidate).

2. **Schedule into waves**: 
   - Unlike the current `ParallelExecutor` which uses static conflict detection, STM uses **optimistic concurrency**.
   - All transactions start executing in parallel against the MVHashMap.
   - Conflicts are detected dynamically at commit time.

3. **Conflict detection**:
   - A conflict occurs when tx `T_j` reads a key that tx `T_i` (where `i < j`) later writes.
   - The transaction with the **higher index** (later in the ordered list) loses and must retry.
   - Resolution is deterministic: tx order is sacred.

4. **Retry mechanism**:
   - Conflicting txs are re-executed in subsequent waves.
   - Continue until all txs have committed or have been deterministically aborted (e.g., persistent validation failures).

5. **Commit final state**:
   - Once all txs are finalized, the MVHashMap's committed state is merged into the ledger.
   - The result must be **semantically equivalent** to sequential execution of the same tx list.

### 2.5 Fitting into Existing Abstractions

The new STM executor would implement the `Executor` trait:

```rust
pub struct StmExecutor {
    threads: usize,
    // Configuration for wave limits, retry caps, etc.
}

impl Executor for StmExecutor {
    fn execute_block(
        &self,
        node: &mut SingleNode,
        input: ExecInput,
    ) -> ExecOutcome {
        // 1. Initialize MVHashMap from current node state
        // 2. Run STM scheduling loop
        // 3. Commit final state to node
        // 4. Build and return Block
    }
}
```

This allows seamless integration with the existing runtime selector in `consensus_runner.rs`.

### 2.6 Future DAG Integration (Acknowledgment)

The `backup/consensus-dag/` crate contains a DAG consensus implementation that could eventually provide tx ordering for the STM executor. Key files:
- `order.rs`: DAG ordering logic
- `executor_shim.rs`: Execution shim
- `types.rs`: DAG vertex and payload types

**This DAG integration is NOT part of T73.x.** It will be addressed in future tasks (e.g., T74.x). For now, the STM executor will accept tx ordering from the existing sources (mempool or the current DAG runner's shadow candidate).

---

## 3. Configuration & Feature Flags

### 3.1 Runtime Executor Mode Selection

Propose extending the existing `EEZO_EXECUTOR_MODE` environment variable:

| Value | Behavior |
|-------|----------|
| `single` / `s` | Use `SingleExecutor` (sequential) |
| `parallel` / `p` | Use `ParallelExecutor` (wave scheduling, current default) |
| `stm` / `block-stm` | Use `StmExecutor` (Block-STM, new) |

> **Note**: The `stm` alias is kept short for convenience. The longer `block-stm` alias is more explicit about the algorithm.

Implementation in `consensus_runner.rs`:

```rust
let exec_mode = std::env::var("EEZO_EXECUTOR_MODE")
    .unwrap_or_else(|_| "parallel".to_string())
    .to_ascii_lowercase();

let exec: Box<dyn Executor> = match exec_mode.as_str() {
    "single" | "s" => {
        log::info!("executor: mode=single");
        Box::new(SingleExecutor::new())
    }
    "stm" => {
        log::info!("executor: mode=stm threads={}", exec_threads);
        Box::new(StmExecutor::new(exec_threads))
    }
    _ => { // "parallel" | "p" | default
        log::info!("executor: mode=parallel threads={}", exec_threads);
        Box::new(ParallelExecutor::new(exec_threads))
    }
};
```

### 3.2 Cargo Feature Flag

Propose a new Cargo feature to gate STM-specific code:

```toml
# In crates/node/Cargo.toml
[features]
stm-exec = ["dashmap"]  # or any STM-specific deps
```

Benefits:
- Allows builds without STM on constrained environments.
- Keeps binary size smaller when STM is not needed.
- Enables gradual rollout.

Usage:
```rust
// In executor/mod.rs
#[cfg(feature = "stm-exec")]
mod stm;

#[cfg(feature = "stm-exec")]
pub use stm::StmExecutor;
```

### 3.3 Additional Configuration Knobs

| Env Var | Purpose | Default |
|---------|---------|---------|
| `EEZO_STM_MAX_RETRIES` | Max retry attempts per tx before abort | 5 |
| `EEZO_STM_WAVE_TIMEOUT_MS` | Timeout per wave (safety bound); should be high enough to avoid premature timeouts under load | 1000 |
| `EEZO_STM_PREFETCH_ENABLED` | Enable key prefetching from MVHashMap | true |

> **Note on wave timeout**: The 1000ms default provides a generous safety margin. This can be tuned lower (e.g., 100-500ms) after benchmarking typical wave execution times under load.

---

## 4. Safety & Correctness Invariants

### 4.1 Semantic Equivalence Invariant

> **Given the same ordered list of transactions for a block, STM must produce the same final ledger state as the current sequential executor (SingleExecutor).**

This is the primary correctness requirement. Verification:
- Unit tests comparing STM vs sequential execution on identical tx batches.
- Integration tests with deterministic tx generation.
- Shadow execution mode: run both executors and compare state hashes.

### 4.2 Transaction Order Preservation

> **STM must not reorder transactions beyond what DAG/consensus already decided.**

The input tx list order is sacred. If tx `T_i` appears before `T_j` in the input, and they conflict, `T_j` must see `T_i`'s effects (or retry after `T_i` commits).

### 4.3 Conflict Definition

A conflict occurs when:
1. Tx `T_j` reads key `K` from the MVHashMap.
2. Tx `T_i` (where `i < j`) subsequently writes to key `K`.
3. `T_j`'s read was speculative (not from `T_i`'s committed value).

Conflict granularity is at the **state key level**:
- Account balances: `Account(Address)`
- Account nonces: `Nonce(Address)`
- Supply: `Supply`
- Buckets: `Bucket(u16)`

### 4.4 Conflict Resolution Rules

| Situation | Resolution |
|-----------|------------|
| `T_i` writes, `T_j` read speculatively | `T_j` retries in next wave |
| `T_j` validates fail after `T_i` changed state | `T_j` retries |
| `T_j` fails validation consistently | `T_j` is deterministically aborted (skipped) |
| Max retries exceeded | `T_j` is deterministically aborted |

All conflict resolutions are **deterministic** based on tx index order.

### 4.5 Handling Non-Determinism

To ensure identical results across nodes:
1. **No randomness**: No random number generation in tx execution paths.
2. **Deterministic timestamps**: Block timestamp is fixed at block construction time.
3. **Deterministic ordering**: Conflict resolution always favors lower-index tx.
4. **Deterministic abort**: If a tx must be aborted, all nodes agree on which wave and which reason.

### 4.6 Failure Semantics

- **Validation failure** (e.g., bad nonce, insufficient funds): Tx is skipped, logged, not included in block.
- **Apply failure** (e.g., internal error): Tx is skipped, logged, not included in block.
- **Retry exhaustion**: Tx is skipped after max retries, logged with conflict info.
- **Wave timeout**: Hard limit; remaining txs in wave are rolled back and retried.

Skipped txs remain in mempool for potential inclusion in future blocks.

---

## 5. T73.x Implementation Roadmap

### T73.1 — Introduce MVHashMap + STM Modules (Scaffold)

**Scope**: Copy and adapt `mvhashmap_backup.rs` and `stm_backup.rs` into `crates/node/src/executor/`.

**Deliverables**:
- New files: `executor/mvhashmap.rs`, `executor/stm.rs`
- Gated behind `#[cfg(feature = "stm-exec")]`
- **Not wired into the build** or executor selection yet
- Basic compile check passes

**Acceptance**:
- `cargo check -p eezo-node --features "pq44-runtime,stm-exec"` succeeds
- No behavior changes; existing tests pass

---

### T73.2 — Unit Tests for STM Execution

**Scope**: Implement STM executor core logic with mock/in-memory state.

**Deliverables**:
- `StmExecutor::new()` and basic `execute_block()` implementation
- Unit tests comparing STM vs `SingleExecutor` on small tx sets
- Test cases:
  - No conflicts → same result as sequential
  - Simple conflict → correct retry and final state
  - Multiple conflicts → deterministic resolution
  - Validation failures → skipped correctly

**Acceptance**:
- All STM unit tests pass
- State comparison tests pass (STM == sequential for same input)

---

### T73.3 — Wire STM into Consensus Runner

**Scope**: Integrate `StmExecutor` into the runtime executor selection.

**Deliverables**:
- Update `consensus_runner.rs` to recognize `EEZO_EXECUTOR_MODE=stm`
- Log which mode is active at startup
- Default remains `parallel` (no behavior change unless opt-in)
- Integration test with STM mode enabled

**Acceptance**:
- Node starts successfully with `EEZO_EXECUTOR_MODE=stm`
- Basic tx flow works end-to-end
- Existing tests still pass with default mode

---

### T73.4 — STM-Specific Metrics

**Scope**: Add observability for STM execution.

**Deliverables**:
- Metrics:
  - `eezo_stm_waves_total`: Total waves executed
  - `eezo_stm_conflicts_total`: Total conflicts detected
  - `eezo_stm_retries_total`: Total tx retries
  - `eezo_stm_aborts_total`: Total tx aborts (already exists in backup)
  - `eezo_stm_wave_size_histogram`: Txs per wave distribution
  - `eezo_stm_apply_seconds`: Time in apply phase
  - `eezo_stm_commit_seconds`: Time in commit phase
- Perf harness script for STM vs parallel comparison

**Acceptance**:
- Metrics visible on `/metrics` endpoint
- Dashboard or Grafana panel showing STM perf

---

### T73.5 — Tuning and Optimization

**Scope**: Performance tuning based on metrics from T73.4.

**Deliverables**:
- Optimize MVHashMap (consider epoch-based GC, read-set caching)
- Tune retry and wave parameters
- Benchmark under realistic load (1k+ txs/block)

**Acceptance**:
- STM matches or exceeds parallel executor TPS under most workloads
- Conflict rate is within acceptable bounds (<10% for typical transfer loads)

> **Note on conflict threshold**: The 10% conflict rate is a starting target based on typical financial workloads where most transfers touch distinct accounts. This threshold should be validated against real EEZO transaction patterns during T73.4 benchmarking. Higher conflict rates may indicate suboptimal key-space partitioning or workloads that are inherently sequential.

---

### Future Work: T74.x — DAG Core Integration

**Note**: This is out of scope for T73.x but acknowledged here.

The `backup/consensus-dag/` crate provides:
- DAG vertex model and ordering
- Gossip and store layers
- Executor shim for DAG-driven execution

Future tasks (T74.x) will:
1. Integrate DAG ordering with STM executor
2. Use DAG's `order.rs` to provide deterministic tx ordering
3. Potentially enable higher parallelism through DAG's inherent concurrency

---

## Summary

This design document covers:
1. **Current architecture**: Executor trait, SingleExecutor, ParallelExecutor, and wiring.
2. **Target STM design**: MVHashMap, wave scheduling, conflict detection/resolution.
3. **Configuration**: `EEZO_EXEC_MODE=stm`, `stm-exec` Cargo feature, env knobs.
4. **Safety invariants**: Semantic equivalence, order preservation, determinism.
5. **Roadmap**: T73.1–T73.5 with clear acceptance criteria.

---

## Appendix: Reference File Locations

| File | Purpose |
|------|---------|
| `crates/node/src/executor/mod.rs` | Executor module entry |
| `crates/node/src/executor/types.rs` | `Executor` trait, `ExecInput`, `ExecOutcome` |
| `crates/node/src/executor/single.rs` | Sequential executor |
| `crates/node/src/executor/parallel.rs` | Wave-based parallel executor |
| `crates/node/src/stm_backup/mvhashmap_backup.rs` | **Reference**: Multi-version hashmap |
| `crates/node/src/stm_backup/stm_backup.rs` | **Reference**: STM executor baseline |
| `backup/consensus-dag/` | **Future reference**: DAG consensus (T74.x+) |
| `crates/node/src/consensus_runner.rs` | Executor wiring and slot loop |
| `crates/node/src/dag_runner.rs` | DAG runner (tx source, template gate) |
