# EEZO TPS Next-Stage Proposals

> **Analysis Date:** December 2024  
> **Based on:** T82.x (STM executor with BlockOverlay), T83.0 (Sigpool), mempool actor live  
> **Target:** Single laptop dag-primary devnet (~150–250 TPS baseline)

---

## Section 1 — Current Bottleneck Assessment

After deep code analysis of the current implementation, including the STM executor (`crates/node/src/executor/stm.rs`), sigpool (`crates/node/src/sigpool.rs`), mempool actor (`crates/node/src/mempool_actor.rs`), DAG ordering engine (`crates/consensus-dag/src/order.rs`), and persistence layer (`crates/ledger/src/persistence.rs`), I can provide a concrete assessment of current TPS limiting factors.

### 1.1 Current State Summary

The codebase shows significant optimization work has already been done:

| Subsystem | Status | Key Implementation |
|-----------|--------|-------------------|
| **STM Executor** | ✅ Optimized | `AnalyzedTx`, `BlockOverlay`, `WaveFingerprint` with bloom filter pre-screening |
| **Sigpool** | ✅ Implemented | Micro-batching (default 64), timeout-based flush, LRU replay cache (8K entries) |
| **Mempool** | ✅ Actor-based | 256 virtual buckets, in-flight tracking, prefetch support |
| **DAG Ordering** | ✅ Minimal | Single-threaded but trivial for single-node (threshold=1) |
| **Persistence** | ⚠️ Synchronous | RocksDB with WriteBatch, LZ4 compression, but blocking writes |

### 1.2 What Is NOT the Bottleneck (Given Current Metrics)

Based on the problem statement indicating:
- STM conflicts ≈ 0 for simple transfer spam
- Sigpool micro-batching working with sub-ms latency
- Mempool actor batches served correctly

The following are **not** currently the primary bottleneck:

1. **Conflict Detection** — The `WaveFingerprint` + bloom filter pre-screening (`stm.rs:225-302`) is working efficiently. With zero conflicts for single-sender spam, the two-phase conflict detection is effectively O(1) per tx.

2. **Signature Verification Throughput** — The sigpool's micro-batch pipeline (`sigpool.rs:331-360`) with rayon parallelization is handling verification well. The `SigVerifyCache` (`sigpool.rs:251-306`) reduces repeated verification work.

3. **Mempool Lock Contention** — The actor-based design (`mempool_actor.rs:231-633`) eliminates shared mutex contention entirely. The single-owner task with channel-based communication is wait-free for callers.

### 1.3 Likely Current Bottlenecks (In Priority Order)

Given the above, the limiting factors are now likely:

#### **Bottleneck #1: Per-Wave State Snapshot Clone**

**Location:** `crates/node/src/executor/stm.rs:1016-1017`

```rust
// T73.6: Execute transactions in parallel using rayon
let snapshot_accounts = accounts.clone();
let snapshot_supply = supply.clone();
```

**Analysis:** Even with `BlockOverlay`, the legacy `execute_stm()` path (lines 946-1111) still clones full state per wave. The overlay-based path (`execute_stm_with_overlay()`, lines 1134-1332) is better but still requires a `base_accounts.clone()` at line 1182:

```rust
let base_accounts = accounts.clone();
```

For a single-sender spam workload with ~150-250 TPS:
- At ~100-500 txs per block
- With ~1-2 waves per block (conflicts ≈ 0)
- Each wave requires reading from base + overlay

The clone overhead scales with account set size. As the test progresses and touches more accounts, this becomes more expensive.

**Evidence:** The problem statement notes ~140-250 TPS "depending on config" — this variance likely correlates with account working set size.

#### **Bottleneck #2: Synchronous RocksDB Persistence**

**Location:** `crates/ledger/src/persistence.rs:441-481`

```rust
// put_block() - synchronous batch write
let mut wb = WriteBatch::default();
wb.put_cf(cf_hdrs, k_height(height), &hdr_bytes);
wb.put_cf(cf_blks, k_height(height), &blk_bytes);
// ... tx index entries
self.db.write(wb)?;  // <-- Blocking!
```

**Analysis:** The persistence path is fully synchronous. Every `put_block()`, `put_state_snapshot()`, and `put_header()` blocks the caller until RocksDB completes the write. This creates a serial bottleneck in the block commit path:

1. Execute block (parallel) → ~X ms
2. Commit to DB (serial) → ~Y ms per block
3. Block interval = X + Y

For NVMe SSDs, Y is typically 1-5ms. For 5 blocks/second target, this leaves only ~200ms budget with ~25-100ms consumed by persistence alone (~12-50% of budget).

#### **Bottleneck #3: Single-Threaded DAG Ordering + Block Building**

**Location:** `crates/consensus-dag/src/order.rs:42-75`

```rust
pub fn try_order_round(&self, store: &DagStore, round: Round) -> Option<OrderedBundle> {
    let ready_nodes = store.get_ready_round(round);
    // ... single-threaded processing
}
```

**Analysis:** For single-node devnet, the DAG ordering is trivial (threshold=1 means immediate ordering). However, the block building path that consumes ordered DAG bundles and produces executable blocks is sequential. The proposer loop (in dag_runner or consensus_runner) processes one block at a time.

With pipelined execution, we could be:
- Executing block N
- Persisting block N-1  
- Ordering block N+1

Currently, these steps are largely serial.

#### **Bottleneck #4: Transaction Decode/Parse Cost**

**Location:** Various (HTTP handlers, mempool, executor)

While not directly visible in metrics, each transaction is decoded multiple times:
1. At HTTP ingress (JSON → SignedTx)
2. In sigpool (for verification)
3. In `analyze_batch()` at executor entry
4. During `validate_tx_stateful()` calls

The `AnalyzedTx` optimization helps but doesn't eliminate all redundancy.

#### **Bottleneck #5: Allocations and Copies in Hot Path**

**Evidence from code:**
- `Vec::new()` allocations in wave building loops
- `HashMap::new()` for conflict tracking per wave
- `clone()` calls on tx data in various paths

The STM executor creates new `Vec`, `HashSet`, `HashMap` structures per wave. With micro-allocator overhead, this adds up.

---

## Section 2 — Proposed Tasks (T83.x / T84.x)

### T83.1 — Multi-Sender Benchmark & Conflict Profiling

**Goal:** Establish realistic conflict behavior baseline and tune STM for multi-sender workloads.

**Rationale:** The current "single-sender transfer spam" workload produces 0 conflicts by design. Real-world traffic will have multi-sender patterns hitting overlapping accounts. We need:
1. A benchmark that generates controllable conflict rates (0%, 5%, 20%, etc.)
2. Metrics to understand STM behavior under conflict pressure
3. Tuning of `EEZO_EXEC_LANES`, `EEZO_EXEC_WAVE_CAP`, and `EEZO_STM_MAX_RETRIES` for these workloads

**Subsystems:** Executor (stm.rs), benchmark scripts, metrics

**Scope:**
- Add `scripts/spam_multi.sh` (already exists, enhance it) with configurable sender count
- Add `--conflict-ratio` parameter to control overlap
- Add per-wave size distribution histogram analysis
- Document optimal config for different conflict profiles

**Difficulty:** S (small) — primarily scripting and config tuning

**Risk:** Low — measurement-only, no behavioral changes

**Expected TPS Impact:** Enables informed tuning that could yield +10-20% on multi-sender workloads

---

### T83.2 — Async Persistence Pipeline

**Goal:** Decouple persistence from the block commit critical path using async writes.

**Rationale:** The synchronous `put_block()` path blocks the proposer loop during RocksDB writes. By pipelining persistence asynchronously, we can execute block N+1 while persisting block N. This removes persistence latency from the TPS calculation.

**Subsystems:** Persistence (persistence.rs), consensus runner

**Scope:**
- Wrap `put_block()` / `put_state_snapshot()` with `tokio::task::spawn_blocking`
- Add a `PersistenceQueue` actor that batches writes
- Ensure durability guarantees via WAL (RocksDB already has this)
- Add `eezo_persist_queue_len` gauge for observability
- Configurable `EEZO_PERSIST_BATCH_INTERVAL_MS` (default: 0 = immediate)

**Architecture:**
```
[Executor] → Block N result → [Commit to memory state]
                            ↘
                              [PersistenceQueue] → (async) RocksDB write
                            ↗
[Executor] → Block N+1 (proceeds immediately)
```

**Difficulty:** M (medium) — requires careful handling of ordering guarantees

**Risk:** Medium — must ensure no data loss on crash, handle backpressure

**Expected TPS Impact:** +1.2-1.4× (estimate based on removing 10-30% persistence overhead)

---

### T83.3 — Block Execution Pipelining

**Goal:** Overlap block building, execution, and persistence stages.

**Rationale:** Currently the proposer loop runs: `get_batch → execute_block → commit → persist` sequentially. With pipelining:
- Stage 1 (N): Persist block N-2
- Stage 2 (N): Commit block N-1 to state
- Stage 3 (N): Execute block N
- Stage 4 (N): Build block N+1 (prefetch mempool)

**Subsystems:** dag_runner, consensus_runner, mempool_actor, executor

**Scope:**
- Refactor proposer loop into a 3-stage pipeline
- Add `EEZO_PIPELINE_DEPTH` config (default: 2)
- Use mempool actor's existing `prefetch()` for ahead-of-time batch building
- Track per-stage latency in metrics: `eezo_exec_stage_latency_seconds{stage="build|execute|commit|persist"}`

**Difficulty:** M-L (medium-large) — significant refactor of consensus runner

**Risk:** Medium — must maintain determinism, handle pipeline stalls correctly

**Expected TPS Impact:** +1.3-1.5× (estimate based on 3-stage parallelism with ~33% overlap)

---

### T83.4 — Zero-Copy Tx Propagation with Arc<Bytes>

**Goal:** Eliminate redundant tx deserialization and copying in the hot path.

**Rationale:** Transactions are currently copied at multiple points:
- HTTP handler decodes JSON to `SignedTx`
- Mempool stores `Arc<Vec<u8>>` (raw bytes)
- Executor re-accesses tx fields repeatedly

By using `Arc<SignedTx>` consistently and caching decoded forms, we eliminate redundant work.

**Subsystems:** mempool_actor, executor, tx types

**Scope:**
- Change `TxEntry.bytes` from `Arc<Vec<u8>>` to `Arc<SignedTx>` (already decoded)
- Add `Arc<AnalyzedTx>` caching in mempool (compute once at admission)
- Modify `analyze_batch()` to use cached `AnalyzedTx` when available
- Add `eezo_tx_parse_cached_total` / `eezo_tx_parse_fresh_total` counters

**Difficulty:** S-M (small-medium) — type changes but localized

**Risk:** Low — purely implementation optimization, same semantics

**Expected TPS Impact:** +1.1-1.2× (estimate based on eliminating ~10% CPU on decode)

---

### T84.0 — Lazy/Incremental State Root Computation

**Goal:** Avoid full state root computation on every block; compute incrementally.

**Rationale:** If state roots are computed after each block, this is O(accounts) work. With incremental/lazy computation:
- Track dirty accounts in a set
- Compute Merkle updates only for dirty accounts
- Full recomputation only on checkpoint boundaries

**Subsystems:** Accounts (accounts.rs), persistence, state root computation

**Scope:**
- Add `DirtySet` tracking to `Accounts` or `BlockOverlay`
- Implement incremental Merkle tree updates (path update only)
- Add `eezo_state_root_incremental_updates` counter
- Configure checkpoint interval for full recomputation (`EEZO_STATE_ROOT_CHECKPOINT_INTERVAL`)

**Difficulty:** L (large) — requires Merkle tree refactor

**Risk:** Medium-High — must ensure correctness of incremental updates

**Expected TPS Impact:** +1.2-1.4× for large account sets (less impact for small sets)

---

## Section 3 — Suggested Ordering & Warnings

### 3.1 Recommended Implementation Order

| Order | Task | Why First |
|-------|------|-----------|
| 1 | **T83.1** | No code changes, establishes realistic baseline |
| 2 | **T83.4** | Low risk, quick win, foundational for later work |
| 3 | **T83.2** | High impact, isolated to persistence layer |
| 4 | **T83.3** | Highest complexity, depends on T83.2 being stable |
| 5 | **T84.0** | Only if state root is measured as bottleneck |

### 3.2 Critical Invariants to Preserve

#### **In-Flight Mempool Tracking**

The mempool actor's in-flight tracking (`mempool_actor.rs:469-487`) is critical for preventing "zombie tx" reappearance. Any pipelining work must ensure:

```
INVARIANT: A tx hash must NOT appear in two concurrent block proposals
```

The `move_to_in_flight()` → `on_block_commit()` flow handles this. Pipelining must not break this.

#### **Deterministic Execution**

The STM executor's conflict detection is deterministic: lower index wins. This is essential for all validators producing identical state. Any parallelization must preserve:

```
INVARIANT: Given same (accounts, supply, txs), execution produces identical (accounts', supply', block)
```

#### **Persistence Durability**

If T83.2 (async persistence) is implemented, must ensure:

```
INVARIANT: After successful block commit message, block WILL be persisted (eventually)
```

RocksDB's WAL provides this, but the application must not bypass it.

#### **Head Mutability Trap**

The problem statement mentioned "mutable head" traps. Be careful with:
- `node.accounts` vs. snapshot copies
- `node.supply` updates during parallel execution
- Any shared mutable state accessed from parallel threads

The current `BlockOverlay` design correctly handles this, but modifications must maintain the pattern.

### 3.3 Config Recommendations for Immediate TPS Gains

Based on code analysis, try these configs today (no code changes):

```bash
# Increase execution parallelism
export EEZO_EXEC_LANES=32  # from default 16

# Larger sigpool batches for fewer context switches
export EEZO_SIGPOOL_BATCH_SIZE=128  # from default 64

# More mempool capacity
export EEZO_MEMPOOL_MAX_LEN=50000  # from default 10000
export EEZO_MEMPOOL_MAX_BYTES=128MB  # from default 64MB

# Larger sigpool cache for repeated keys
export EEZO_SIGPOOL_CACHE_SIZE=32768  # from default 8192
```

### 3.4 Metrics to Monitor During Optimization

| Metric | What It Tells You |
|--------|-------------------|
| `eezo_exec_stm_waves_per_block` | If >1.5, conflict handling is becoming significant |
| `eezo_exec_stm_wave_size` | If avg << WAVE_CAP, batch building is suboptimal |
| `eezo_sigpool_batch_latency_seconds` | If >1ms, sig verification is becoming bottleneck |
| `eezo_mempool_batches_served_total` | If growing faster than blocks, prefetch is working |
| `PERSIST_WRITE_DUR_MS` | If >50ms, persistence is the bottleneck |

---

## Appendix: Code References

| Component | Path | Key Lines |
|-----------|------|-----------|
| STM Executor | `crates/node/src/executor/stm.rs` | 946-1111 (legacy), 1134-1332 (overlay) |
| BlockOverlay | `crates/node/src/executor/stm.rs` | 369-435 |
| WaveFingerprint | `crates/node/src/executor/stm.rs` | 196-302 |
| Sigpool | `crates/node/src/sigpool.rs` | 425-648 |
| Mempool Actor | `crates/node/src/mempool_actor.rs` | 254-633 |
| DAG Ordering | `crates/consensus-dag/src/order.rs` | 42-75 |
| Persistence | `crates/ledger/src/persistence.rs` | 441-481 |
| TPS Benchmark | `scripts/tps_benchmark.sh` | Full file |

---

*End of TPS Next-Stage Proposals*
