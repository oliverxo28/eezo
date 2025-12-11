# EEZO TPS Architect's Report

> **Analysis Date:** December 2024  
> **Status:** Pure DAG mode (T81.x complete, HotStuff fully removed)  
> **Current Baseline:** ~150–180 tx/s dev-unsafe on single laptop

---

## Executive Summary

This report provides a comprehensive TPS bottleneck analysis for the EEZO blockchain in its current pure DAG consensus mode. Based on deep code analysis of the `eezo-node`, `eezo-ledger`, `consensus-dag`, `eezo-crypto`, and `eezo-prover` crates, we identify the most likely limiting factors and propose a phased roadmap to maximize throughput.

**Key Findings:**

1. **Primary Bottleneck:** STM executor conflict handling and state snapshot cloning
2. **Secondary Bottleneck:** ML-DSA-44 signature verification (PQ crypto is CPU-expensive)
3. **Tertiary Bottleneck:** Mempool lock contention under heavy spam
4. **GPU Opportunity:** Existing GPU hashing infrastructure is functional but underutilized
5. **Scaling Potential:** 5–20× TPS gains are achievable with targeted optimizations

---

## 1. Current TPS & Bottlenecks

### 1.1 Bottleneck Stack (Most → Least Limiting)

| Rank | Subsystem | Component | Impact | Evidence |
|------|-----------|-----------|--------|----------|
| **1** | STM Executor | State snapshot cloning | **High** | `execute_stm()` clones entire `Accounts` + `Supply` per wave |
| **2** | STM Executor | Conflict detection | **High** | O(n²) worst-case in `detect_conflicts_in_wave()` |
| **3** | Crypto | ML-DSA-44 verification | **Medium-High** | PQ signatures ~50-100× slower than ECDSA |
| **4** | Mempool | Tokio Mutex contention | **Medium** | `SharedMempool` uses `tokio::sync::Mutex` |
| **5** | DAG Consensus | Single-threaded ordering | **Low-Medium** | `OrderingEngine::try_order_round()` is sequential |
| **6** | Persistence | Synchronous RocksDB writes | **Low** | `put_block()` is synchronous |
| **7** | Network | Serialization overhead | **Low** | Even single-node has encoding costs |

### 1.2 STM Executor Analysis

**Location:** `crates/node/src/executor/stm.rs`

**Current Implementation:**
```rust
// Full state clone per wave
let snapshot_accounts = accounts.clone();
let snapshot_supply = supply.clone();
```

**Issues Identified:**

1. **State Cloning Overhead:**
   - Every wave clones the entire `Accounts` HashMap
   - With 1000+ accounts, this becomes significant
   - O(n) clone per wave, multiple waves per block

2. **Conflict Detection:**
   - `detect_conflicts_in_wave()` iterates pending transactions in O(n)
   - Builds `committed_writes` HashMap with O(n) insertions
   - Worst case: all transactions conflict → max retries

3. **Configuration Gaps:**
   - `exec_lanes` defaults to 16 (configurable via `EEZO_EXEC_LANES`)
   - `wave_cap` defaults to 0 (unlimited)
   - `max_retries` defaults to 5

**Metrics Available:**
- `stm_block_waves_inc()` - waves per block
- `stm_block_conflicts_inc()` - conflicts per block
- `stm_block_retries_inc()` - retries per block

### 1.3 Parallel Executor Analysis

**Location:** `crates/node/src/executor/parallel.rs`

**Current Implementation (PreparedTx optimization):**
```rust
// Parallel tx preparation
let prepared: Vec<PreparedTx> = input.txs
    .par_iter()  // PARALLEL iteration
    .map(|tx| PreparedTx::from_tx(tx))
    .collect();
```

**Strengths:**
- Uses rayon `par_iter()` for parallel preparation
- Caches access lists via `PreparedTx` to avoid redundant calls
- Wave compaction and fusion reduce wave count

**Bottlenecks:**
- Wave building is sequential (`build_waves_greedy`)
- Bucket-based locking in `apply_tx_parallel_bucketed()`

### 1.4 Signature Verification Analysis

**Location:** `crates/crypto/src/sig/ml_dsa.rs`

**Current Implementation:**
```rust
// ML-DSA-44 verify - PQ signature verification
fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
    verify_detached_signature(&sig, msg, &pk).is_ok()
}
```

**Performance Characteristics:**
- ML-DSA-44 signature: 2420 bytes (vs 64 bytes for ECDSA)
- Public key: 1312 bytes (vs 33 bytes for ECDSA)
- Verification: ~50-100× slower than ECDSA

**Current State:**
- `sigpool.rs` exists but signature verification is stubbed (`ok = true`)
- No batch verification parallelization
- Each tx verified individually

### 1.5 Mempool Analysis

**Location:** `crates/node/src/mempool.rs`

**Current Implementation:**
```rust
pub struct SharedMempool {
    inner: Arc<Mutex<Mempool>>,  // Tokio async Mutex
    tx_bytes_cache: Arc<parking_lot::RwLock<HashMap<...>>>,
}
```

**Bottlenecks:**
- Single `Mutex<Mempool>` for all operations
- `pop_batch()` locks entire mempool
- Rate limiting (`RateBucket`) per-IP, O(1) but adds overhead

**Capacity Limits:**
- `max_len`: configurable queue length
- `max_bytes`: configurable byte cap
- Token bucket: `bucket_capacity` tokens, refill per second

### 1.6 DAG Consensus Analysis

**Location:** `crates/consensus-dag/src/`

**Current Implementation:**
- Single-threaded `OrderingEngine`
- `DagStore` uses simple HashMap for vertices
- `DagConsensusHandle` provides async interface

**Ordering Rule:**
```rust
// order.rs
pub fn try_order_round(&self, store: &DagStore, round: Round) -> Option<OrderedBundle> {
    let ready_nodes = store.get_ready_round(round);
    // Count distinct authors
    let distinct_authors: HashSet<_> = ready_nodes.iter().map(|n| n.author).collect();
    if distinct_authors.len() < self.threshold { return None; }
    // ...
}
```

**Single-Node Optimization:**
- `EEZO_DAG_ORDERING_THRESHOLD` defaults to 1 for single-node
- Minimal consensus overhead in dev mode

### 1.7 Persistence Analysis

**Location:** `crates/ledger/src/persistence.rs`

**Current Implementation:**
- RocksDB with column families (blocks, headers, tx_index, metadata, snapshots)
- LZ4 compression enabled by default
- Synchronous writes via `WriteBatch`

**Write Patterns:**
```rust
// put_block() - synchronous batch write
let mut wb = WriteBatch::default();
wb.put_cf(cf_hdrs, k_height(height), &hdr_bytes);
wb.put_cf(cf_blks, k_height(height), &blk_bytes);
// ... tx index entries
self.db.write(wb)?;  // <-- Blocking!
```

**Metrics:**
- `PERSIST_WRITE_DUR_MS` - write latency
- `PERSIST_READ_DUR_MS` - read latency

### 1.8 GPU Hashing Analysis

**Location:** `crates/eezo-prover/src/gpu_hash.rs`, `crates/node/src/gpu_hash.rs`

**Current State:**
- wgpu-based GPU backend with BLAKE3 compute shader
- Shader is a stub (zeroes output) - CPU path used for correctness
- `EEZO_GPU_HASH_REAL=1` enables GPU init
- `EEZO_NODE_GPU_HASH={off|shadow|prefer}` controls node behavior

**GPU Backend:**
```rust
impl Blake3GpuBackend for GpuBlake3Context {
    fn hash_batch(&self, batch: &mut Blake3GpuBatch<'_>) -> Result<(), GpuError> {
        cpu_hash_batch(batch)?;  // CPU is source of truth
        // GPU path exercises buffer layout but returns CPU result
        // ...
    }
}
```

**Limitations:**
- Only single-chunk messages (≤64 bytes) exercise GPU path
- GPU output not actually used yet
- Designed for block body hashing, not per-tx

---

## 2. TPS Roadmap — Single Laptop (Phases A–E)

### Current Baseline: ~150–180 tx/s

### Phase A: Measurement & Easy Wins

**Goal:** Establish accurate baseline, enable profiling, tune obvious params

**Changes:**

1. **Enhanced Metrics (config only)**
   - Enable all existing histograms in Prometheus
   - Add `EEZO_TRACE_EXEC=1` for per-block timing breakdown
   - Profile with `perf record` / `flamegraph`

2. **Config Tuning (no code)**
   - Increase `EEZO_EXEC_LANES=32` (from default 16)
   - Set `EEZO_EXEC_WAVE_CAP=500` to limit wave size
   - Tune mempool: `max_len=50000`, `max_bytes=100MB`

3. **Quick Fixes (small code)**
   - Use `parking_lot::Mutex` instead of `tokio::sync::Mutex` for mempool
   - Pre-allocate `VecDeque` in mempool to avoid reallocs

**Estimated Impact:** 1.2–1.5× (180–270 tx/s)

**Risks:** Low - configuration changes only

**Success Criteria:**
- Flamegraph shows STM executor as top consumer
- Metrics show <2 waves per block average
- No increase in conflict rate

### Phase B: STM Executor Tuning

**Goal:** Reduce state cloning and conflict overhead

**Changes:**

1. **Copy-on-Write State (medium refactor)**
   ```rust
   // Replace full clone with Arc-based CoW
   pub struct CowAccounts {
       inner: Arc<HashMap<Address, Account>>,
       overlay: HashMap<Address, Account>,
   }
   ```

2. **Bloom Filter for Conflicts (small code)**
   - Add Bloom filter for write-set membership
   - Reduces false conflict checks

3. **Sender-based Partitioning (medium refactor)**
   - Group txs by sender before wave building
   - Avoid cross-sender conflicts within wave

4. **Tune Wave Behavior**
   - Increase `EEZO_STM_MAX_RETRIES=10` for burst traffic
   - Add adaptive wave sizing based on conflict rate

**Estimated Impact:** 2–3× (360–540 tx/s)

**Risks:** Medium - correctness must be verified via equivalence tests

**Success Criteria:**
- Average waves per block ≤1.5
- Conflict rate <5% of txs
- Existing equivalence tests pass

### Phase C: Mempool / Admission / Batching

**Goal:** Reduce mempool lock contention and improve batch quality

**Changes:**

1. **Sharded Mempool (medium refactor)**
   ```rust
   pub struct ShardedMempool {
       shards: Vec<Mutex<Mempool>>,  // 16 shards
   }
   ```

2. **Batch Pre-sorting (small code)**
   - Sort batch by sender before execution
   - Groups same-sender txs for sequential nonces

3. **Priority Queue (medium refactor)**
   - Replace `VecDeque` with fee-weighted priority queue
   - Higher-fee txs processed first

4. **Async Drain (small code)**
   - Use `try_lock()` for non-blocking batch pop
   - Fallback to async wait if needed

**Estimated Impact:** 1.3–1.5× (470–810 tx/s)

**Risks:** Low-Medium - no consensus changes

**Success Criteria:**
- Mempool lock wait time <1ms p99
- No tx starvation (FIFO preserved per shard)
- Batch quality metrics show <10% nonce failures

### Phase D: Crypto / PQ Path Optimizations

**Goal:** Parallelize signature verification

**Changes:**

1. **Enable SigPool Verification (small code)**
   ```rust
   // sigpool.rs - change from stub to real
   let ok = verify_mldsa44(&tx.pubkey, &msg, &tx.sig);
   ```

2. **Parallel Batch Verification (medium refactor)**
   - Use rayon `par_iter()` for signature verification
   - Process N signatures concurrently

3. **Signature Caching (medium refactor)**
   - Cache verified (pubkey, sig_hash) → bool
   - LRU cache with ~100k entries

4. **Pre-verification in HTTP Handler (small code)**
   - Verify signature before mempool admission
   - Reject invalid early, reduce wasted work

**Estimated Impact:** 1.5–2× (700–1600 tx/s)

**Risks:** Medium - signature verification is security-critical

**Success Criteria:**
- Signature verification <20% of total block time
- No valid signatures rejected (false negatives)
- Cache hit rate >50% for repeated pubkeys

### Phase E: Persistence / IO Tuning

**Goal:** Reduce blocking IO in commit path

**Changes:**

1. **Async RocksDB Writes (medium refactor)**
   - Use `tokio::task::spawn_blocking` for DB writes
   - Pipeline: execute block N while persisting block N-1

2. **Write-Ahead Batching (small code)**
   - Batch multiple blocks before flush
   - Configurable batch interval (e.g., 100ms)

3. **Separate Commit Thread (medium refactor)**
   - Dedicated thread for persistence
   - Channel-based handoff from executor

4. **SSD Optimization (config)**
   - Increase RocksDB write buffer size
   - Tune compaction for SSD workloads

**Estimated Impact:** 1.2–1.5× (840–2400 tx/s)

**Risks:** Low-Medium - must ensure durability guarantees

**Success Criteria:**
- Block commit latency <50ms p99
- No data loss on crash (WAL integrity)
- Persistence not on critical path for TPS

---

## 3. GPU TPS Plan — Single Node with GPU

### 3.1 Current GPU Integration

**Existing Infrastructure:**
- `eezo-prover/src/gpu_hash.rs`: wgpu-based BLAKE3 context
- `node/src/gpu_hash.rs`: Node-side adapter with CPU fallback
- Compute pipeline with proper buffer layout (T46.2a)
- Metrics: attempts, fallbacks, compare, mismatch

**Current Limitations:**
- GPU shader body is a stub (zeroes output)
- Only single-chunk messages (≤64 bytes) use GPU path
- CPU always used for correctness

### 3.2 Easy GPU Wins (T83.x)

**Hashing Offload:**

| Task | Effort | TPS Impact |
|------|--------|------------|
| Complete BLAKE3 WGSL shader | 2-3 weeks | 1.5–2× |
| Block body hashing to GPU | 1 week | Minimal direct, but unblocks CPU |
| Merkle tree computation | 2-3 weeks | 1.3–1.5× |

**Implementation Path:**
1. Implement real BLAKE3 single-chunk in WGSL
2. Enable GPU path with CPU cross-check (`EEZO_GPU_HASH_CHECK=1`)
3. Once stable, use GPU result without cross-check

**Estimated Impact:** If hashing becomes not-the-bottleneck, 1.5–2× improvement, but executor/DB then limits.

### 3.3 Medium-Hard GPU Work

**State Root Computation:**
- Currently computed on CPU in persistence layer
- Could batch account hash computations on GPU
- Requires careful API design

**Signature Verification Assist:**
- ML-DSA-44 not GPU-friendly (complex lattice operations)
- Potential for batch parallelization on GPU
- Research-level: no existing GPU ML-DSA implementations

### 3.4 Long-term / Speculative

**Proof Generation:**
- ZK proofs naturally GPU-accelerated
- Would require ZK integration (out of current scope)

**Full Executor on GPU:**
- Execute simple transfers on GPU
- Complex: state management across host/device
- 6-12 month research project

### 3.5 GPU TPS Summary

| Category | Items | Effort | TPS Multiplier |
|----------|-------|--------|----------------|
| **Easy** | BLAKE3 shader, block hashing | 3-4 weeks | 1.5–2× |
| **Medium** | Merkle trees, state roots | 6-8 weeks | 1.3–1.5× |
| **Hard** | Signature assist | 3-6 months | 1.2–1.5× |
| **Speculative** | Full executor | 6-12 months | Unknown |

---

## 4. Rented Hardware & Multi-node TPS Projections

### 4.1 Single Strong Server (CPU + GPU)

**Hardware Assumption:**
- 32-64 core CPU (AMD EPYC / Intel Xeon)
- 128GB+ RAM
- NVMe SSD
- NVIDIA datacenter GPU (A100 / H100)

**TPS Projections:**

| Configuration | TPS Range | Notes |
|---------------|-----------|-------|
| CPU only, optimized (Phases A-E) | 2,000–5,000 | Assumes all Phase A-E complete |
| CPU + GPU hashing | 3,000–8,000 | GPU unblocks CPU for execution |
| CPU + GPU + async persistence | 5,000–15,000 | Fully pipelined |

**Key Scaling Factors:**
- More cores → more parallel signature verification
- More RAM → larger mempool, more account cache
- NVMe → faster persistence, less blocking
- GPU → offload hashing, Merkle computation

### 4.2 Multi-node Cluster

**Architecture:**
- N validator nodes running DAG consensus
- Proper network (10Gbps+ between nodes)
- Each node: 16-32 cores, 64GB RAM

**TPS Projections:**

| Nodes | TPS Range | Notes |
|-------|-----------|-------|
| 1 (current) | 150–180 | Baseline |
| 1 (optimized) | 2,000–5,000 | Phases A-E |
| 4 nodes | 5,000–20,000 | DAG parallelism |
| 16 nodes | 15,000–50,000 | Network may limit |
| 64+ nodes | 30,000–100,000+ | Theoretical (see assumptions below) |

**Assumptions for High-End Multi-node TPS:**
- **Network:** Dedicated 25Gbps+ interconnect, sub-1ms latency between nodes
- **Executor:** State sharding implemented (each node only executes 1/N of state)
- **Consensus:** Optimized gossip with erasure coding, no O(N²) broadcast
- **Hardware:** Datacenter-grade servers with NVMe storage per node
- **Load:** Transaction load is uniformly distributed across shards

Without these optimizations, 64-node clusters are more likely to achieve 30,000–50,000 tx/s
due to network and replication overhead.

**Scaling Considerations:**

1. **DAG Parallelism:**
   - Each validator produces vertices independently
   - Ordering happens after data availability
   - More validators → more parallel proposal

2. **Network Bottleneck:**
   - Vertex propagation: O(N) broadcast per validator
   - With N validators: O(N²) total messages per round
   - Mitigation: gossip protocol, topology optimization

3. **Executor Scaling:**
   - Each node executes same tx set (for verification)
   - Execution is embarrassingly parallel if state is partitioned
   - Sharding (future) could break this dependency

4. **Storage Scaling:**
   - Each node stores full state (currently)
   - State sync enables fast catch-up
   - Archival nodes could offload historical data

### 4.3 Tradeoffs

| Factor | Single Node | Multi-node |
|--------|-------------|------------|
| Complexity | Low | High (networking, consensus) |
| Fault tolerance | None | Byzantine fault tolerance |
| Decentralization | None | Yes |
| TPS ceiling | ~10-15k | ~50-100k+ |
| Latency | Very low | Higher (consensus rounds) |

---

## 5. Recommended Next Milestones (T82.x+)

### T82.0 — DAG TPS Baseline & Profiling

**Goal:**
Establish accurate TPS baseline with proper profiling infrastructure. Identify actual hotspots versus theoretical analysis.

**Scope:**
- Enable all executor metrics (waves, conflicts, retries)
- Add CPU profiling hooks (perf/flamegraph compatible)
- Create automated TPS benchmark suite
- Document baseline on reference hardware

**Boundaries:**
- No code changes to executor or consensus
- Config tuning only (exec_lanes, wave_cap, etc.)
- Metrics and profiling infrastructure only

**Success Criteria:**
- Flamegraph clearly shows top 3 CPU consumers
- Automated benchmark produces repeatable TPS numbers (±5%)
- Baseline documented: X tx/s on [hardware spec]

---

### T82.1 — STM Executor Tuning, Part 1

**Goal:**
Implement copy-on-write state to eliminate per-wave cloning overhead.

**Scope:**
- Implement `CowAccounts` wrapper for `Accounts`
- Modify `execute_stm()` to use CoW instead of full clone
- Add unit tests for CoW correctness
- Benchmark before/after

**Boundaries:**
- No changes to conflict detection algorithm
- No changes to wave scheduling
- Preserves STM semantics exactly

**Success Criteria:**
- Equivalence tests pass (same results as before)
- Memory allocation reduced by >50% per block
- TPS improvement of 1.3–1.5×

---

### T82.2 — Mempool + Admission Optimization

**Goal:**
Reduce mempool contention and improve batch quality.

**Scope:**
- Replace `tokio::sync::Mutex` with `parking_lot::Mutex`
- Implement sender-based pre-sorting in `pop_batch()`
- Add mempool contention metrics
- Optional: sharded mempool (if contention is measured)

**Boundaries:**
- No changes to tx format or validation
- No changes to rate limiting algorithm
- Preserves FIFO ordering per sender

**Success Criteria:**
- Lock contention <1ms p99
- Batch nonce failure rate <10%
- No tx starvation under high load

---

### T82.3 — Executor Metrics & Conflict Analytics

**Goal:**
Deep visibility into STM behavior for future optimization.

**Scope:**
- Add per-sender conflict tracking
- Histogram of conflict reasons (same account, supply, etc.)
- Wave size distribution metrics
- Retry reason breakdown

**Boundaries:**
- Metrics only, no behavioral changes
- Should not add measurable overhead (<1%)

**Success Criteria:**
- Can identify top conflict patterns from metrics
- Dashboard shows conflict hotspots
- Data enables informed T82.4 decisions

---

### T82.4 — STM Executor Tuning, Part 2

**Goal:**
Implement conflict-aware scheduling based on T82.3 analytics.

**Scope:**
- Bloom filter for fast conflict pre-check
- Sender-based partitioning for wave building
- Adaptive wave sizing based on conflict rate

**Boundaries:**
- No changes to consensus or DAG
- Preserves deterministic execution

**Success Criteria:**
- Conflict rate <5% of total txs
- Average waves per block <1.5
- TPS improvement of 1.5–2×

---

### T83.0 — Parallel Signature Verification

**Goal:**
Enable real ML-DSA-44 verification in sigpool with parallelization.

**Scope:**
- Enable signature verification in `sigpool.rs`
- Use rayon for parallel batch verification
- Add verification cache (LRU)
- Pre-verify in HTTP handler

**Boundaries:**
- No changes to signature scheme
- No changes to tx format
- Must pass all KAT tests

**Success Criteria:**
- Signature verification <20% of block time
- Cache hit rate >50% for repeated pubkeys
- No valid tx rejected

---

### T83.1 — Initial GPU Offload (Hashing)

**Goal:**
Complete GPU BLAKE3 implementation and enable for block hashing.

**Scope:**
- Implement real BLAKE3 compression in WGSL
- Enable GPU path with CPU cross-check
- Benchmark GPU vs CPU hashing
- Gradual rollout (shadow → prefer)

**Boundaries:**
- Block hashing only (not per-tx)
- CPU remains source of truth initially
- No changes to block format

**Success Criteria:**
- GPU produces bit-identical hashes to CPU
- GPU path 2–5× faster than CPU for large batches
- Zero mismatches in production traffic

---

### T83.2 — GPU Merkle Tree Computation

**Goal:**
Offload Merkle tree computation for tx roots and state roots.

**Scope:**
- Batch leaf hashing on GPU
- Parallel Merkle tree construction
- Integration with block building

**Boundaries:**
- Same Merkle algorithm as before
- CPU fallback available
- No changes to consensus

**Success Criteria:**
- Merkle computation <5% of block time
- Scales linearly with GPU compute units
- TPS improvement measurable

---

### T84.0 — Multi-node DAG TPS Experiments

**Goal:**
Validate TPS scaling with multiple validator nodes.

**Scope:**
- Deploy 4-node testnet (cloud or local)
- Measure TPS with increasing load
- Identify network bottlenecks
- Document multi-node TPS curve

**Boundaries:**
- Existing DAG consensus (no algorithm changes)
- Focus on measurement, not optimization
- Use reference hardware spec

**Success Criteria:**
- 4-node TPS ≥ 2× single-node TPS
- Network bandwidth utilization documented
- Bottleneck identified (network vs CPU vs consensus)

---

### T84.1 — Network Topology Optimization

**Goal:**
Optimize vertex propagation for multi-node TPS.

**Scope:**
- Implement efficient gossip protocol
- Reduce redundant message sends
- Add network bandwidth metrics

**Boundaries:**
- No changes to consensus algorithm
- Compatible with existing peer discovery

**Success Criteria:**
- Network overhead reduced by >50%
- TPS scales sublinearly with node count
- No increase in finality latency

---

## Appendix A: Key Code Locations

| Component | Path | Key Functions |
|-----------|------|---------------|
| STM Executor | `crates/node/src/executor/stm.rs` | `execute_stm()`, `detect_conflicts_in_wave()` |
| Parallel Executor | `crates/node/src/executor/parallel.rs` | `execute_block()`, `build_waves_greedy()` |
| Mempool | `crates/node/src/mempool.rs` | `pop_batch()`, `submit()` |
| Signature | `crates/crypto/src/sig/ml_dsa.rs` | `verify_single()`, `batch_verify()` |
| GPU Hashing | `crates/eezo-prover/src/gpu_hash.rs` | `hash_batch()`, `GpuBlake3Context` |
| DAG Consensus | `crates/consensus-dag/src/order.rs` | `try_order_round()` |
| Persistence | `crates/ledger/src/persistence.rs` | `put_block()`, `put_state_snapshot()` |

## Appendix B: Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `EEZO_EXEC_LANES` | 16 | Parallel execution lanes (16/32/48/64) |
| `EEZO_EXEC_WAVE_CAP` | 0 (unlimited) | Max txs per wave |
| `EEZO_STM_MAX_RETRIES` | 5 | Max retry attempts per tx |
| `EEZO_STM_WAVE_TIMEOUT_MS` | 1000 | Wave timeout safety bound |
| `EEZO_GPU_HASH_REAL` | 0 | Enable real GPU init in prover |
| `EEZO_NODE_GPU_HASH` | off | Node GPU mode (off/shadow/prefer) |
| `EEZO_DAG_ORDERING_THRESHOLD` | 1 | Min distinct producers for round |

## Appendix C: Existing Metrics

### Executor Metrics
- `eezo_exec_block_prepare_seconds`
- `eezo_exec_block_apply_seconds`
- `eezo_exec_block_commit_seconds`
- `eezo_exec_txs_per_block`
- `eezo_exec_lanes` (gauge)
- `eezo_exec_wave_cap` (gauge)

### STM Metrics
- `eezo_stm_block_waves_total`
- `eezo_stm_block_conflicts_total`
- `eezo_stm_block_retries_total`
- `eezo_stm_waves_per_block` (histogram)
- `eezo_stm_conflicts_per_block` (histogram)
- `eezo_stm_retries_per_block` (histogram)

### Mempool Metrics
- `eezo_mempool_len` (gauge)
- `eezo_mempool_bytes_gauge`
- `eezo_tx_rejected_total` (by reason)

### GPU Metrics
- `eezo_gpu_hash_attempts_total`
- `eezo_gpu_hash_success_total`
- `eezo_gpu_hash_error_total`
- `eezo_gpu_hash_mismatch_total`
- `eezo_node_gpu_hash_enabled` (gauge)

---

*End of TPS Architect's Report*
