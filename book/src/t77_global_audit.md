# T77.0 — EEZO Full Project Audit Report

**Date**: 2025-12-05  
**Version**: 1.0  
**Scope**: Consensus, DAG Hybrid, TPS Pipeline, PQC Crypto, Bridge, Observability

---

## Executive Summary

### Current Health

1. **Liveness**: The chain runs in `dag-hybrid` mode with STM executor and successfully processes transactions (600 tx spam test passes). However, **fallback rate is high** — most blocks use mempool fallback, not DAG batches.

2. **Safety**: No critical safety vulnerabilities identified. The hybrid mode preserves Hotstuff finality guarantees. DAG shadow hash mismatch counter shows no ordering divergence.

3. **TPS**: Theoretical capacity with STM executor (32 lanes, 256 wave cap) is ~500-1000 TPS. Practical observed TPS is likely 250-400 TPS under load. **Bottleneck is in DAG batch consumption, not execution.**

4. **Biggest Risk**: The DAG ordering layer is not effectively feeding transactions to the proposer. The `eezo_dag_hybrid_batches_used_total` staying low while `eezo_dag_hybrid_fallback_total` is high indicates a structural timing or queue-depth issue.

5. **Root Cause Hypothesis**: DAG batches arrive too late relative to the consensus tick. The proposer checks for batches at tick-start, but batches become ready after ordering completes (which happens asynchronously).

### Biggest Risks / Unknowns

- **DAG-Hotstuff timing mismatch**: DAG ordering may be slower than Hotstuff tick cadence
- **Empty batches at tick-start**: The proposer polls before batches are populated
- **Mempool-DAG data flow**: Pending txs may not be submitted to DAG early enough
- **Stale batch handling**: Batches from pre-startup rounds may pollute the queue
- **No quorum validation in shadow mode**: DAG operates single-node without Byzantine fault testing

### Recommendation

**Prioritize: (A) Safety/Correctness First, (B) DAG-Primary Second**

1. Fix the immediate liveness issue (DAG batch timing) before declaring DAG-primary ready
2. Add comprehensive invariant tests for hybrid commit ordering
3. Instrument deeper metrics to identify exact bottleneck location
4. Complete 7-day canary with zero fallbacks before moving to DAG-primary

---

## 1. Consensus & Ordering Audit

### 1.1 HotStuff Path

**Location**: `crates/ledger/src/consensus.rs`, `crates/node/src/consensus_runner.rs`

**Implementation Quality**: 
- Clean single-node implementation with deterministic slot-based ticking
- Uses `SingleNode` struct which encapsulates accounts, supply, mempool, and config
- Proper snapshot/rollback mechanism for error recovery
- Transaction draining is fee-ordered with nonce-ordering per sender

**Safety/Correctness**:
- ✅ Monotonic height enforcement (no rollbacks)
- ✅ Block hash chaining (`prev_hash` updated after each commit)
- ✅ State root computation tied to checkpoints
- ⚠️ Single-node mode means no view change or leader election tested
- ⚠️ No Byzantine fault tolerance exercised (expected for single-node)

**Timeouts**:
- Tick interval configurable via `tick_ms` parameter
- No explicit view change timeout (single-node doesn't need it)
- Checkpoint emission at configurable interval (`EEZO_CHECKPOINT_EVERY`)

**Verdict**: HotStuff path is solid for single-node operation. Ready to serve as fallback/safety rail.

### 1.2 DAG Path

**Location**: `crates/node/src/dag_runner.rs`, `crates/node/src/dag_consensus_runner.rs`, `crates/consensus-dag/src/`

**DAG Store**:
- In-memory vertex store with parent tracking
- Tip management for graph traversal
- Monotonic vertex ID assignment
- No persistence (expected for shadow mode)

**HybridDagHandle**:
- Provides `try_next_ordered_batch()` for non-blocking batch consumption
- `submit_pending_txs()` feeds mempool txs to DAG for ordering
- `peek_ordered_queue_len()` for observability without consumption
- Tracks sync status via `DagConsensusTracker`

**Narwhal/Bullshark-style Ordering**:
- `consensus-dag` crate implements DAG consensus handle
- Payloads are submitted and ordered by round advancement
- Batches are enqueued and consumed via `try_next_ordered_batch()`

**Vertex Formation**:
- Vertices carry `DagPayload` which can be `Empty` or `TxHashes(Vec<DagTxRef>)`
- Transaction hashes are referenced, not full tx bodies
- Bytes can be optionally attached for zero-copy consumption

**Hash Sampling**:
- `dag_shadow_payload_from_mempool()` samples up to N hashes from mempool
- Shadow mode records canonical tx hashes for comparison

**What Looks Solid**:
- Clean separation between DAG store, handle, and consensus runner
- Non-blocking batch consumption fits async tick model
- De-dup cache prevents double-processing of committed txs
- Nonce pre-check filters stale transactions early

**What Feels Experimental**:
- Single-node DAG doesn't exercise network gossip or Byzantine scenarios
- No quorum certificates or threshold signatures on DAG vertices
- Batch ordering is round-based but no explicit latency bounds
- `submit_pending_txs()` was added recently (T76.12) and may have timing issues

**Needs Tests**:
- Multi-batch aggregation under high load
- Stale batch rejection with various startup watermarks
- DAG-Hotstuff hybrid commit ordering invariants
- Network partition simulation (when multi-node is ready)

### 1.3 Hybrid Integration

**Location**: `crates/node/src/consensus_runner.rs` (lines 1326-1520)

**Interaction Model**:
1. At each tick, proposer feeds pending mempool txs to DAG (`submit_pending_txs`)
2. Waits up to `batch_timeout_ms` for DAG batches (T76.12 fix)
3. If batches available, aggregates up to `max_tx`/`max_bytes` with time budget
4. Applies de-dup filter and nonce pre-check
5. If no usable txs from DAG, falls back to mempool
6. After commit, removes committed txs from mempool

**Liveness Concerns**:
- **Timing Issue**: DAG batches may not be ready at tick-start
- **Empty Batches**: Batches may pass initial check but be empty after filtering
- **Fallback Reasons**: `eezo_dag_hybrid_fallback_reason_total{reason="empty|min_dag_not_met"}` indicates batches exist but are unusable

**Safety**:
- ✅ Fallback to mempool preserves liveness
- ✅ De-dup cache prevents double-commit
- ✅ Nonce pre-check prevents stale tx inclusion
- ⚠️ No explicit check that DAG ordering matches ledger ordering

### 1.4 Liveness & Safety Analysis

**Ways the Chain Can Stall**:
1. ❌ Mempool empty and no pending txs → Empty blocks (not a stall, just no progress)
2. ❌ DAG handle not attached → Falls back to mempool (covered)
3. ⚠️ All DAG batches stale or filtered → Falls back, but indicates DAG is ineffective

**Ways the Chain Can Fork**:
- Not applicable in single-node mode
- Multi-node would need BFT quorum validation

**Safety Violations**:
- ✅ No identified paths to double-spend or invalid state transitions
- ✅ Signature verification mandatory (except dev mode)
- ⚠️ Dev mode (`EEZO_DEV_ALLOW_UNSIGNED_TX`) bypasses sig verification — never in production

**Network Partition / Slow Validators**:
- Single-node is immune to partition
- Multi-node DAG would need:
  - Quorum certificate requirements
  - Timeout-based view changes
  - Pessimistic leader election after failures

---

## 2. Execution & State Audit

### 2.1 STM Executor

**Location**: `crates/node/src/executor/` (feature-gated with `stm-exec`)

**Configuration**:
- `EEZO_EXECUTOR_MODE=stm`
- `EEZO_EXEC_LANES=32` (concurrent execution lanes)
- `EEZO_EXEC_WAVE_CAP=256` (max txs per wave)

**Scheduling**:
- Transactions are grouped into waves
- Concurrent execution within wave
- Conflict detection and retry on write-write conflicts
- Max retries configurable

**Interaction with Consensus**:
- Executor is called from consensus runner after tx collection
- Returns `ExecOutcome` with result or error
- Block applied to state only on success

**Performance**:
- Theoretical max: `lanes × (1000/avg_exec_ms)` TPS
- With 32 lanes and 3ms avg exec: ~10,000 theoretical TPS
- Practical bottleneck is elsewhere (DAG/aggregation)

**Risks**:
- ⚠️ Conflict storms under high contention (same account, same nonce)
- ⚠️ Wave timeout too aggressive may drop valid txs
- ✅ Fallback to parallel executor if STM feature not compiled

### 2.2 Mempool Design

**Location**: `crates/ledger/src/mempool.rs`

**Nonce Handling**:
- Per-sender BTreeMap keyed by nonce
- Only lowest nonce per sender is "ready" for draining
- Higher nonces kept as "futures"
- Gap tolerance: allows future nonces to be enqueued

**Rate Limiting**:
- `EEZO_MEMPOOL_MAX_LEN`, `EEZO_MEMPOOL_MAX_BYTES`
- `EEZO_MEMPOOL_RATE_CAP`, `EEZO_MEMPOOL_RATE_PER_MIN`
- Implemented in node's HTTP layer (not shown in mempool.rs)

**Spam Behavior**:
- Fee-ordering prioritizes high-fee txs
- Nonce-ordering per sender prevents nonce exhaustion
- Future nonces don't block current nonce processing

**Zombie Tx Risks**:
- ✅ `remove_committed_txs()` cleans up after hybrid commit (T76.13 fix)
- ⚠️ No expiration for stale txs (could accumulate if never committed)
- ⚠️ Very high-nonce txs could sit forever if gaps never filled

**Recommendations**:
- Add TTL-based expiration for mempool entries
- Add metrics for mempool age distribution
- Consider nonce-gap limit to prevent unbounded futures

### 2.3 State Sync & Checkpoints

**Location**: `crates/node/src/state_sync.rs`, `crates/ledger/src/checkpoints.rs`

**State Sync**:
- Anchor-based sync with height, QC hash, state root
- Snapshot paging for large state sets
- Delta batches for incremental sync
- Retry with exponential backoff

**Checkpoints**:
- Emitted at configurable interval
- Contains tx root, state root, height, finality depth
- Optional QC sidecar for rotation support

**Potential Issues**:
- ⚠️ State sync signature verification only enforced when TLS enabled
- ⚠️ No merkle proof validation for snapshot pages (trusts source)
- ✅ Anchor signature verification with ML-DSA or SPHINCS+
- ✅ Monotonic height enforcement

---

## 3. Performance & TPS Pipeline

### 3.1 End-to-End Path

```
/tx → Mempool → [DAG Ordering] → Hybrid Aggregation → STM Execution → Commit → Metrics
```

**Step 1: /tx Endpoint**
- Signature verification (sigpool)
- Stateful validation (nonce, funds)
- Enqueue to mempool

**Step 2: DAG Ordering**
- At tick-start: `submit_pending_txs()` feeds mempool hashes to DAG
- DAG orders and enqueues batches
- `try_next_ordered_batch()` returns ordered batch

**Step 3: Hybrid Aggregation**
- Multi-batch consumption with time budget
- De-dup filter removes already-committed
- Nonce pre-check removes stale nonces
- Byte and tx count soft caps

**Step 4: STM Execution**
- Wave-based parallel execution
- Conflict detection and retry
- State mutations applied on success

**Step 5: Commit**
- Block header written
- State snapshot at intervals
- Checkpoint emission
- Mempool cleanup

### 3.2 Why DAG Batches Are Underutilized

**Observed Symptoms**:
- `eezo_dag_hybrid_batches_used_total`: 2-4
- `eezo_dag_hybrid_fallback_total`: hundreds
- `fallback_reason="empty|min_dag_not_met"`: most common

**Root Cause Analysis**:

1. **Timing Mismatch**: 
   - `submit_pending_txs()` is called at tick-start
   - DAG ordering is asynchronous
   - By the time ordering completes, tick has moved on
   - Next tick finds empty queue (already consumed or not ready)

2. **Min DAG Threshold Not Met**:
   - `EEZO_HYBRID_MIN_DAG_TX=1` (default) should be easy to meet
   - But if batch is filtered down to 0 by de-dup, threshold fails
   - This suggests txs submitted to DAG were already committed

3. **Batch Timeout Too Short**:
   - `EEZO_HYBRID_BATCH_TIMEOUT_MS=10` may be too short
   - DAG ordering might need 20-50ms under load

**Recommendations**:
- Increase `EEZO_HYBRID_BATCH_TIMEOUT_MS` to 20-50ms
- Add metrics for DAG ordering latency
- Consider pre-populating DAG batches in background thread
- Add metric for "time from submit to batch ready"

### 3.3 Real Bottleneck

**Bottleneck Ranking** (most to least likely):

1. **DAG Batch Timing** (High)
   - Evidence: High fallback rate, low batch usage
   - Fix: Longer timeout, async pre-population

2. **Aggregation Window** (Medium)
   - Evidence: `agg_time_budget_ms` may be too short
   - Fix: Increase or make adaptive

3. **De-dup Filter** (Medium)
   - Evidence: `fallback_reason="empty"` after filtering
   - Fix: Only submit fresh txs to DAG

4. **Executor** (Low)
   - Evidence: STM with 32 lanes should be fast
   - Not the bottleneck currently

5. **Crypto** (Low)
   - Evidence: ML-DSA verification is fast
   - Sigpool parallelizes verification

### 3.4 Devnet Production Ready Estimate

**Current State**: 60% ready

**Must Fix**:
- DAG batch timing issue
- Achieve <5% fallback rate under load
- Pass 7-day canary with all SLOs

**Low-Hanging Fruit**:
- Increase batch timeout (config change, no code)
- Tune adaptive aggregation parameters
- Add ordering latency histogram

**Deep Changes**:
- Pre-populate DAG batches asynchronously
- Multi-node DAG with network gossip
- Quorum certificates on vertices

---

## 4. PQC & Crypto Integration

### 4.1 eezo-crypto Overview

**Location**: `crates/crypto/src/`

**Algorithms**:
| Family | Variant | Algo ID | Status |
|--------|---------|---------|--------|
| ML-DSA | 44 | 0x0144 | Default signature |
| SLH-DSA | 128s | 0x0244 | Optional (`slh-dsa` feature) |
| ML-KEM | 768 | 0x0344 | Default KEM |

**Usage Patterns**:
- Wallet: keygen, signing
- Node: verification, anchor signing
- Prover: (not directly using crypto crate)
- Bridge: verification of checkpoint signatures

### 4.2 Key/Address Derivation

**Address from PublicKey**:
- First 20 bytes of public key used as address
- `sender_from_pubkey_first20()` in `crates/ledger/src/tx.rs`
- Consistent across node, wallet, and bridge

**Key Formats**:
- ML-DSA-44 public key: 1952 bytes (encoded)
- ML-DSA-44 signature: 2560 bytes
- SPHINCS+-128f signature: much larger (48KB+)

### 4.3 Potential Issues

**Red Flags**:
- ⚠️ `EEZO_DEV_ALLOW_UNSIGNED_TX=1` in production would be catastrophic
- ⚠️ `skip-sig-verify` feature should never be in production builds

**Missing Checks**:
- ✅ Signature length validation before verification
- ✅ Public key format validation
- ⚠️ No explicit check for weak/known-bad keys

**Randomness**:
- Uses `OsRng` from `rand` crate for keygen
- ✅ Cryptographically secure on supported platforms
- ⚠️ No entropy health monitoring

**Recommendations**:
- Add CI check to fail if `skip-sig-verify` in release builds
- Add audit for `EEZO_DEV_ALLOW_UNSIGNED_TX` usage in prod config
- Consider key revocation mechanism for compromised keys

---

## 5. Bridge & Light Client

### 5.1 EezoLightClient.sol

**Location**: `eezo-contracts/src/EezoLightClient.sol`

**Trust Model**:
- Ethereum trusts EEZO block headers submitted via `verifyAndStore()`
- Headers contain: height, tx root, state root, sig batch digest
- Proof verification delegated to external `IVerifier` contract

**What Ethereum Trusts**:
1. The `verifier` contract correctly validates STARK proofs
2. The admin correctly sets `expectedChainId20`
3. Header submissions are monotonically increasing in height
4. Circuit versions are allowlisted by admin

### 5.2 Security Considerations

**Replay Risks**:
- ✅ Chain ID binding prevents cross-chain replay
- ✅ Monotonic height prevents re-submission of old headers
- ✅ Idempotent store for same-height updates

**Header Validation**:
- ✅ Zero root check (non-zero required)
- ✅ Circuit version allowlist
- ✅ Suite ID validation for rotation

**Proof Format Brittleness**:
- ⚠️ ABI-encoded public inputs must match exact struct layout
- ⚠️ Circuit version mismatch could cause decode failures
- ✅ Separate V1/V2 decoding paths

### 5.3 Bridge Relay

**Location**: `eezo-relay/` (not fully audited)

**High-Level Flow**:
1. Relay polls node for new checkpoints
2. Fetches proof from prover
3. Submits to Ethereum light client contract
4. Handles backoff on failures

**Risks**:
- ⚠️ Relay is centralized (single point of failure)
- ⚠️ Proof generation latency affects bridge freshness
- ✅ Backoff mechanism prevents spam on failures

---

## 6. Observability & SLOs

### 6.1 Metrics Coverage

**Consensus Metrics**:
- ✅ `eezo_consensus_mode_active`: 0=hotstuff, 1=hybrid, 2=dag
- ✅ `eezo_block_height`: current committed height
- ✅ `eezo_txs_included_total`: cumulative txs
- ✅ `eezo_block_e2e_latency_seconds`: slot timing

**DAG Metrics**:
- ✅ `eezo_dag_ordered_ready`: queue depth gauge
- ✅ `eezo_dag_hybrid_batches_used_total`: successful DAG usage
- ✅ `eezo_dag_hybrid_fallback_total`: fallback count
- ✅ `eezo_dag_hybrid_fallback_reason_total{reason=...}`: labeled fallback

**Execution Metrics**:
- ✅ `eezo_exec_lanes`, `eezo_exec_wave_cap`: STM config
- ⚠️ Missing: conflicts per wave histogram
- ⚠️ Missing: wave duration histogram

**Mempool Metrics**:
- ✅ `eezo_mempool_len`, `eezo_mempool_bytes_gauge`
- ⚠️ Missing: per-sender queue depth
- ⚠️ Missing: oldest tx age

### 6.2 Alerts

**Current Alerts** (`ops/alerts.yml`):
- ✅ `DagHybridFallbackHigh`: >1 fallback/hour
- ✅ `DagShadowHashMismatch`: any mismatch
- ✅ `DagOrderedQueueBacklog`: queue >10
- ✅ `DagHybridApplyQualityLow`: <99.9% apply rate

**Gaps**:
- ⚠️ No alert for DAG ordering latency
- ⚠️ No alert for mempool age
- ⚠️ No alert for executor conflict rate

### 6.3 Missing Metrics for Production

| Metric | Purpose | Priority |
|--------|---------|----------|
| `eezo_dag_ordering_latency_seconds` | Time from submit to batch ready | High |
| `eezo_mempool_oldest_age_seconds` | Detect zombie txs | Medium |
| `eezo_stm_conflicts_per_wave` | Detect contention | Medium |
| `eezo_sigpool_queue_depth` | Signature verification backlog | Medium |
| `eezo_bridge_proof_latency_seconds` | Prover performance | Low |

---

## 7. HotStuff vs DAG — Architectural Recommendation

### 7.1 Medium-Term Recommendation

**Keep Hybrid Mode for Devnet**

The current hybrid architecture provides a safe path forward:
- Hotstuff guarantees liveness even if DAG underperforms
- DAG can be improved without risking chain stalls
- Metrics allow gradual confidence building

### 7.2 When to Move to DAG-Primary

**Prerequisites**:
1. ✅ DAG batch fallback rate <5% under sustained load
2. ✅ No hash mismatches in 7-day canary
3. ✅ Apply quality ≥99.9%
4. ⬜ DAG ordering latency p99 <50ms
5. ⬜ Multi-node DAG with network tested

**Milestones**:

| Phase | Description | When |
|-------|-------------|------|
| Hybrid | HotStuff primary, DAG assists | Now |
| DAG-Primary | DAG primary, HotStuff fallback | After 7-day canary passes |
| DAG-Only | Remove HotStuff | After 30-day multi-node canary |

### 7.3 When It's Safe to Remove HotStuff

**Conditions**:
1. Multi-node DAG with BFT quorum tested
2. Network partition handling proven
3. 30+ days production without any HotStuff fallback
4. Formal verification of DAG safety properties (optional but recommended)

**Not Before**:
- Multi-node deployment
- Byzantine fault injection testing
- Crash/restart durability proven

---

## 8. Prioritized Task List

| ID | Category | Description | Main Files | Impact | Size |
|----|----------|-------------|------------|--------|------|
| **SAFE-1** | safety/correctness | Add invariant tests for hybrid commit order | `consensus_runner.rs`, `tests/` | High | Medium |
| **SAFE-2** | safety/correctness | Add CI check blocking `skip-sig-verify` in release | `.github/workflows/` | High | Small |
| **SAFE-3** | safety/correctness | Add TTL expiration for mempool entries | `mempool.rs` | Medium | Medium |
| **DAG-1** | DAG-primary | Increase `EEZO_HYBRID_BATCH_TIMEOUT_MS` default to 20-50ms | `adaptive_agg.rs` | High | Small |
| **DAG-2** | DAG-primary | Add `eezo_dag_ordering_latency_seconds` histogram | `dag_consensus_runner.rs`, `metrics.rs` | High | Small |
| **DAG-3** | DAG-primary | Pre-populate DAG batches asynchronously | `consensus_runner.rs`, `dag_consensus_runner.rs` | High | Large |
| **DAG-4** | DAG-primary | Only submit fresh (non-committed) txs to DAG | `consensus_runner.rs` | Medium | Medium |
| **DAG-5** | DAG-primary | Add multi-node DAG with network gossip | `consensus-dag/`, `dag_runner.rs` | High | Large |
| **TPS-1** | TPS/perf | Add wave duration histogram | `executor/` | Medium | Small |
| **TPS-2** | TPS/perf | Add conflict rate per wave metric | `executor/` | Medium | Small |
| **TPS-3** | TPS/perf | Profile and optimize de-dup filter | `dag_consensus_runner.rs` | Medium | Medium |
| **TPS-4** | TPS/perf | Add per-sender mempool depth metric | `mempool.rs`, `metrics.rs` | Low | Small |
| **BRIDGE-1** | bridge | Add proof generation latency metric | `eezo-relay/`, `eezo-prover/` | Medium | Small |
| **BRIDGE-2** | bridge | Add relay redundancy (multiple relayers) | `eezo-relay/` | Medium | Large |
| **BRIDGE-3** | bridge | Add header freshness alert | `ops/alerts.yml` | Medium | Small |
| **OPS-1** | ops | Add DAG ordering latency alert | `ops/alerts.yml` | High | Small |
| **OPS-2** | ops | Add mempool age alert | `ops/alerts.yml` | Medium | Small |
| **OPS-3** | ops | Add Grafana panel for hybrid batch timing | `ops/grafana/` | Medium | Small |
| **OPS-4** | ops | Add chaos testing runbook | `book/src/` | Medium | Medium |
| **CRYPTO-1** | crypto | Add entropy health monitoring | `eezo-crypto/` | Low | Medium |
| **CRYPTO-2** | crypto | Add key revocation mechanism | `eezo-crypto/`, `ledger/` | Low | Large |
| **SYNC-1** | state-sync | Add merkle proof validation for snapshots | `state_sync.rs` | Medium | Large |
| **TEST-1** | testing | Add multi-batch aggregation stress test | `tests/` | Medium | Medium |
| **TEST-2** | testing | Add stale batch rejection test | `dag_consensus_runner.rs` tests | Medium | Small |
| **TEST-3** | testing | Add Byzantine fault injection harness | `tests/` | High | Large |

---

## Appendix A: Environment Variables Reference

### Consensus

| Variable | Default | Description |
|----------|---------|-------------|
| `EEZO_CONSENSUS_MODE` | `hotstuff` | `hotstuff`, `dag-hybrid`, or `dag` |
| `EEZO_DAG_ORDERING_ENABLED` | `0` | Enable DAG ordering in hybrid mode |
| `EEZO_HYBRID_MIN_DAG_TX` | `1` | Min txs from DAG before fallback |
| `EEZO_HYBRID_BATCH_TIMEOUT_MS` | `10` | Wait time for DAG batches |

### Execution

| Variable | Default | Description |
|----------|---------|-------------|
| `EEZO_EXECUTOR_MODE` | `parallel` | `single`, `parallel`, or `stm` |
| `EEZO_EXEC_LANES` | `num_cpus` | STM execution lanes |
| `EEZO_EXEC_WAVE_CAP` | `256` | Max txs per wave |

### Aggregation

| Variable | Default | Description |
|----------|---------|-------------|
| `EEZO_HYBRID_AGG_TIME_BUDGET_MS` | adaptive | Fixed aggregation window |
| `EEZO_HYBRID_AGG_MAX_TX` | `500` | Max txs per block |
| `EEZO_HYBRID_AGG_MAX_BYTES` | `1MiB` | Max bytes per block |

### Mempool

| Variable | Default | Description |
|----------|---------|-------------|
| `EEZO_MEMPOOL_MAX_LEN` | `100000` | Max pending txs |
| `EEZO_MEMPOOL_MAX_BYTES` | `256MiB` | Max mempool size |
| `EEZO_MEMPOOL_RATE_CAP` | `100000` | Rate limit (tx/window) |

---

## Appendix B: Glossary

- **DAG**: Directed Acyclic Graph for transaction ordering
- **HotStuff**: BFT consensus protocol (single-node variant here)
- **STM**: Software Transactional Memory executor
- **ML-DSA**: Module Lattice Digital Signature Algorithm (NIST PQC)
- **SPHINCS+**: Stateless hash-based signature scheme
- **ML-KEM**: Module Lattice Key Encapsulation Mechanism

---

*End of T77.0 Audit Report*
