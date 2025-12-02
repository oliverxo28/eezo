# T74.0 — DAG Consensus Integration Plan

**Goal:** Evolve from Hotstuff-driven block production + DAG sidecar to full DAG-based consensus using the `backup/consensus-dag` code as reference, without breaking the bridge, light client, persistence, or executor layers.

---

## Table of Contents

1. [Current Architecture Snapshot](#1-current-architecture-snapshot)
2. [consensus-dag Crate Anatomy](#2-consensus-dag-crate-anatomy)
3. [Target DAG Consensus Architecture](#3-target-dag-consensus-architecture)
4. [Migration Plan: Hotstuff → DAG](#4-migration-plan-hotstuff--dag)
5. [Constraints & Compatibility](#5-constraints--compatibility)
6. [T74.x Task Breakdown](#6-t74x-task-breakdown)

---

## 1. Current Architecture Snapshot

### 1.1 Hotstuff Consensus Path

The current block production is driven by `CoreRunnerHandle` in `crates/node/src/consensus_runner.rs`:

```
┌─────────────────────────────────────────────────────────────────┐
│                       CoreRunnerHandle                          │
│  ┌──────────┐    ┌─────────────┐    ┌───────────┐              │
│  │ Mempool  │───▶│ SingleNode  │───▶│ Executor  │───▶ Block    │
│  │ drain()  │    │ (Hotstuff)  │    │ (S/P/STM) │    Commit    │
│  └──────────┘    └─────────────┘    └───────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

**Key components:**

1. **`CoreRunnerHandle::spawn()`** — Starts a background task that:
   - Drains transactions from mempool
   - Proposes blocks via `SingleNode` (Hotstuff-style consensus)
   - Executes transactions via the configured Executor (Single/Parallel/STM)
   - Commits blocks to persistence

2. **`SingleNode`** — Implements the `Consensus` trait with:
   - Height-based block ordering
   - PQ signature verification (ML-DSA)
   - QC (Quorum Certificate) for finality

3. **Block finality** is currently defined by:
   - Hotstuff QC signed by validators
   - `qc_hash` field in `BlockHeader` (when `checkpoints` feature is enabled)

### 1.2 DAG Sidecar Path

The current DAG implementation in `crates/node/src/dag_runner.rs` is a **sidecar** that:

```
┌─────────────────────────────────────────────────────────────────┐
│                       DagRunnerHandle                           │
│  ┌──────────┐    ┌───────────┐    ┌─────────────────────────┐  │
│  │ Mempool  │───▶│ DagStore  │───▶│ Shadow Block Templates  │  │
│  │ sample() │    │ (in-mem)  │    │ (dry-run, no commit)    │  │
│  └──────────┘    └───────────┘    └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**What DAG sidecar does:**
- Samples tx hashes from mempool (non-destructive)
- Creates DAG vertices with payload references
- Provides debug endpoints (`/dag/debug`, `/dag/candidate`, `/dag/block_dry_run`)
- Builds "shadow" block templates for testing

**What DAG sidecar does NOT do:**
- **No real block commits** — blocks still come from Hotstuff
- **No network gossip** — vertices are local only
- **No ordering/finality** — no consensus protocol
- **No persistence** — in-memory only

### 1.3 Current Assumptions Used by Bridge/Light Client

The `eezo-contracts` light client and `eezo-relay` rely on:

1. **Block headers** with:
   - `height`, `prev_hash`, `tx_root`, `fee_total`, `tx_count`, `timestamp_ms`
   - `qc_hash` (checkpoint feature) — proves validator consensus

2. **Commit rules:**
   - Headers are linearly ordered by height
   - Finality is determined by QC inclusion
   - Relay submits headers to L1 bridge contract

3. **Prover/relay interfaces:**
   - SSZ serialization for proofs (`eth-ssz` feature)
   - Merkle inclusion proofs for transactions

---

## 2. consensus-dag Crate Anatomy

The `backup/consensus-dag/` crate provides a candidate DAG consensus stack:

### 2.1 Module Overview

| Module | Purpose |
|--------|---------|
| `types.rs` | Core types: `VertexId`, `PayloadId`, `Round`, `AuthorId`, `DagNode`, `OrderedBundle` |
| `store.rs` | Thread-safe DAG storage with GC, equivocation detection (DashMap-based) |
| `gossip.rs` | Network messages: `VertexAnn`, `PayloadReq/Resp`, `ParentsReq/Resp` |
| `builder.rs` | Payload construction from mempool (peek-based, non-destructive) |
| `order.rs` | Bullshark-style deterministic ordering: `OrderingEngine` |
| `da_worker.rs` | Data availability worker: payload caching and chunk assembly |
| `metrics.rs` | Prometheus metrics for DAG consensus |
| `executor_shim.rs` | Bridge from `OrderedBundle` → existing executor |

### 2.2 Key Mechanisms

#### Vertex Building (`builder.rs`)
```rust
// Non-destructive peek from mempool
let txs = mempool.peek_by_bytes(target_bytes);
// Serialize + compute blake3 digest
let payload_id = PayloadId::compute(&payload);
```

#### Data Availability (`da_worker.rs`)
- **Hash-only consensus:** Vertices carry `PayloadId` (blake3 digest), not full payload
- **Separate data plane:** Payloads fetched via `PayloadReq/Resp` messages
- **Cache management:** `PayloadCache` stores assembled payloads

#### Ordering / Finality (`order.rs`)
```rust
// Bullshark-style: round is ready when distinct_authors >= threshold
fn try_order_round(&self, store: &DagStore, round: Round) -> Option<OrderedBundle>
```

**Finality model:**
- A round is finalized when sufficient distinct producers contribute vertices
- `OrderedBundle` contains ordered vertex IDs and transaction count
- Deterministic: same DAG state → same ordering

### 2.3 Reusable vs. Needs Rework

| Component | Status | Notes |
|-----------|--------|-------|
| `types.rs` | ✅ Reusable | Core types are well-defined |
| `store.rs` | ✅ Reusable | Thread-safe, equivocation detection included |
| `order.rs` | ✅ Reusable | Deterministic ordering logic is sound |
| `builder.rs` | ⚠️ Needs adaptation | Must integrate with current mempool API |
| `gossip.rs` | ⚠️ Needs network layer | Messages defined, but no transport yet |
| `da_worker.rs` | ⚠️ Needs network layer | Fetching requires P2P integration |
| `executor_shim.rs` | ⚠️ Needs update | Must integrate with current Executor trait |
| `metrics.rs` | ✅ Reusable | Prometheus metrics compatible |

---

## 3. Target DAG Consensus Architecture

### 3.1 Production consensus_dag Integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Node Runtime (main.rs)                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                     DagConsensusRunner                            │  │
│  │  ┌──────────┐  ┌───────────────┐  ┌─────────────────────────────┐│  │
│  │  │ Mempool  │  │  DagStore     │  │      OrderingEngine         ││  │
│  │  │ peek()   │──│  (persist)    │──│  (Bullshark)                ││  │
│  │  └──────────┘  └───────────────┘  └─────────────────────────────┘│  │
│  │        │               │                       │                  │  │
│  │        ▼               ▼                       ▼                  │  │
│  │  ┌──────────┐  ┌───────────────┐  ┌─────────────────────────────┐│  │
│  │  │ Builder  │  │   DAWorker    │  │     ExecutorShim            ││  │
│  │  │ payload  │──│   (fetch)     │──│ (STM/Parallel/Single)       ││  │
│  │  └──────────┘  └───────────────┘  └─────────────────────────────┘│  │
│  │                                            │                      │  │
│  │                                            ▼                      │  │
│  │  ┌──────────────────────────────────────────────────────────────┐│  │
│  │  │                    Persistence Layer                          ││  │
│  │  │  - DAG vertices (new table)                                   ││  │
│  │  │  - Ordered blocks (existing)                                  ││  │
│  │  │  - Checkpoints (existing)                                     ││  │
│  │  └──────────────────────────────────────────────────────────────┘│  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Runtime Configuration

**Environment variables:**

| Variable | Values | Purpose |
|----------|--------|---------|
| `EEZO_CONSENSUS_MODE` | `hotstuff` / `dag` / `dag-shadow` | Select consensus backend |
| `EEZO_EXECUTOR_MODE` | `single` / `parallel` / `stm` | Select executor (unchanged) |
| `EEZO_DAG_ORDERING_THRESHOLD` | `1` - `n` | Min distinct producers for round finality |
| `EEZO_DAG_BATCH_TARGET_BYTES` | bytes | Target payload size |

**Feature flags:**

| Feature | Purpose |
|---------|---------|
| `dag-consensus` | Compile DAG consensus code |
| `stm-exec` | Enable STM executor (unchanged) |
| `checkpoints` | Enable checkpoint emission |
| `persistence` | Enable persistent storage |

### 3.3 Finality in DAG World

**Definition:** A round is finalized when:
1. Sufficient distinct producers (≥ threshold) have vertices in the round
2. All parent vertices are available and in earlier rounds
3. `OrderingEngine::try_order_round()` returns `Some(OrderedBundle)`

**Confirmation depth:**
- Conservative: wait for N additional rounds after ordering
- Configurable via `EEZO_DAG_CONFIRMATION_DEPTH`

### 3.4 DAG → Executor Handoff

```rust
// In DagConsensusRunner:
loop {
    // 1. Check for orderable rounds
    if let Some(bundle) = ordering.try_order_round(&store, current_round) {
        // 2. Wait for payloads
        executor_shim.wait_for_payloads(&bundle).await?;
        
        // 3. Deserialize transactions
        let txs = executor_shim.deserialize_payloads(&bundle)?;
        
        // 4. Execute via existing Executor trait
        let outcome = executor.execute(ExecInput {
            height: bundle.height(),
            prev_hash,
            txs,
            timestamp_ms: now(),
        });
        
        // 5. Commit to persistence
        persistence.commit_block(&outcome.block)?;
        
        // 6. Update DAG state
        store.mark_committed(current_round);
        current_round += 1;
    }
}
```

### 3.5 Persistence Schema

**New tables for DAG:**

```sql
-- DAG vertices
CREATE TABLE dag_vertices (
    id BLOB PRIMARY KEY,      -- VertexId (32 bytes)
    round INTEGER NOT NULL,
    author BLOB NOT NULL,     -- AuthorId (32 bytes)
    parent_ids BLOB,          -- Serialized Vec<VertexId>
    payload_id BLOB NOT NULL, -- PayloadId (32 bytes)
    created_at INTEGER,       -- Unix timestamp
    committed INTEGER DEFAULT 0
);

-- Ordered bundles (for replay)
CREATE TABLE dag_bundles (
    round INTEGER PRIMARY KEY,
    vertex_ids BLOB NOT NULL,  -- Serialized Vec<VertexId>
    tx_count INTEGER,
    committed_height INTEGER,  -- Maps to block height
    finalized_at INTEGER
);
```

**Existing tables (unchanged):**
- `blocks` — Finalized blocks with headers
- `checkpoints` — Checkpoint data for light client

### 3.6 Metrics

**DAG-specific metrics (from `consensus-dag/metrics.rs`):**

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_dag_vertices_total` | Counter | Total vertices stored |
| `eezo_dag_round` | Gauge | Current round number |
| `eezo_dag_bundles_total` | Counter | Ordered bundles emitted |
| `eezo_dag_bundle_txs_total` | Counter | Transactions in bundles |
| `eezo_dag_ordering_latency_seconds` | Histogram | Round ordering time |
| `eezo_dag_equivocations_total` | Counter | Equivocations detected |

---

## 4. Migration Plan: Hotstuff → DAG

### Phase T74.x: Bring consensus-dag Back

**Goal:** Get `consensus-dag` compiling as a crate, gated behind a feature flag.

1. **T74.1:** Create `crates/consensus-dag/` from backup
   - Copy `backup/consensus-dag/` to `crates/consensus-dag/`
   - Fix any import paths (e.g., `eezo-ledger` path)
   - Add `dag-consensus` feature flag to `eezo-node`
   - Ensure `cargo check` passes with the feature disabled

2. **T74.2:** Add tests and metrics for consensus-dag in isolation
   - Port existing tests from backup
   - Add unit tests for `OrderingEngine` determinism
   - Verify metrics registration works
   - Test `DagStore` equivocation detection

### Phase T75.x: Shadow DAG (Orders but Doesn't Commit)

**Goal:** Run DAG ordering alongside Hotstuff, comparing outputs.

3. **T75.1:** Wire shadow DAG path in node
   - Add `EEZO_CONSENSUS_MODE=dag-shadow` mode
   - Run `OrderingEngine` on DAG vertices
   - Log ordered bundles (don't commit)
   - Compare with Hotstuff-committed blocks

4. **T75.2:** Add shadow metrics and comparison
   - Track DAG round vs Hotstuff height
   - Log divergences (different tx sets, ordering)
   - Add dashboard for monitoring

### Phase T76.x: Switch Source of Truth (Devnet)

**Goal:** DAG commits blocks; Hotstuff is disabled.

5. **T76.1:** Implement DAG commit path
   - Replace `CoreRunnerHandle` with `DagConsensusRunner`
   - Wire `ExecutorShim` to real executor
   - Implement DAG persistence

6. **T76.2:** Devnet testing
   - Deploy with `EEZO_CONSENSUS_MODE=dag`
   - Monitor stability and performance
   - Test failure scenarios (node restart, equivocation)

7. **T76.3:** Rollback mechanism
   - Add `EEZO_CONSENSUS_FALLBACK=hotstuff` for quick rollback
   - Test switching between modes

### Phase T77.x+: Bridge/Light Client Update

**Goal:** Update bridge to trust DAG headers instead of Hotstuff QC.

8. **T77.1:** Update block header format
   - Add DAG metadata to header (round, vertex IDs)
   - Maintain backward compatibility with version field

9. **T77.2:** Update light client contract
   - Accept DAG-style finality proofs
   - Support both Hotstuff QC and DAG proofs during transition

10. **T77.3:** Update relay
    - Submit DAG headers to L1
    - Handle transition period

---

## 5. Constraints & Compatibility

### 5.1 No Breaking Changes To

| Component | Constraint |
|-----------|------------|
| Light client contract | Header format must be versioned if changed |
| Prover/relay interfaces | Maintain SSZ compatibility |
| Persistence schema | Additive changes only (new tables) |
| Executor trait | DAG uses existing `Executor` via shim |

### 5.2 Feature Flag Strategy

```toml
[features]
default = []

# DAG consensus (can be built but not used by default)
dag-consensus = ["dep:consensus-dag"]

# STM executor (already exists)
stm-exec = []
```

**Toggle behavior:**

```rust
match std::env::var("EEZO_CONSENSUS_MODE") {
    "dag" if cfg!(feature = "dag-consensus") => run_dag_consensus(),
    "dag-shadow" if cfg!(feature = "dag-consensus") => run_dag_shadow(),
    "hotstuff" | _ => run_hotstuff_consensus(),
}
```

### 5.3 Executor Independence

The executor layer (Single/Parallel/STM) remains **independent of consensus**:

- DAG produces `OrderedBundle` with ordered transactions
- `ExecutorShim` converts to `ExecInput` for the executor
- Executor sees the same interface regardless of consensus backend

### 5.4 Avoiding Double-Commit Bugs

**Risk:** Both DAG and Hotstuff committing the same transactions.

**Mitigation:**
1. **Mutual exclusion:** Only one consensus mode active at a time
2. **Mempool coordination:** DAG uses peek (non-destructive); commits drain
3. **Shadow mode:** DAG-shadow only logs, never commits
4. **Height validation:** Persistence rejects duplicate heights

### 5.5 Rollback Strategy

If DAG misbehaves:

1. Stop nodes
2. Set `EEZO_CONSENSUS_MODE=hotstuff`
3. (Optional) Replay from last checkpoint if DAG corrupted state
4. Restart nodes

---

## 6. T74.x Task Breakdown

### T74.1: Create crates/consensus-dag

**Scope:**
- [ ] Copy `backup/consensus-dag/` to `crates/consensus-dag/`
- [ ] Update `Cargo.toml` paths for `eezo-ledger` dependency
- [ ] Add `dag-consensus` feature to `crates/node/Cargo.toml`
- [ ] Ensure `cargo check --all-features` passes
- [ ] Ensure `cargo check` (without dag-consensus) still passes

**Acceptance:** `cargo check` passes with and without `dag-consensus` feature.

### T74.2: Add Tests and Metrics

**Scope:**
- [ ] Port `store.rs` tests for equivocation detection
- [ ] Add `order.rs` determinism tests (same input → same output)
- [ ] Test `builder.rs` with mock mempool
- [ ] Verify metrics registration in `metrics.rs`
- [ ] Add integration test: vertices → ordering → bundle

**Acceptance:** All new tests pass, metrics are observable.

### T74.3: Wire Shadow DAG Path

**Scope:**
- [ ] Add `ConsensusMode::DagShadow` variant
- [ ] Create `DagConsensusRunner` with shadow-only mode
- [ ] Wire `OrderingEngine` to DAG sidecar's `DagStore`
- [ ] Log ordered bundles without committing
- [ ] Add comparison metrics (DAG round vs Hotstuff height)

**Acceptance:** Running with `EEZO_CONSENSUS_MODE=dag-shadow` logs DAG bundles while Hotstuff commits blocks normally.

### T74.4+: Full DAG Commit (Future)

**Scope:**
- [ ] Implement `ExecutorShim` → real executor handoff
- [ ] Add DAG persistence tables
- [ ] Wire DAG commit path in `DagConsensusRunner`
- [ ] Test in devnet with `EEZO_CONSENSUS_MODE=dag`
- [ ] Monitor and iterate

**Acceptance:** Devnet runs stably with DAG as sole consensus source.

---

## Summary

This document provides a roadmap for evolving from Hotstuff to DAG consensus:

1. **Current state:** Hotstuff commits blocks; DAG is a debug sidecar
2. **Target:** DAG as the production consensus layer
3. **Migration:** Phased approach with shadow mode, devnet testing, and bridge updates
4. **Constraints:** No breaking changes to light client, persistence, or executor

The T74.x tasks create a foundation by bringing `consensus-dag` back as a proper crate, testing it in isolation, and then wiring it into the node as a shadow mode before taking over commit authority.
