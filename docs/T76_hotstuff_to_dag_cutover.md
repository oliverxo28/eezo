# T76.0: Hotstuff → DAG Consensus Cutover Plan

**Status**: Design Document  
**Version**: v1.0.0  
**Created**: 2025-12-02  
**Author**: EEZO Core Team  

---

## Executive Summary

This document describes the phased migration from Hotstuff-driven block production to DAG-driven consensus in the EEZO node. The goal is to transition the canonical ordering layer from Hotstuff to DAG while:

1. **Preserving block/tx semantics** — no history rewrite, identical on-chain invariants
2. **Keeping the STM executor** as the main execution engine
3. **Avoiding downtime** and minimizing implementation risk
4. **Enabling rollback** at any phase if issues arise

---

## Table of Contents

1. [Current Architecture Snapshot](#1-current-architecture-snapshot)
2. [Target Architecture (DAG as Source of Truth)](#2-target-architecture-dag-as-source-of-truth)
3. [Migration Strategy & Safety](#3-migration-strategy--safety)
4. [Configuration & Feature Flags](#4-configuration--feature-flags)
5. [Performance Targets and Constraints](#5-performance-targets-and-constraints)
6. [T76.x Roadmap](#6-t76x-roadmap)
7. [Appendix: Metrics Reference](#appendix-metrics-reference)

---

## 1. Current Architecture Snapshot

### 1.1 Block Ordering: Hotstuff + CoreRunnerHandle

Today, block production is driven by `CoreRunnerHandle` in `crates/node/src/consensus_runner.rs`:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CoreRunnerHandle                             │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────────┐   │
│  │  SingleNode   │───▶│   Executor    │───▶│  Block Applied    │   │
│  │  (Hotstuff)   │    │  (STM/Para)   │    │  (height bumped)  │   │
│  └───────────────┘    └───────────────┘    └───────────────────┘   │
│         │                                                            │
│         ▼                                                            │
│  ┌───────────────┐                                                   │
│  │   Mempool     │ ◀── drain_for_block() ─────────────────────────  │
│  │ (SharedMempool)                                                   │
│  └───────────────┘                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

**Key components:**

| Component | Location | Role |
|-----------|----------|------|
| `CoreRunnerHandle` | `consensus_runner.rs` | Main consensus loop, owns `SingleNode` |
| `SingleNode` | `eezo-ledger` | Hotstuff consensus state, mempool, accounts |
| `run_one_slot()` (retired) | `eezo-ledger` | Original Hotstuff slot runner (now bypassed) |
| `Executor` trait | `crates/node/src/executor/` | Block execution abstraction |

**Block production flow (current):**

1. `CoreRunnerHandle::spawn()` starts an async loop on a fixed tick (`tick_ms`)
2. Each tick: collect txs from mempool via `drain_for_block(block_byte_budget)`
3. Build `ExecInput` with txs and `next_height`
4. Call `executor.execute_block(&mut node, exec_input)`
5. On success: `apply_block()` updates accounts, supply, height, prev_hash
6. Emit metrics, checkpoints, and (if `dag-consensus` feature) shadow DAG summary

### 1.2 DAG Pieces Today

#### 1.2.1 dag_runner.rs — Tx Sampling & Dry-Run

`DagRunnerHandle` in `crates/node/src/dag_runner.rs` provides:

- **DAG vertex model**: `DagVertex`, `DagVertexMeta`, `DagPayload`
- **In-memory DAG store**: `DagStore` with tips, parents, round/height tracking
- **Shadow payload**: `dag_shadow_payload_from_mempool()` — read-only tx sampling
- **Block preview**: `block_preview()` — decode txs for debug endpoint
- **Dry-run execution**: `block_dry_run()` — sandbox execution without commit
- **Shadow block template**: `block_template_shadow()` — header-like summary
- **Template gate**: `evaluate_template_gate()` — quality gate for T69.0

**Key env controls:**
- `EEZO_BLOCK_TX_SOURCE={mempool, dag}` — select tx source
- `EEZO_DAG_TEMPLATE_POLICY={off, clean_only, tolerate_partial}` — gate policy

#### 1.2.2 consensus-dag Crate + dag_consensus_runner.rs (Shadow Only)

`crates/consensus-dag` provides a full DAG consensus implementation:

- `DagConsensusHandle` — public façade for submitting payloads and ordering
- `DagStore` — vertex storage with GC
- `OrderingEngine` — Bullshark-style deterministic ordering
- `DagPayload`, `OrderedBatch` — data types for consensus

`dag_consensus_runner.rs` wires this as a **shadow mode**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DagConsensusShadowRunner                          │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────────┐   │
│  │ ShadowBlock   │───▶│ DagConsensus  │───▶│  Ordered Batch    │   │
│  │ Summary (recv)│    │  Handle       │    │  (log/metrics)    │   │
│  └───────────────┘    └───────────────┘    └───────────────────────┘ │
│         ▲                                                            │
│         │ mpsc::channel                                              │
│         │                                                            │
│  [CoreRunnerHandle] ──────────────────────────────────────────────  │
└─────────────────────────────────────────────────────────────────────┘
```

**Shadow mode behavior:**
- Receives `ShadowBlockSummary` after each canonical commit
- Submits to `DagConsensusHandle` as a payload
- Polls for ordered batches (for metrics/logging only)
- Tracks sync status via `DagConsensusTracker`

**Key env controls:**
- `EEZO_DAG_CONSENSUS_MODE={off, shadow}` — enable shadow mode

**Feature flag:**
- `dag-consensus` — compiles in the shadow DAG runner

### 1.3 STM Executor

The STM (Software Transactional Memory) executor in `crates/node/src/executor/stm.rs`:

- Implements `Executor` trait
- Uses `MvHashMap` for multi-version concurrent state
- Executes transactions in waves with conflict detection/retry
- Configurable via `EEZO_EXECUTOR_MODE=stm`

**Key env controls:**
- `EEZO_EXECUTOR_MODE={single, parallel, stm}` — executor selection
- `EEZO_EXECUTOR_THREADS` — thread count
- `EEZO_STM_MAX_RETRIES` — retry limit for conflicts
- `EEZO_STM_WAVE_TIMEOUT_MS` — wave timeout

**Current performance (observed):**
- ~160–190 TPS on 1000-tx spam with 1s blocks on laptop
- STM enables higher throughput vs sequential execution

### 1.4 Current Metrics (Shadow DAG Observations)

Under load with shadow DAG enabled:

| Metric | Observed Value | Meaning |
|--------|----------------|---------|
| `eezo_dag_shadow_in_sync` | 1 | DAG shadow matches canonical |
| `eezo_dag_shadow_lag_blocks` | ≈1 | At most 1 block behind |
| `eezo_dag_shadow_hash_mismatch_total` | 0 | No content divergence |

This confirms the shadow DAG is tracking canonical correctly.

---

## 2. Target Architecture (DAG as Source of Truth)

### 2.1 Overview

In the target architecture, DAG becomes the canonical ordering layer:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      CoreRunnerHandle (Updated)                      │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                  DagConsensusHandle                            │  │
│  │  ┌─────────┐   ┌─────────────┐   ┌──────────────────────┐     │  │
│  │  │ Submit  │──▶│   Order     │──▶│  OrderedBatch        │     │  │
│  │  │ Payload │   │   Engine    │   │  (blocks + tx order) │     │  │
│  │  └─────────┘   └─────────────┘   └──────────────────────┘     │  │
│  └───────────────────────────────────────────────────────────────┘  │
│         │                                      │                     │
│         ▼                                      ▼                     │
│  ┌───────────────┐                    ┌───────────────────┐         │
│  │   Mempool     │                    │   STM Executor    │         │
│  │ (tx source)   │                    │  (ExecInput)      │         │
│  └───────────────┘                    └───────────────────┘         │
│                                                │                     │
│                                                ▼                     │
│                                       ┌───────────────────┐         │
│                                       │  Block Applied    │         │
│                                       │  (canonical state)│         │
│                                       └───────────────────┘         │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Block Heights/Rounds

**Current (Hotstuff):**
- `node.height` monotonically increases on each commit
- `prev_hash` chains blocks together
- No explicit "round" concept (implicit: 1 round = 1 block)

**Target (DAG):**
- **DAG Round**: Consensus layer concept, may not map 1:1 to blocks
- **Block Height**: Continues as the canonical ledger height
- **Mapping**: Each `OrderedBatch` from DAG produces one or more block(s)

**Height derivation:**
```rust
// In CoreRunnerHandle, after receiving OrderedBatch from DAG
let ordered_batch = dag_handle.try_next_ordered_batch()?;
let next_height = current_height + 1;  // Still incremental

// The DAG round is for internal consensus bookkeeping
// Block height remains the canonical chain pointer
```

### 2.3 OrderedBatch → ExecInput → BlockHeader

The transition layer converts DAG output to executor input:

```rust
// OrderedBatch from DagConsensusHandle
struct OrderedBatch {
    round: u64,
    bundles: Vec<OrderedBundle>,
}

// Transform to ExecInput (Result-returning for proper error handling)
async fn ordered_batch_to_exec_input(
    batch: &OrderedBatch,
    mempool: &SharedMempool,
    height: u64,
) -> Result<ExecInput, DagConversionError> {
    // 1. Extract tx hashes from ordered bundles
    let tx_hashes: Vec<[u8; 32]> = batch.bundles
        .iter()
        .flat_map(|b| extract_tx_hashes(&b.vertices))
        .collect();
    
    if tx_hashes.is_empty() {
        log::debug!("dag: empty batch for height={}", height);
        return Ok(ExecInput::new(vec![], height));
    }
    
    // 2. Fetch full tx bytes from mempool
    let txs = mempool.get_bytes_for_hashes(&tx_hashes).await;
    
    // 3. Parse into SignedTx, logging parse failures
    let signed_txs: Vec<SignedTx> = txs
        .into_iter()
        .filter_map(|(hash, bytes)| {
            match parse_signed_tx(&bytes) {
                Some(tx) => Some(tx),
                None => {
                    log::warn!("dag: failed to parse tx 0x{}", hex::encode(&hash[..4]));
                    None
                }
            }
        })
        .collect();
    
    Ok(ExecInput::new(signed_txs, height))
}
```

### 2.4 On-Chain Invariants with STM

The STM executor preserves all ledger invariants:

| Invariant | Enforcement |
|-----------|-------------|
| **Nonce monotonicity** | `validate_tx_stateful()` checks `tx.nonce == account.nonce` |
| **Balance sufficiency** | `validate_tx_stateful()` checks `balance >= amount + fee` |
| **Supply conservation** | `apply_tx()` debits sender, credits recipient, accumulates fees |
| **State root** | Post-execution Merkle root (when eth-ssz enabled) |

STM's conflict detection ensures correct ordering even with concurrent execution:
- Read/write conflicts trigger retry
- Final commit order respects original tx ordering from DAG

### 2.5 Gradual Hotstuff De-scoping

The migration proceeds in phases, each with a rollback path:

#### Phase 1: Hybrid Mode ("Hotstuff still committing but DAG ordering")

```
┌──────────────────────────────────────────────────────────────────┐
│  EEZO_CONSENSUS_MODE=dag-hybrid                                   │
│                                                                   │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐        │
│  │ DAG Handle  │────▶│ Ordered     │────▶│ Hotstuff    │        │
│  │ (ordering)  │     │ Batch       │     │ (commit)    │        │
│  └─────────────┘     └─────────────┘     └─────────────┘        │
│                                                 │                 │
│                            ┌────────────────────┘                 │
│                            ▼                                      │
│                    ┌─────────────┐                               │
│                    │ STM Exec    │                               │
│                    └─────────────┘                               │
└──────────────────────────────────────────────────────────────────┘
```

- DAG orders transactions
- Hotstuff still holds commit authority (safety net)
- Metrics track divergence between DAG order and Hotstuff result

#### Phase 2: DAG Primary ("DAG ordering + STM execution + minimal commit layer")

```
┌──────────────────────────────────────────────────────────────────┐
│  EEZO_CONSENSUS_MODE=dag                                          │
│                                                                   │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐        │
│  │ DAG Handle  │────▶│ Ordered     │────▶│ Commit      │        │
│  │ (ordering)  │     │ Batch       │     │ (direct)    │        │
│  └─────────────┘     └─────────────┘     └─────────────┘        │
│                                                 │                 │
│                            ┌────────────────────┘                 │
│                            ▼                                      │
│                    ┌─────────────┐                               │
│                    │ STM Exec    │                               │
│                    └─────────────┘                               │
└──────────────────────────────────────────────────────────────────┘
```

- DAG is the only ordering authority
- Hotstuff commit logic replaced with direct state apply
- Hotstuff code still compiled but not active

#### Phase 3: DAG-Only ("Hotstuff fully removed")

- Hotstuff code behind `#[cfg(feature = "legacy-hotstuff")]`
- Default builds exclude Hotstuff
- Clean removal after devnet/testnet validation

---

## 3. Migration Strategy & Safety

### 3.1 Environment Progression

| Environment | Phase | Duration | Success Criteria |
|-------------|-------|----------|------------------|
| **Devnet** | Hybrid → DAG | 2 weeks | No hash mismatches, stable TPS |
| **Testnet** | Hybrid (1 week) → DAG | 3 weeks | Zero divergence, no rollbacks needed |
| **Mainnet** | Hybrid (2 weeks) → DAG | 4+ weeks | Operator sign-off, no incidents |

### 3.2 Shadow Mode as Guardrail

Before enabling any "real DAG" mode, shadow must prove stability:

**Metrics to watch:**

| Metric | Green Condition | Alert Threshold |
|--------|-----------------|-----------------|
| `eezo_dag_shadow_in_sync` | = 1 for N blocks | < 1 for > 10 blocks |
| `eezo_dag_shadow_lag_blocks` | ≤ 1 | > 5 |
| `eezo_dag_shadow_hash_mismatch_total` | = 0 | > 0 |
| `eezo_dag_template_would_apply_cleanly` | = 1 for > 95% blocks | < 90% |

**Pre-cutover checklist:**

1. Shadow mode running for ≥ 1000 blocks with no mismatches
2. DAG template dry-run success rate > 99%
3. No OOM or crash in shadow runner
4. Metrics exported and alerting configured

### 3.3 Rollback / Kill-Switch Strategy

Each phase has a defined rollback path:

#### Kill Switch: Environment Variable

```bash
# Immediate rollback to Hotstuff
export EEZO_CONSENSUS_MODE=hotstuff

# Or if in hybrid mode, disable DAG ordering
export EEZO_DAG_ORDERING_ENABLED=false
```

#### Rollback Procedure

1. **Detect**: Alert fires on mismatch metrics or operator observation
2. **Decide**: Ops team assesses severity (data corruption vs performance)
3. **Execute**: 
   - Set `EEZO_CONSENSUS_MODE=hotstuff`
   - Restart node (graceful via SIGTERM)
   - Node resumes with Hotstuff ordering from last committed height
4. **Verify**: Check `eezo_block_height` continues incrementing
5. **Investigate**: Post-mortem on why DAG mode failed

#### Data Integrity on Rollback

- DAG does not modify ledger state until executor commits
- Rollback to Hotstuff uses same state as DAG would have
- No ledger reorg needed; just change ordering source

---

## 4. Configuration & Feature Flags

### 4.1 Proposed Environment Variables

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `EEZO_CONSENSUS_MODE` | `hotstuff`, `dag-hybrid`, `dag` | `hotstuff` | Consensus ordering mode |
| `EEZO_DAG_CONSENSUS_MODE` | `off`, `shadow` | `off` | Shadow DAG mode (existing) |
| `EEZO_DAG_ORDERING_ENABLED` | `true`, `false` | `false` | Within hybrid, use DAG ordering |
| `EEZO_EXECUTOR_MODE` | `single`, `parallel`, `stm` | `parallel` | Executor selection (existing) |
| `EEZO_BLOCK_TX_SOURCE` | `mempool`, `dag` | `mempool` | Tx source (existing) |

### 4.2 Interaction Matrix

| CONSENSUS_MODE | DAG_CONSENSUS_MODE | DAG_ORDERING_ENABLED | Behavior |
|----------------|--------------------|----------------------|----------|
| `hotstuff` | `off` | (ignored) | Current default behavior |
| `hotstuff` | `shadow` | (ignored) | Hotstuff + shadow DAG metrics |
| `dag-hybrid` | (forced shadow) | `false` | DAG shadows, Hotstuff orders |
| `dag-hybrid` | (forced shadow) | `true` | DAG orders, Hotstuff commits |
| `dag` | (n/a) | (n/a) | DAG orders and commits directly |

### 4.3 Feature Flags

| Feature | Purpose | Phase |
|---------|---------|-------|
| `dag-consensus` | Compile shadow DAG runner | Phase 0 (now) |
| `dag-ordering` (new) | Enable DAG as ordering source | Phase 1 |
| `legacy-hotstuff` (new) | Keep Hotstuff code compiled | Phase 3+ |

### 4.4 Backward Compatibility

**Existing configs unchanged:**

- Unset `EEZO_CONSENSUS_MODE` → defaults to `hotstuff`
- Unset `EEZO_DAG_CONSENSUS_MODE` → defaults to `off`
- No behavioral change for operators who don't touch new envs

---

## 5. Performance Targets and Constraints

### 5.1 TPS Targets

| Phase | Mode | Target TPS (laptop) | Stretch TPS | Notes |
|-------|------|---------------------|-------------|-------|
| Current | Hotstuff + STM | 160-190 | 200 | Observed baseline |
| Hybrid | DAG order + Hotstuff commit | 150-180 | 200 | Slight overhead from dual path |
| DAG Primary | DAG order + direct commit | 300-500 | 800 | Reduced commit overhead |
| DAG + Optimized | DAG + batched commits | 500-800 | 1-2k | Pipeline ordering/execution |

**Realistic short-term target (laptop):** 500-800 TPS with DAG + STM  
**Stretch target:** 1-2k TPS with additional optimizations

### 5.2 GPU Hashing Integration

GPU hashing (`EEZO_NODE_GPU_HASH`) is orthogonal to consensus mode:

| Consensus Mode | GPU Hash Compatible | Notes |
|----------------|---------------------|-------|
| Hotstuff | ✓ | Current T71.x integration |
| DAG Hybrid | ✓ | No change to hash paths |
| DAG Primary | ✓ | DAG uses same block hashing |

Post-cutover GPU usage:
- **Node GPU hash**: Block body hashing for comparison/metrics
- **Prover GPU hash**: STARK proof generation (separate subsystem)

### 5.3 Avoiding Hotstuff Bottlenecks

DAG design explicitly avoids Hotstuff's sequential bottlenecks:

| Hotstuff Bottleneck | DAG Solution |
|---------------------|--------------|
| Leader-based proposal | Leaderless vertex broadcast |
| Sequential view changes | Parallel round advancement |
| Single commit path | Batched ordered commits |
| Lock on proposal | Lock-free payload submission |

Key metrics to confirm improvement:
- `eezo_block_e2e_latency_seconds` — should decrease
- `eezo_executor_tps_inferred` — should increase
- `eezo_dag_shadow_lag_blocks` — should stay ≤ 1

---

## 6. T76.x Roadmap

### T76.0: Design Document (This Document) ✓

**Scope:** Documentation only, no code changes  
**Deliverable:** `docs/T76_hotstuff_to_dag_cutover.md`  
**Acceptance:**
- [x] Document created with all required sections
- [x] Document reviewed for clarity and completeness
- [x] Build verification confirms no code changes introduced

---

### T76.1: Hybrid Mode — DAG Ordering with Hotstuff Commit

**Goal:** Let `CoreRunnerHandle` consume ordered batches from `DagConsensusHandle` while Hotstuff still commits.

**Scope:**
1. Add `EEZO_CONSENSUS_MODE=dag-hybrid` handling in `consensus_runner.rs`
2. When `dag-hybrid`:
   - Create/attach `DagConsensusHandle` (not just shadow runner)
   - In the tick loop, check for ordered batches before falling back to mempool
   - If batch available, convert to `ExecInput` and execute
   - Hotstuff's `run_one_slot()` path remains for commit semantics
3. Add metrics:
   - `eezo_dag_hybrid_batches_used_total`
   - `eezo_dag_hybrid_fallback_total`

**Gating:**
- `EEZO_DAG_ORDERING_ENABLED=true` must be set within hybrid mode
- Default is false (Hotstuff continues as before)

**Files modified:**
- `consensus_runner.rs` — add hybrid path
- `metrics.rs` — add hybrid metrics

**Tests:**
- Unit test: hybrid mode selects DAG batch when available
- Integration test: node runs in hybrid mode, blocks continue

**Rollback:** Set `EEZO_DAG_ORDERING_ENABLED=false` or `EEZO_CONSENSUS_MODE=hotstuff`

---

### T76.2: DAG Durability, Metrics, and Error Handling

**Goal:** Strengthen the DAG ordering path for production use.

**Scope:**
1. Add proper error handling in DAG → ExecInput conversion
2. Metrics for DAG ordering latency:
   - `eezo_dag_order_latency_seconds`
   - `eezo_dag_batch_size` histogram
3. Durability considerations:
   - WAL/checkpoint for DAG vertex store (if ordering must survive restart)
   - Or: accept that DAG state is transient, rebuilt from mempool
4. Logging improvements:
   - Structured logs for each ordered batch
   - Trace-level per-vertex logging

**Files modified:**
- `consensus-dag/src/handle.rs` — error types and metrics
- `consensus-dag/src/store.rs` — optional WAL
- `dag_consensus_runner.rs` — enhanced logging

---

### T76.3: DAG-Driven Height/Round Mapping

**Goal:** Introduce DAG-driven height/round mapping to `BlockHeader`.

**Scope:**
1. Define `DagBlockMeta` struct:
   ```rust
   struct DagBlockMeta {
       dag_round: u64,
       vertex_ids: Vec<VertexId>,
       // ... additional DAG provenance
   }
   ```
2. Extend `BlockHeader` (or create wrapper) to include DAG metadata
3. Update `apply_block()` to accept optional DAG metadata
4. Persist DAG metadata alongside block (when persistence enabled)

**Compatibility:**
- Legacy blocks without DAG metadata remain valid
- New blocks include DAG round for debugging/auditing

**Files modified:**
- `eezo-ledger/src/block.rs` — header extension
- `consensus_runner.rs` — populate DAG metadata
- `persistence.rs` — store/retrieve DAG metadata

---

### T76.4: Feature-Gate Hotstuff, Add Kill-Switches

**Goal:** Prepare for Hotstuff removal with clean feature gating.

**Scope:**
1. Introduce `#[cfg(feature = "legacy-hotstuff")]` around Hotstuff-specific code:
   - `SingleNode::run_one_slot()`
   - Hotstuff vote/QC handling in ledger
2. Add runtime kill-switch in `CoreRunnerHandle`:
   ```rust
   if env::var("EEZO_KILL_DAG_ORDERING").is_ok() {
       // Immediately fall back to Hotstuff/mempool
   }
   ```
3. Document rollback procedures in runbooks
4. Alert configuration for mismatch metrics

**Files modified:**
- `eezo-ledger/src/consensus.rs` — feature gate
- `consensus_runner.rs` — kill-switch
- `docs/runbooks/consensus_rollback.md` — new

---

### T76.5+: Remove Hotstuff Code Paths

**Goal:** Clean removal of Hotstuff after DAG-only is proven in devnet.

**Scope:**
1. Remove `run_one_slot()` and related Hotstuff consensus logic
2. Remove `SingleNode` Hotstuff-specific fields (or repurpose)
3. Update documentation to reflect DAG-only architecture
4. Deprecation notices for any external API changes

**Prerequisites:**
- DAG-only mode stable on devnet for ≥ 2 weeks
- No rollback incidents on testnet
- Operator sign-off

**Files modified:**
- `eezo-ledger/src/consensus.rs` — major refactor
- `consensus_runner.rs` — remove Hotstuff paths
- Multiple documentation files

---

## Appendix: Metrics Reference

### Existing Metrics (Shadow DAG)

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_dag_shadow_in_sync` | Gauge | 1 if shadow matches canonical |
| `eezo_dag_shadow_lag_blocks` | Gauge | Blocks behind canonical |
| `eezo_dag_shadow_hash_mismatch_total` | Counter | Content divergences |

### New Metrics (Proposed for T76.x)

| Metric | Type | Phase | Description |
|--------|------|-------|-------------|
| `eezo_dag_hybrid_batches_used_total` | Counter | T76.1 | Blocks built from DAG batches |
| `eezo_dag_hybrid_fallback_total` | Counter | T76.1 | Fallbacks to mempool |
| `eezo_dag_order_latency_seconds` | Histogram | T76.2 | Time to order a batch |
| `eezo_dag_batch_size` | Histogram | T76.2 | Vertices per batch |
| `eezo_consensus_mode_active` | Gauge | T76.1 | Current mode (0=hs, 1=hybrid, 2=dag) |

### Metrics Alerting Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| `eezo_dag_shadow_hash_mismatch_total` | > 0 | > 5 |
| `eezo_dag_shadow_lag_blocks` | > 2 | > 10 |
| `eezo_dag_hybrid_fallback_total` rate | > 10% | > 50% |

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-02 | EEZO Core Team | Initial design document |

---

*End of T76.0 Design Document*
