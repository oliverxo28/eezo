# T97.0 — STM Fastpath v2: Arc-Free Tx Handles & Cheaper Account Copies

## Summary

This document describes the T97.0 optimization to push CPU TPS higher by:
1. Eliminating unnecessary `Arc` cloning for transactions in the STM hot loop
2. Reducing heavy account cloning/copying where safe

## Hot-Path Audit

### Arc<SignedTx> Cloning Locations

| Location | Path | Frequency | Essential? |
|----------|------|-----------|------------|
| `analyze_tx` | Creates `Arc::new(tx.clone())` | Per tx | **Redundant** - can use index |
| `analyze_shared_tx` | Creates `Arc::new(shared_tx.signed_tx().clone())` | Per tx | **Redundant** - can use index |
| Building committed txs | `txs[idx].clone()` at block end | Per committed tx | Essential for block output |
| `execute_tx_with_arena` | Takes `&Arc<SignedTx>` | Per tx per wave | Reference only, no clone |

### Account Cloning Locations

| Location | Path | Frequency | Essential? |
|----------|------|-----------|------------|
| `execute_tx_with_overlay` | Clones sender/receiver for `SpeculativeResult` | Per tx per wave | Essential for rollback |
| `execute_tx_with_arena` | Clones accounts for `ArenaSpeculativeResult` | Per tx per wave | Essential for general path |
| `BlockOverlay::get_account` | `.cloned()` on HashMap lookup | Per read | Can be optimized |
| Arena snapshots | `arena.snapshot()` | Per wave | Essential for speculative exec |

## Design: Arc-Free Transaction Handles

### Problem
The current `AnalyzedTx` struct stores `Arc<SignedTx>` per transaction:
```rust
pub struct AnalyzedTx {
    pub tx: Arc<SignedTx>,  // Cloned in analyze_tx()
    ...
}
```

This means every transaction analysis creates a new Arc, and every access potentially increments/decrements the refcount.

### Solution
1. Store transactions in a single canonical `Vec<SignedTx>` owned by the block execution context
2. Use `tx_idx` (a `usize` index) instead of Arc - the index acts as a handle
3. Cache the essential transaction fields directly in `AnalyzedTx`

```rust
pub struct AnalyzedTx {
    pub tx_idx: usize,              // Index into txs slice (acts as handle)
    pub sender: Address,            // Cached sender address
    pub receiver: Address,          // Cached receiver address
    pub amount: u128,               // Cached amount
    pub fee: u128,                  // Cached fee
    pub nonce: u64,                 // Cached nonce
    pub meta: ConflictMetadata,
    pub kind: AnalyzedTxKind,
    pub sender_arena_idx: Option<u32>,
    pub receiver_arena_idx: Option<u32>,
}
```

### Benefits
- Zero Arc clones in the analysis phase
- No refcount overhead in the hot path
- Same semantics - just references instead of owned copies

## Design: Cheaper Account Copies

### Problem
In the simple fastpath, every successful transfer still requires:
1. Reading sender account from arena
2. Computing new balance/nonce
3. Writing back to arena

This is already fairly optimized, but we can avoid some intermediate copies.

### Optimizations
1. **In-place arena updates**: The fastpath already modifies accounts directly in the arena without creating intermediate `SpeculativeResult` structs
2. **Skip overlay for fastpath**: Fastpath writes directly to arena, avoiding the BlockOverlay HashMap overhead

The current implementation is already quite optimized for the fastpath case.

## Metrics

### New Metrics

1. **eezo_stm_tx_arc_clones_total** - Counter tracking Arc clones in the STM execution path. After this refactor, should be zero during normal operation since we no longer create Arc<SignedTx> in AnalyzedTx.

2. **eezo_stm_account_clones_total** - Counter tracking Account struct clones during speculative execution. These clones remain essential for correctness (rollback semantics).

## Performance Expectations

| Metric | Before | After T97.0 |
|--------|--------|-------------|
| Arc<SignedTx> clones per block | O(n) | 0 |
| Account clones per wave | 2 per tx | 2 per tx (unchanged, required) |
| HashMap lookups per tx | O(n) linear search | O(1) via analyzed_map |

Expected improvements:
- STM per tx: ~0.88 ms/tx → target ≤0.7 ms/tx
- Fat-block TPS: ~192 TPS → target ≥250 TPS  
- Devnet burst TPS: ~330-360 TPS → target ≥380 TPS

## Implementation Summary

### Changes Made

1. **AnalyzedTx struct refactored**:
   - Removed `tx: Arc<SignedTx>` field
   - Added `receiver: Address`, `amount: u128`, `fee: u128`, `nonce: u64`
   - `tx_idx` serves as a lightweight handle to the canonical tx list

2. **analyze_tx() and analyze_shared_tx() optimized**:
   - No longer creates Arc clones
   - Caches essential fields directly from transaction core

3. **execute_tx_with_overlay() updated**:
   - Uses cached fields from AnalyzedTx
   - Tracks account clones via metrics

4. **execute_simple_fastpath_wave() updated**:
   - Uses cached fields from AnalyzedTx
   - No Arc access in hot path

5. **execute_tx_with_arena() updated**:
   - Takes `&AnalyzedTx` instead of `&Arc<SignedTx>`
   - Uses cached fields for validation and execution

## Testing

1. All existing STM tests pass
2. Fastpath on/off yields identical final ledger state
3. Determinism preserved across runs

---

# T97.1 — Vec-Based Index Optimization (Postmortem)

## Problem Identified

After T97.0, while `eezo_stm_tx_arc_clones_total = 0` confirmed Arc cloning was eliminated,
end-to-end TPS did not improve as expected:

- Fat-block harness: ~190 TPS, STM ~0.88 ms/tx (good)
- Quick TPS devnet: ~87-139 TPS, STM ~1.25-1.35 ms/tx (worse)

The discrepancy was caused by:

1. **HashMap overhead in hot loops**: `analyzed_map: HashMap<usize, &AnalyzedTx>` and 
   `idx_to_arena: HashMap<usize, usize>` were being looked up for every tx in every wave.
   Hash computation adds 30-50 ns per lookup.

2. **Per-wave allocations**: Each wave allocated a new `Vec<(usize, u16)>` for pending txs
   instead of reusing pre-allocated storage.

3. **Redundant iterations**: After fastpath execution, a full scan of `arena_contexts`
   was needed to collect committed txs, plus another scan to count pending.

## Root Cause Analysis

In `execute_stm_with_arena()`, for a block with N txs and W waves:

- **Before T97.1**: ~2N HashMap lookups per wave = 2NW total lookups
- **Before T97.1**: W Vec allocations for pending list
- **Before T97.1**: 2NW iterations to scan contexts after each wave

For quick_tps with 2000 txs and ~10 waves, this was:
- 40,000+ HashMap lookups (40,000 × 40ns = ~1.6ms)
- 10 Vec allocations
- ~40,000 redundant iterations

## Solution (T97.1)

1. **Vec-based index maps**: Replace `HashMap<usize, &AnalyzedTx>` and `HashMap<usize, usize>`
   with `Vec<Option<usize>>` for O(1) array indexing without hash computation.

2. **Pre-allocated pending Vec**: Allocate `pending: Vec<(usize, u16)>` once per block with
   capacity N, then `clear()` and reuse each wave.

3. **Incremental pending tracking**: Track `pending_count` as a counter, decrement on commit,
   avoiding full scans.

4. **execute_simple_fastpath_wave_v2()**: Optimized fastpath using Vec-based lookups.

5. **detect_conflicts_arena_v2()**: Optimized conflict detection using Vec-based lookups.

## Key Changes

```rust
// Before: HashMap lookup (hash + probe)
let atx = analyzed_map.get(&tx_idx)?;

// After: Vec index (direct array access)
let atx = analyzed_vec[tx_idx].map(|i| &analyzed_txs[i]);
```

## Expected Improvements

| Metric | Before T97.1 | Target T97.1 |
|--------|--------------|--------------|
| Quick TPS (single) | ~87 TPS | ≥160 TPS |
| Quick TPS (multi) | ~139 TPS | ≥200 TPS |
| STM per tx | 1.25-1.35 ms | ≤1.0 ms |

## Metrics to Monitor

When debugging TPS issues, check these metrics:

```bash
# Core execution time
curl -s http://127.0.0.1:9898/metrics | grep -E "eezo_exec_stm_time_seconds|eezo_stm_simple_time"

# Fastpath effectiveness
curl -s http://127.0.0.1:9898/metrics | grep -E "eezo_stm_simple_(candidate|fastpath|fallback)_total"

# Wave overhead
curl -s http://127.0.0.1:9898/metrics | grep -E "eezo_exec_stm_waves"

# Arc clones (should be 0 post-T97.0)
curl -s http://127.0.0.1:9898/metrics | grep "eezo_stm_tx_arc_clones_total"
```

A healthy system shows:
- `fastpath_total / candidate_total > 40%` (good conflict avoidance)
- `waves_total / blocks_total < 3` (few retries needed)
- `stm_tx_arc_clones_total = 0` (no Arc cloning)

## Testing

1. All 66 STM unit tests pass
2. All 7 executor equivalence tests pass
3. Fastpath on/off produces identical final ledger state
4. Determinism preserved across runs
