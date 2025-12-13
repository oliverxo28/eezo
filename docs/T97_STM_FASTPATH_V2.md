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
2. Use a lightweight `TxHandle` (just a `usize` index) instead of Arc
3. The STM executor looks up transaction data via index when needed

```rust
/// Lightweight transaction handle - just an index into the canonical tx list.
pub type TxHandle = usize;

pub struct AnalyzedTx {
    pub tx_handle: TxHandle,  // Index into txs slice
    pub tx_idx: usize,
    pub sender: Address,
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

### New Metric: eezo_stm_tx_arc_clones_total
Counter tracking Arc clones in the STM execution path. After this refactor, should be zero or near-zero during normal operation.

## Performance Targets

| Metric | Before | Target | 
|--------|--------|--------|
| STM per tx (fat-block) | ~0.88 ms/tx | ≤0.7 ms/tx |
| Fat-block TPS (5000 tx) | ~192 TPS | ≥250 TPS |
| Devnet burst TPS | ~330-360 TPS | ≥380 TPS |
| Arc clones per block | O(n) | O(1) or zero |

## Testing

1. All existing STM tests pass
2. Fastpath on/off yields identical final ledger state
3. Determinism preserved across runs
