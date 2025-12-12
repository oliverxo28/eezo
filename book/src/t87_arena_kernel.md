# T87.4 — Arena-Indexed STM Kernel

> **Task Family:** T87.4–T87.6  
> **Status:** In Progress  
> **Scope:** Memory layout optimization for STM executor — no changes to consensus, wire formats, or PQ semantics

---

## Overview

The Arena-Indexed STM Kernel is a performance optimization that improves cache locality in the STM executor's hot path. Instead of repeatedly looking up accounts by Address in HashMaps, we:

1. At block start, pre-load all touched accounts into a contiguous `Vec<Account>` (the "Arena")
2. Map each logical `Address` to a `u32` index into this arena
3. Execute transactions using indices instead of repeated HashMap lookups

This transforms the hot path from random pointer chasing (cache-unfriendly) into mostly linear array processing (cache-friendly).

---

## Table of Contents

- [Design Rationale](#design-rationale)
- [Current Data Flow](#current-data-flow)
- [Arena-Based Data Flow](#arena-based-data-flow)
- [Key Types](#key-types)
- [Configuration](#configuration)
- [Invariants](#invariants)
- [Metrics](#metrics)
- [Usage](#usage)

---

## Design Rationale

### Problem: HashMap Lookups in Hot Path

The current STM executor performs multiple HashMap lookups per transaction:

```rust
// Current hot path (simplified):
let sender_acc = overlay.get_account(&sender, &base);  // HashMap lookup
let receiver_acc = overlay.get_account(&receiver, &base);  // HashMap lookup
// ... execute ...
overlay.put_account(sender, new_sender);  // HashMap insert
overlay.put_account(receiver, new_receiver);  // HashMap insert
```

For a block with 500 transactions, this means ~2000 HashMap operations, each involving:
- Hash computation (fast, but adds up)
- Random memory access (cache-unfriendly)
- Potential hash collision handling

### Solution: Index-Based Access

With an arena, we resolve addresses to indices once at block start:

```rust
// Arena-based hot path (simplified):
let sender_idx = arena.index_of(&sender);  // Done once at block start
let receiver_idx = arena.index_of(&receiver);  // Done once at block start

// During execution:
let sender_acc = arena.account(sender_idx);  // Array index: O(1), cache-friendly
let receiver_acc = arena.account(receiver_idx);  // Array index: O(1), cache-friendly
```

---

## Current Data Flow

```
mempool → [analyzed_tx with sender, conflict metadata]
                      ↓
               STM wave builder
                      ↓
           [parallel speculative execution]
                      ↓
         BlockOverlay.get_account(addr, base)  ← HashMap lookup
                      ↓
         compute new_sender, new_receiver
                      ↓
         BlockOverlay.put_account(addr, acct)  ← HashMap insert
                      ↓
               conflict detection
                      ↓
            apply to base state
```

### Hot Path Bottlenecks

1. **BlockOverlay.get_account()**: HashMap lookup + fallback to base (another HashMap lookup)
2. **BlockOverlay.put_account()**: HashMap insert
3. **TxContext read/write sets**: HashSet operations for conflict detection

---

## Arena-Based Data Flow

```
mempool → [analyzed_tx with sender, conflict metadata]
                      ↓
               STM wave builder
                      ↓
         AccountArena::from_snapshot_and_write_set()
              ↓ (builds Vec<Account> + Address→u32 map)
         ArenaTxContext with (sender_idx, receiver_idx)
                      ↓
           [parallel speculative execution]
                      ↓
         arena.account(sender_idx)  ← Vec index: O(1)
                      ↓
         compute new_sender, new_receiver
                      ↓
         arena.account_mut(sender_idx) = new_sender  ← Vec index: O(1)
                      ↓
               conflict detection (index-based)
                      ↓
         arena.to_block_write_set() → apply to base state
```

### Key Benefits

1. **Cache Locality**: All touched accounts are contiguous in memory
2. **Predictable Access**: Vec indexing is O(1) with no hashing overhead
3. **Reduced Allocations**: No per-lookup allocations in hot path
4. **SIMD Potential**: Contiguous data enables future SIMD optimizations

---

## Key Types

### AccountArena

```rust
/// A contiguous, cache-friendly collection of accounts for a single block.
///
/// All accounts that may be touched during block execution are loaded once
/// at block start. Transactions access accounts by index (u32) rather than
/// by Address, avoiding repeated HashMap lookups in the hot path.
pub struct AccountArena {
    /// Contiguous storage for all touched accounts.
    /// Index 0 is reserved for the "supply" pseudo-account (for fee tracking).
    accounts: Vec<Account>,
    
    /// Maps Address → index in the accounts vector.
    /// Only used during arena construction and write-back.
    index_map: HashMap<Address, u32>,
    
    /// Total fees accumulated during block execution.
    /// Applied to Supply at block commit.
    total_fees: u128,
}
```

### ArenaTxContext

```rust
/// Transaction execution context using arena indices instead of addresses.
///
/// All address lookups are resolved to indices at block start.
/// During execution, all state access is done via Vec indexing.
pub struct ArenaTxContext {
    /// Index in block's tx list
    tx_idx: usize,
    /// Sender's index in the arena
    sender_idx: u32,
    /// Receiver's index in the arena (or None for special cases)
    receiver_idx: Option<u32>,
    /// Current retry attempt
    attempt: u16,
    /// Status of this transaction
    status: TxStatus,
}
```

### StmKernelMode

```rust
/// Selects which STM kernel implementation to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StmKernelMode {
    /// Use the existing HashMap-based implementation.
    /// This is the default and matches pre-T87.4 behavior exactly.
    #[default]
    Legacy,
    
    /// Use the arena-indexed implementation for better cache locality.
    /// Opt-in via EEZO_STM_KERNEL_MODE=arena.
    Arena,
}
```

---

## Configuration

### Environment Variables

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `EEZO_STM_KERNEL_MODE` | `legacy`, `arena` | `legacy` | Select STM kernel implementation |

### Example Usage

```bash
# Enable arena kernel
export EEZO_STM_KERNEL_MODE=arena

# Combined with T84.5 devnet profile
source devnet_tps.env
export EEZO_STM_KERNEL_MODE=arena
./scripts/devnet_dag_primary.sh
```

---

## Invariants

The arena kernel MUST preserve these invariants:

1. **Determinism**: Same input blocks produce identical results and state roots
2. **Equivalence**: Legacy and Arena kernels produce bit-for-bit identical results
3. **Semantics**: No changes to ledger rules, nonce/balance semantics
4. **Wire Format**: No changes to block/header/tx wire formats
5. **PQ Signatures**: No changes to signature scheme or validity rules

### Verification

Equivalence is tested by:
1. Running the same block sequence through both kernels
2. Comparing final balances for all touched accounts
3. Comparing final state roots
4. Asserting exact equality

---

## Metrics

### New Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_exec_stm_kernel_mode` | Gauge (labeled) | Current kernel mode: 0=legacy, 1=arena |
| `eezo_exec_stm_arena_accounts_total` | Counter | Accounts loaded into arena per block |
| `eezo_exec_stm_arena_build_seconds` | Histogram | Time to build arena per block |

### Comparison Workflow

```bash
# Run with legacy kernel, capture TPS
export EEZO_STM_KERNEL_MODE=legacy
./scripts/tps_benchmark.sh --duration 30 --warmup 10 --verbose
# Result: TPS ≈ X

# Run with arena kernel, capture TPS  
export EEZO_STM_KERNEL_MODE=arena
./scripts/tps_benchmark.sh --duration 30 --warmup 10 --verbose
# Result: TPS ≈ Y

# Compare metrics
curl -s http://127.0.0.1:9898/metrics | grep eezo_exec_stm
```

---

## Usage

### Testing Arena Kernel

```bash
# Run with arena kernel on devnet
source devnet_tps.env
export EEZO_STM_KERNEL_MODE=arena
./scripts/devnet_dag_primary.sh

# In another terminal, run multi-sender spam
./scripts/spam_multi_senders.sh \
  --senders 32 \
  --per-sender 200 \
  --hot-receivers 32 \
  --pattern disjoint \
  --node http://127.0.0.1:8080

# Observe metrics
curl -s http://127.0.0.1:9898/metrics | grep eezo_exec_stm_arena
```

### Disabling (if issues occur)

```bash
# Revert to legacy kernel
export EEZO_STM_KERNEL_MODE=legacy
# Or simply unset (legacy is default)
unset EEZO_STM_KERNEL_MODE
```

---

## Implementation Notes

### Phase 1: AccountArena (T87.4)

The arena module lives in `crates/ledger/src/stm_arena.rs` to keep it close to the Account type.

Key methods:
- `from_snapshot_and_write_set()`: Loads touched accounts from base + overlay
- `index_of(addr)`: Returns the u32 index for an address (or inserts new)
- `account(idx)`: Returns &Account at index
- `account_mut(idx)`: Returns &mut Account at index
- `to_block_write_set()`: Exports changes back to a BlockWriteSet

### Phase 2: ArenaTxContext (T87.5)

Located in `crates/node/src/executor/stm.rs` alongside existing TxContext.

Conversion:
```rust
// At block start, for each AnalyzedTx:
let arena_ctx = ArenaTxContext::from_analyzed(&analyzed, &arena);
```

### Phase 3: Integration (T87.6)

The `StmExecutor::execute_block()` method checks the kernel mode:

```rust
match self.config.kernel_mode {
    StmKernelMode::Legacy => self.execute_stm_with_overlay(...),
    StmKernelMode::Arena => self.execute_stm_with_arena(...),
}
```

---

## Related Documentation

- [T82.0: TPS Baseline](t82_tps_baseline.md)
- [T84.5: Performance Plateau](t84_plateau.md)
- [T87.x: Deep Performance Pass](t87_deep_perf.md)
