# T96: DAG Ordering Integration

This document describes the DAG transaction ordering layer implemented in T96.0/T96.1/T96.2.

## Overview

The DAG ordering layer sits between transaction collection (from DAG batches or mempool) and the STM executor. It reorders transactions to optimize for:

1. **Nonce contiguity**: Transactions from the same sender are grouped together in nonce order to reduce STM conflicts and retries.
2. **Simple transfer batching**: Simple transfers (fee > 0, amount > 0) are grouped to increase the STM fast path hit rate.
3. **Sender stability**: Within a block, same-sender txs appear contiguously.

## Configuration

### Environment Variables

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `EEZO_CONSENSUS_MODE` | `dag-primary`, `dag-hybrid`, `dag` | `dag-primary` (devnet-safe) | Consensus mode |
| `EEZO_DAG_ORDERING_ENABLED` | `1`, `0` | `1` (devnet-safe) | Enable DAG ordering |

### Required Feature Flags

```bash
--features "devnet-safe,metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus,cuda-hash"
```

## Architecture

### Ordering Hooks in consensus_runner.rs

DAG ordering is applied at two locations in `consensus_runner.rs`:

1. **Hook #1 — Hybrid batch consumption path** (~line 2150):
   - Triggered when `hybrid_batch_used=true` (DAG batches consumed)
   - Applies `order_txs_for_dag_block()` to aggregated DAG batches
   - Primary path when DAG consensus is producing ordered batches

2. **Hook #2 — Mempool fallback path** (~line 2280):
   - Triggered when `hybrid_batch_used=false` but in DagPrimary mode
   - Applies `order_txs_for_dag_block()` to mempool-collected txs
   - Ensures ordering even when no DAG batches are available

Both hooks update the same metrics via `record_dag_ordering_metrics()`.

### T96.2 Fix: HybridDagHandle Creation

Prior to T96.2, the `HybridDagHandle` was only created for `DagHybrid` mode, not `DagPrimary`. This meant that in DagPrimary mode:
- `hybrid_opt` was always `None`
- The batch aggregation code was skipped
- `hybrid_batch_used` never became `true`
- DAG ordering metrics stayed at 0

**Fixed in T96.2**: The HybridDagHandle is now created for both `DagHybrid` and `DagPrimary` modes when ordering is enabled.

## Metrics

### DAG Ordering Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_dag_ordering_enabled` | Gauge | 1 if DAG ordering is enabled, 0 otherwise |
| `eezo_dag_ordered_txs_total` | Counter | Total txs passed through DAG ordering |
| `eezo_dag_fastpath_candidates_total` | Counter | Simple transfer candidates identified |
| `eezo_dag_nonce_span_hist` | Histogram | Average nonce span per block |
| `eezo_dag_block_tx_per_block_hist` | Histogram | Txs per block with DAG ordering |
| `eezo_dag_ordering_fallback_total` | Counter | Fallback events from DAG to mempool |

## Verifying DAG Ordering is Active

### Method 1: Check Metrics After Spam Run

```bash
# Start the node
EEZO_DAG_ORDERING_ENABLED=1 \
EEZO_CUDA_HASH_ENABLED=1 \
EEZO_STM_SIMPLE_FASTPATH_ENABLED=1 \
EEZO_STM_KERNEL_MODE=arena \
EEZO_CONSENSUS_MODE=dag-primary \
cargo run --release --bin eezo-node --features devnet-safe

# In another terminal, run spam
scripts/spam_tps.sh 2000 http://127.0.0.1:8080

# Check metrics
curl -s http://127.0.0.1:9898/metrics \
  | grep -E 'eezo_dag_ordering_enabled|eezo_dag_ordered_txs_total|eezo_dag_fastpath_candidates_total'
```

Expected output:
```
eezo_dag_ordering_enabled 1
eezo_dag_ordered_txs_total 1850  # Should be > 0 after spam
eezo_dag_fastpath_candidates_total 1800  # Should be > 0 for simple transfers
```

### Method 2: Using the Fat Block Profile Script

```bash
EEZO_DAG_ORDERING_ENABLED=1 \
EEZO_STM_SIMPLE_FASTPATH_ENABLED=1 \
EEZO_STM_KERNEL_MODE=arena \
scripts/t93_fat_block_profile.sh 5000 60
```

After the run, verify:
- `eezo_dag_ordered_txs_total > 0`
- `eezo_dag_fastpath_candidates_total > 0`

## Troubleshooting

### Metrics Stay at 0

If `eezo_dag_ordered_txs_total` remains at 0 after a spam run:

1. **Check consensus mode**: Ensure `EEZO_CONSENSUS_MODE=dag-primary` or `dag-hybrid`
2. **Check ordering flag**: Ensure `EEZO_DAG_ORDERING_ENABLED=1`
3. **Check feature flags**: Build must include `dag-consensus` and `stm-exec`
4. **Check logs**: Look for `T96.2: HybridDagHandle attached to CoreRunner`

### Low TPS with DAG Ordering Enabled

If TPS is significantly lower with DAG ordering enabled:

1. Check for extra allocations in the ordering path
2. Verify bitmap structures are being reused across waves
3. Ensure no unnecessary Vec clones in the hot path

## Performance Baseline

With DAG ordering enabled, expected performance on devnet:

| Mode | Target TPS | STM per-tx |
|------|------------|------------|
| DAG ordering OFF | ≥ 180 TPS | ≤ 0.9 ms/tx |
| DAG ordering ON | ≥ 180 TPS | ≤ 0.9 ms/tx |

DAG ordering should not significantly impact TPS when properly implemented.
