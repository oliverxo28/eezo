# T94.0 — Block Packing & DAG Tick Tuning

This document describes the T94.0 milestone: block packing policy and DAG tick tuning to improve effective TPS under heavy load.

## Motivation

After T90.x–T93.x optimizations, profiling showed that:

- **Hashing** (CPU and GPU BLAKE3) is fast: ~4–6 µs per tx
- **STM fast path** for simple transfers is fast: ~7 µs per tx when the fast path is used
- **STM per-tx cost** overall is ~1.2–1.6 ms/tx

Despite these improvements, TPS remained capped at ~150–170 TPS because:

1. **Blocks aren't full enough**: With fat-block config (`BLOCK_MAX_TX=2000`), only ~34 tx/block were observed
2. **Block timing is too conservative**: The tick interval respects `EEZO_BLOCK_TARGET_TIME_MS` rigidly, even when mempool has a large backlog

T94.0 addresses these issues by:
- Adding an **aggressive block packing policy** to fill blocks closer to `EEZO_BLOCK_MAX_TX`
- Adding **early tick triggering** when mempool has sufficient backlog (perf mode)

## Current Block Building Architecture

### Block Timing

The consensus loop uses a fixed ticker with `EEZO_CONSENSUS_TICK_MS` (default: 200ms):

```rust
let mut ticker = interval(Duration::from_millis(tick_ms.max(1)));
loop {
    ticker.tick().await;  // Wait for full tick interval
    // ... build and commit block
}
```

This means blocks are produced on a fixed cadence regardless of mempool backlog.

### Block Packing (Mempool Drain)

Transactions are collected via `mempool.drain_for_block(max_bytes, accounts)`:

1. **Byte budget**: Respects `EEZO_MAX_BLOCK_BYTES` (default: 1 MiB)
2. **Nonce contiguity**: Only drains txs with contiguous nonces per sender
3. **Fee ordering**: Higher fee txs are prioritized
4. **Max tx cap**: `EEZO_BLOCK_MAX_TX` is applied after draining (overflow re-enqueued)

The drain function has a safety cap of 10,000 iterations to prevent liveness issues.

### DAG Hybrid/Primary Mode

In `dag-primary` mode (used for devnet), the block builder:
1. Checks for ordered batches from the DAG consensus layer
2. Aggregates multiple batches if available (respecting time budget)
3. Falls back to mempool if no DAG batches are available

## T94.0 Changes

### Block Packing Policy

A new `BlockPackingPolicy` enum controls block building behavior:

```rust
pub enum BlockPackingPolicy {
    Conservative,  // Default: respect full tick interval
    Aggressive,    // Minimize idle time under load
}
```

Controlled via `EEZO_BLOCK_PACKING_MODE` environment variable:
- `"conservative"` or `"c"` (default): Standard tick-based block building
- `"aggressive"` or `"a"`: Early tick triggering when mempool has backlog

### Perf Mode (Early Tick)

When `EEZO_PERF_MODE=1` (or `EEZO_BLOCK_PACKING_MODE=aggressive`):

1. **Early tick triggering**: If mempool has `>= EEZO_EARLY_TICK_THRESHOLD` txs, the block builder fires immediately instead of waiting for the full tick interval
2. **Minimum interval**: A 10ms floor prevents spinning
3. **No change when mempool is empty**: Normal tick behavior when backlog is low

```
if mempool_len >= early_tick_thresh && elapsed >= 10ms:
    build_block_immediately()
else:
    wait_for_tick()
```

Default early tick threshold: `EEZO_BLOCK_MAX_TX / 2` (or 250 if BLOCK_MAX_TX not set)

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EEZO_PERF_MODE` | `0` | Set to `1` to enable aggressive timing |
| `EEZO_BLOCK_PACKING_MODE` | `conservative` | `aggressive` for early tick |
| `EEZO_EARLY_TICK_THRESHOLD` | `BLOCK_MAX_TX/2` | Mempool backlog to trigger early tick |
| `EEZO_BLOCK_MAX_TX` | unlimited | Maximum txs per block |
| `EEZO_CONSENSUS_TICK_MS` | `200` | Base tick interval in ms |

## New Prometheus Metrics

### eezo_t94_early_tick_total

**Type**: Counter

**Description**: Number of times early tick was triggered (block built before tick expired due to mempool backlog).

```
eezo_t94_early_tick_total 42
```

### eezo_t94_block_packing_mode

**Type**: Gauge

**Description**: Current block packing mode (0 = conservative, 1 = aggressive).

### eezo_t94_perf_mode_enabled

**Type**: Gauge

**Description**: Whether perf mode is enabled (0 = disabled, 1 = enabled).

## How to Run T93 Harness (Before/After Comparison)

### Baseline (Before T94)

```bash
# Without perf mode (conservative)
EEZO_STM_SIMPLE_FASTPATH_ENABLED=1 \
EEZO_STM_KERNEL_MODE=arena \
scripts/t93_fat_block_profile.sh 5000 120
```

Expected:
- ~34 tx/block average
- ~150–170 TPS

### With T94 Perf Mode (After)

```bash
EEZO_PERF_MODE=1 \
EEZO_STM_SIMPLE_FASTPATH_ENABLED=1 \
EEZO_STM_KERNEL_MODE=arena \
scripts/t93_fat_block_profile.sh 5000 120
```

Expected improvements:
- Higher tx/block average (closer to `BLOCK_MAX_TX` when backlog exists)
- Higher TPS (reduced idle time between blocks)
- `eezo_t94_early_tick_total` > 0

### Normal Spam Scenario

```bash
# Start node with perf mode
EEZO_PERF_MODE=1 \
EEZO_CUDA_HASH_ENABLED=1 \
EEZO_STM_SIMPLE_FASTPATH_ENABLED=1 \
EEZO_STM_KERNEL_MODE=arena \
EEZO_CONSENSUS_MODE=dag-primary \
EEZO_BLOCK_MAX_TX=500 \
EEZO_BLOCK_TARGET_TIME_MS=1000 \
EEZO_MEMPOOL_MAX_TX=20000 \
./target/release/eezo-node --genesis genesis.min.json --datadir /tmp/eezo-t94

# In another terminal, run spam
scripts/spam_tps.sh 2000 http://127.0.0.1:8080

# Measure TPS
scripts/measure_tps.sh 10 http://127.0.0.1:9898/metrics
```

### Interpreting Metrics

After running spam, query Prometheus metrics:

```bash
curl -s http://127.0.0.1:9898/metrics | grep -E "eezo_t94|eezo_txs_included|block_applied"
```

Key metrics to compare:
- **Δeezo_txs_included_total / Δblock_applied_total** = average tx per block
- **Δeezo_txs_included_total / elapsed_seconds** = TPS
- **eezo_t94_early_tick_total** = number of early tick events

## Where the TPS Uplift Comes From

1. **Reduced idle time**: In conservative mode, the node waits for the full tick (e.g., 200ms) even if 1000 txs are queued. With perf mode, it builds immediately when backlog is sufficient.

2. **More blocks per second**: With early tick threshold at 250 txs and minimum interval of 10ms, the node can theoretically produce up to 100 blocks/second when under heavy load (vs 5 blocks/second with 200ms tick).

3. **Fuller blocks**: By not waiting for the tick, the node can pack more txs per block when they're available.

## Safety Guarantees

- **No change to consensus rules**: Block contents, signatures, and validation unchanged
- **No change to correctness**: State safety in STM unchanged
- **Feature-gated**: All new behavior behind `EEZO_PERF_MODE` or `EEZO_BLOCK_PACKING_MODE`
- **Default is conservative**: Without explicit opt-in, behavior matches pre-T94

## Known Limitations

1. **Single-node only**: These optimizations are for single-node devnet testing. Multi-node consensus has additional constraints.

2. **STM is still the bottleneck**: At ~1.2ms/tx STM cost, theoretical max is ~800 TPS on a single core. Parallel STM waves help, but there are limits.

3. **Network I/O not addressed**: For real multi-node deployments, network latency and gossip delays would be the next bottleneck.

## Future Work (T94.1+)

If further TPS improvements are needed:

1. **STM Wave Optimization**: Increase parallelism in the STM executor
2. **Batch Pre-execution**: Pipeline execution with the next block's txs
3. **Parallel Block Building**: Build multiple candidate blocks in parallel
4. **Memory-mapped State**: Reduce state lookup latency
