# T92 — Hash vs Executor Profiling Under Load

This document describes the T92.0 milestone: adding lightweight timing metrics to EEZO-node for profiling CPU time spent in hashing and STM execution under load.

## Motivation

With the single-node DAG-primary + STM executor stable at ~200–250 TPS sustained (300+ bursts), we need to quantify where CPU time goes during consensus:

1. **Hashing (BLAKE3)**: Computing tx hashes, block body hashes, etc.
2. **STM Executor**: Running block execution with the STM (Block-STM) engine.
3. **Everything else**: Serialization, network I/O, mempool operations, etc.

These metrics help identify bottlenecks and guide future optimization work.

## New Prometheus Metrics

### eezo_hash_cpu_time_seconds

**Type**: Counter (float)

**Description**: Total CPU time (seconds) spent in consensus-related BLAKE3 hashing.

This metric tracks time spent in:
- Block body hash computation (`hash_block_body`)
- Batch tx hash computation (`hash_batch_with_gpu_check`)
- CUDA shadow path CPU cross-check hashing

**Example**:
```
eezo_hash_cpu_time_seconds 0.0523
```

### eezo_exec_stm_time_seconds

**Type**: Counter (float)

**Description**: Total CPU time (seconds) spent in STM executor runs executed by consensus.

This metric tracks time spent in `execute_block()` calls, which includes:
- Transaction validation
- Parallel wave scheduling
- State delta computation
- Conflict detection and retries

**Example**:
```
eezo_exec_stm_time_seconds 1.247
```

## How to Interpret the Metrics

### Healthy Baseline

After running a spam test (e.g., 2000 tx), you should see:

```
eezo_txs_included_total 2000
eezo_hash_cpu_time_seconds > 0.0
eezo_exec_stm_time_seconds > 0.0
```

### Ratio Analysis

The ratio of `eezo_exec_stm_time_seconds` to `eezo_hash_cpu_time_seconds` indicates where CPU time is spent:

- **High STM / Low Hash**: Most time is in execution (expected for transfer-only workloads)
- **High Hash / Low STM**: Hashing is a bottleneck (may benefit from GPU acceleration)
- **Both Low**: Bottleneck is elsewhere (network, mempool, serialization)

### Typical Values

On an RTX 3050 with ~200 TPS sustained:

| Metric | Typical Range |
|--------|---------------|
| `eezo_hash_cpu_time_seconds` | 0.001–0.1s per 1000 tx |
| `eezo_exec_stm_time_seconds` | 0.5–2.0s per 1000 tx |

## How to Profile

### 1. Start the Node

Start the node with DAG-primary + STM + metrics enabled:

```bash
EEZO_CONSENSUS_MODE=dag-primary \
EEZO_EXECUTOR_MODE=stm \
./target/release/eezo-node --genesis genesis.min.json --datadir /tmp/eezo-t92
```

### 2. Run Spam Test

Use the spam script to generate load:

```bash
# 2000 transactions
./scripts/spam_tps.sh 2000

# 10000 transactions for sustained load
./scripts/spam_tps.sh 10000
```

### 3. Check Metrics

Query the `/metrics` endpoint:

```bash
curl -s http://localhost:9100/metrics | grep -E "(eezo_hash_cpu_time|eezo_exec_stm_time|eezo_txs_included)"
```

Expected output after spam:

```
eezo_txs_included_total 2000
eezo_hash_cpu_time_seconds 0.0234
eezo_exec_stm_time_seconds 0.8721
```

### 4. Compute Ratios

Calculate where time is spent:

```bash
# Example with values from metrics
HASH_TIME=0.0234
EXEC_TIME=0.8721
TOTAL=$(echo "$HASH_TIME + $EXEC_TIME" | bc)

# Percentage breakdown
echo "Hash: $(echo "scale=1; $HASH_TIME / $TOTAL * 100" | bc)%"
echo "Exec: $(echo "scale=1; $EXEC_TIME / $TOTAL * 100" | bc)%"
```

## Build Requirements

Enable the required features when building:

```bash
cargo build -p eezo-node \
  --features "pq44-runtime,metrics,checkpoints,stm-exec,dag-consensus" \
  --release
```

For CUDA hash profiling, add `cuda-hash`:

```bash
cargo build -p eezo-node \
  --features "pq44-runtime,metrics,checkpoints,stm-exec,dag-consensus,cuda-hash" \
  --release
```

## What T92.0 Does NOT Do

- **Modify consensus logic**: Block hashes, headers, and STM behavior are identical.
- **Add overhead**: Timing uses `Instant::now()` which is ~10ns per call.
- **Change block format**: No protocol changes.

## Implementation Details

### Hash Timing

Timing is added to these functions:

1. `gpu_hash::hash_batch_with_gpu_check()` — wraps CPU BLAKE3 batch hashing
2. `gpu_hash::NodeHashEngine::hash_block_body()` — wraps single block body hashing
3. `cuda_hash::run_t91_2_cuda_hash_shadow()` — wraps CPU cross-check hashing

### STM Executor Timing

Timing wraps the `exec.execute_block()` call in `consensus_runner.rs`:

```rust
let exec_start = Instant::now();
let exec_outcome = exec.execute_block(&mut guard, exec_input);
let exec_elapsed = exec_start.elapsed().as_secs_f64();
crate::metrics::exec_stm_time_inc(exec_elapsed);
```

This is done in both:
- Non-persistence spawn variant (line ~785)
- Persistence-enabled spawn variant (line ~2005)

## Acceptance Criteria

1. ✅ `cargo build -p eezo-node --features "pq44-runtime,metrics,checkpoints,stm-exec,dag-consensus,cuda-hash" --release` succeeds
2. ✅ Starting the node and hitting `/metrics` shows the new metrics (all starting at 0.0)
3. ✅ After running a spam load (e.g., 2000 tx), `/metrics` shows:
   - `eezo_txs_included_total` increased as expected
   - `eezo_hash_cpu_time_seconds` > 0.0
   - `eezo_exec_stm_time_seconds` > 0.0
4. ✅ No consensus behavior changes

## Files Changed

- `crates/node/src/metrics.rs`: Added T92.0 metrics and helpers
- `crates/node/src/main.rs`: Added metrics registration import and call
- `crates/node/src/consensus_runner.rs`: Added STM executor timing
- `crates/node/src/gpu_hash.rs`: Added hash timing to batch and single hash functions
- `crates/node/src/cuda_hash.rs`: Added hash timing to CPU cross-check
- `book/src/t92_perf_profiling.md`: This documentation file
