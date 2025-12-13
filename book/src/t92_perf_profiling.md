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

---

# T93.0 — STM Executor Tuning Harness

This section describes the T93.0 milestone: a tuning harness for sweeping STM-related runtime knobs and profiling performance under load.

## Overview

The T93.0 harness automates configuration sweeps to find optimal STM executor settings. It:

1. Iterates through combinations of STM-related environment variables
2. Starts a fresh node instance for each configuration
3. Runs a standardized spam workload
4. Captures Prometheus metrics before/after
5. Computes per-tx timing and throughput metrics
6. Prints a summary table for comparison

## Scripts

### scripts/t93_stm_sweep.sh

Main sweep script that automates the full configuration sweep.

**Usage:**

```bash
scripts/t93_stm_sweep.sh [TX_COUNT] [NODE_URL] [METRICS_URL]
```

**Arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| TX_COUNT | 2000 | Number of transactions per config |
| NODE_URL | http://127.0.0.1:8080 | Node HTTP endpoint |
| METRICS_URL | http://127.0.0.1:9898/metrics | Prometheus metrics endpoint |

**Swept Environment Variables:**

| Variable | Values | Description |
|----------|--------|-------------|
| EEZO_EXEC_LANES | 8, 16, 32 | Number of STM execution lanes |
| EEZO_EXECUTOR_THREADS | nproc, nproc/2 | Number of executor threads |
| EEZO_EXEC_WAVE_CAP | 0, 128, 256 | Wave size cap (0 = unlimited) |
| EEZO_EXEC_BUCKETS | 32, 64 | Number of STM buckets |

**Fixed Environment Variables:**

```bash
EEZO_CUDA_HASH_ENABLED=1
EEZO_CONSENSUS_MODE=dag-primary
EEZO_EXEC_HYBRID=1
EEZO_EXEC_WAVE_COMPACT=1
```

**Example Run:**

```bash
# Run sweep with default 2000 tx per config
./scripts/t93_stm_sweep.sh

# Run sweep with 5000 tx for more accurate measurements
./scripts/t93_stm_sweep.sh 5000

# Custom endpoints
./scripts/t93_stm_sweep.sh 2000 http://localhost:8080 http://localhost:9898/metrics
```

### scripts/t93_fund_and_spam.sh

Helper script that handles keypair generation, faucet funding, and spam submission.

**Usage:**

```bash
scripts/t93_fund_and_spam.sh COUNT NODE_URL
```

**Arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| COUNT | 2000 | Number of transactions to submit |
| NODE_URL | http://127.0.0.1:8080 | Node HTTP endpoint |

**Features:**

- Automatically generates ML-DSA keypair using `ml_dsa_keygen`
- Derives sender address from public key (first 20 bytes)
- Funds sender via `/faucet` endpoint
- Calls `spam_tps.sh` to submit transactions

## Output Format

Each configuration produces a summary line with these fields:

```
lanes=16 threads=8 wavecap=256 buckets=64 \
  tx=2000 blocks=320 \
  stm_time=3.4500s hash_time=0.006800s \
  stm_per_tx=0.001725s hash_per_tx=0.00000340s \
  tx_per_block=6.25 tps=185.50
```

**Field Descriptions:**

| Field | Description |
|-------|-------------|
| lanes | EEZO_EXEC_LANES value |
| threads | EEZO_EXECUTOR_THREADS value |
| wavecap | EEZO_EXEC_WAVE_CAP value |
| buckets | EEZO_EXEC_BUCKETS value |
| tx | Number of transactions included (Δeezo_txs_included_total) |
| blocks | Number of blocks applied (Δblock_applied_total) |
| stm_time | Total STM executor time (Δeezo_exec_stm_time_seconds) |
| hash_time | Total hash CPU time (Δeezo_hash_cpu_time_seconds) |
| stm_per_tx | STM time per transaction |
| hash_per_tx | Hash time per transaction |
| tx_per_block | Average transactions per block |
| tps | Approximate transactions per second |

## Example Output

```
═══════════════════════════════════════════════════════════════════════════════════
  T93.0 Sweep Summary
═══════════════════════════════════════════════════════════════════════════════════

lanes=8 threads=16 wavecap=0 buckets=32 tx=2000 blocks=285 stm_time=3.2100s hash_time=0.005400s stm_per_tx=0.001605s hash_per_tx=0.00000270s tx_per_block=7.01 tps=178.50
lanes=8 threads=16 wavecap=0 buckets=64 tx=2000 blocks=290 stm_time=3.1500s hash_time=0.005200s stm_per_tx=0.001575s hash_per_tx=0.00000260s tx_per_block=6.89 tps=182.30
lanes=16 threads=16 wavecap=256 buckets=64 tx=2000 blocks=320 stm_time=2.9800s hash_time=0.004800s stm_per_tx=0.001490s hash_per_tx=0.00000240s tx_per_block=6.25 tps=195.40

═══════════════════════════════════════════════════════════════════════════════════
  Sweep Complete: 36 configurations tested
═══════════════════════════════════════════════════════════════════════════════════
```

## Interpreting Results

1. **Lower stm_per_tx is better**: Indicates faster transaction execution
2. **Higher tps is better**: Indicates higher throughput
3. **Higher tx_per_block is better**: Indicates more efficient block packing

**Typical findings:**

- Increasing EEZO_EXEC_LANES beyond CPU core count may not help
- EEZO_EXEC_WAVE_CAP=256 often performs better than unlimited (0)
- Optimal EEZO_EXECUTOR_THREADS depends on workload contention

## Requirements

Before running the sweep:

1. Build the node with required features:
   ```bash
   cargo build -p eezo-node \
     --features "pq44-runtime,metrics,checkpoints,stm-exec,dag-consensus,cuda-hash" \
     --release
   ```

2. Build helper binaries:
   ```bash
   cargo build -p eezo-crypto --bin ml_dsa_keygen --release
   cargo build -p eezo-node --bin eezo-txgen --release
   ```

3. Ensure ports 8080 and 9898 are available

4. Have `jq`, `curl`, `awk`, `bc` installed

## What T93.0 Does NOT Do

- **Modify STM algorithm**: No changes to execution logic
- **Modify consensus**: Block format and consensus remain identical
- **Persist results**: Results are printed to stdout (redirect to file if needed)
- **Auto-tune**: Does not automatically select the best config

## Files Added

- `scripts/t93_stm_sweep.sh`: Main sweep script
- `scripts/t93_fund_and_spam.sh`: Helper for funding and spamming
