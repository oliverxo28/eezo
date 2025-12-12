# T84.5 — Performance Plateau Snapshot

> **Task:** T84.5  
> **Status:** Implemented  
> **Scope:** Configuration, documentation, and regression guardrails — no changes to consensus, wire formats, or PQ semantics

---

## Overview

T84.5 marks a **performance plateau** after completing the T82–T84 optimization arc:

| Task | Description |
|------|-------------|
| T82.0–T82.4 | STM metrics, analyzed tx, overlay, conflict prescreen (WaveFingerprint), mempool actor |
| T83.0 | Sigpool micro-batching + metrics |
| T83.1 | Multi-sender spam generator (`spam_multi_senders.sh`) + docs |
| T83.2 | Async persistence (CommittedMemHead + PersistenceWorker, `EEZO_PERSIST_ASYNC=1`) |
| T83.3 | Block execution pipelining (BlockPipeline, `EEZO_PIPELINE_ENABLED=1`) |
| T83.4 | Zero-copy SharedTx propagation (mempool + STM analyze) |
| T84.0 | Lazy/incremental state root (IncrementalStateRoot, `EEZO_LAZY_STATE_ROOT=1`) |

**Current performance on a laptop devnet (single node):** ~150–250 TPS, depending on workload and timing.

This document provides:
1. A reusable "max-perf devnet" configuration
2. Three canonical TPS scenarios with expected metrics
3. A troubleshooting checklist for TPS drops
4. A simple regression guard script

---

## Table of Contents

- [Max-Perf Devnet Configuration](#max-perf-devnet-configuration)
- [Canonical TPS Scenarios](#canonical-tps-scenarios)
- [If TPS Drops — Troubleshooting Checklist](#if-tps-drops--troubleshooting-checklist)
- [Regression Guard Script](#regression-guard-script)

---

## Max-Perf Devnet Configuration

### Environment File

Use `devnet_tps.env` for high-throughput benchmarking:

```bash
# Source the T84.5 high-throughput profile
source devnet_tps.env

# Then run the devnet launcher
./scripts/devnet_dag_primary.sh
```

The `devnet_tps.env` file sets:

```bash
# T84.5: High-Throughput Devnet Profile
EEZO_CONSENSUS_MODE=dag-primary

# Performance optimizations
EEZO_MEMPOOL_ACTOR_ENABLED=1    # T82.4: Mempool actor
EEZO_PERSIST_ASYNC=1            # T83.2: Async persistence
EEZO_PIPELINE_ENABLED=1         # T83.3: Block pipelining
EEZO_LAZY_STATE_ROOT=1          # T84.0: Incremental state root

# STM executor
EEZO_EXEC_LANES=32
EEZO_EXEC_WAVE_CAP=256

# Sigpool (T83.0)
EEZO_SIGPOOL_THREADS=4
EEZO_SIGPOOL_BATCH_SIZE=128
EEZO_SIGPOOL_QUEUE=20000

# Mempool
EEZO_MEMPOOL_MAX_LEN=50000

# Block production
EEZO_BLOCK_MAX_TX=500
EEZO_BLOCK_TARGET_TIME_MS=1000
```

### Direct Cargo Command

For manual runs without the launcher script:

```bash
set -a && source devnet_tps.env && set +a

cargo run -p eezo-node --bin eezo-node \
  --features "devnet-safe,metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus" -- \
  --genesis genesis.min.json \
  --datadir /tmp/eezo-t84
```

### Test Thread Isolation

When running `adaptive_agg` tests, use `--test-threads=1` to avoid environment variable races:

```bash
cargo test --features "pq44-runtime,metrics" adaptive_agg -- --test-threads=1
```

---

## Canonical TPS Scenarios

### Scenario Table

| Scenario              | TPS (approx) | Conflicts | Waves/Block | Notes                       |
|-----------------------|--------------|-----------|-------------|-----------------------------|
| A: Single sender      | ~180–220 TPS | 0         | ~1.0        | Pure throughput ceiling     |
| B: 32 disjoint senders| ~160–200 TPS | ~0        | ~1.0–1.5    | Parallel, conflict-free     |
| C: 32 hotspot senders | ~100–150 TPS | >0        | ~2.0–4.0    | Intentional conflict stress |

> **Note:** These are approximate ranges measured on a laptop. Your results may vary based on hardware, OS, and background load.

### Scenario A — Single Sender Baseline (No Conflicts)

**Purpose:** Measure pure throughput ceiling with no STM conflicts.

**Setup:**

```bash
# Terminal 1: Start node with T84.5 profile
source devnet_tps.env
./scripts/devnet_dag_primary.sh

# Terminal 2: Generate load (requires ml_dsa_keygen setup)
./scripts/spam_tps.sh 5000 http://127.0.0.1:8080

# Terminal 3: Measure TPS
./scripts/tps_benchmark.sh --duration 60 --warmup 10 --verbose
```

**Expected metrics:**
- TPS: ~180–220 tx/s
- `eezo_exec_stm_waves_total`: Low (1 wave per block)
- `eezo_exec_stm_conflicts_total`: 0
- `avg_txs_per_block`: ~180–220

### Scenario B — 32 Senders, Disjoint (Low Conflicts)

**Purpose:** Test parallel execution with multiple senders but minimal state contention.

**Setup:**

```bash
# Terminal 1: Start node (same as above)

# Terminal 2: Multi-sender spam with disjoint pattern
./scripts/spam_multi_senders.sh \
  --senders 32 \
  --per-sender 200 \
  --hot-receivers 32 \
  --pattern disjoint \
  --node http://127.0.0.1:8080

# Terminal 3: Measure TPS
./scripts/tps_benchmark.sh --duration 60 --warmup 10 --verbose
```

**Expected metrics:**
- TPS: ~160–200 tx/s
- `eezo_exec_stm_conflicts_total`: ~0 or very low
- `eezo_exec_stm_waves_built_total`: Non-zero, ~1 wave per block
- `eezo_mempool_len`: Should drain to near 0 after burst

### Scenario C — 32 Senders, Hotspot (Intentional Conflicts)

**Purpose:** Stress-test STM conflict resolution by targeting a single receiver.

**Setup:**

```bash
# Terminal 1: Start node (same as above)

# Terminal 2: Multi-sender spam with hotspot pattern
./scripts/spam_multi_senders.sh \
  --senders 32 \
  --per-sender 200 \
  --hot-receivers 1 \
  --pattern hotspot \
  --node http://127.0.0.1:8080

# Terminal 3: Measure TPS
./scripts/tps_benchmark.sh --duration 60 --warmup 10 --verbose
```

**Expected metrics:**
- TPS: ~100–150 tx/s (lower due to conflict retries)
- `eezo_exec_stm_conflicts_total`: Significantly higher
- `eezo_exec_stm_retries_total`: Non-zero
- `eezo_exec_stm_waves_built_total`: More waves per block (~2–4)

---

## If TPS Drops — Troubleshooting Checklist

### 1. Verify Environment Variables

Ensure these are set for max TPS:

- [ ] `EEZO_MEMPOOL_ACTOR_ENABLED=1`
- [ ] `EEZO_PERSIST_ASYNC=1`
- [ ] `EEZO_PIPELINE_ENABLED=1`
- [ ] `EEZO_LAZY_STATE_ROOT=1`
- [ ] `EEZO_EXEC_LANES=32` (or higher)
- [ ] `EEZO_SIGPOOL_THREADS=4` (or match CPU cores/2)
- [ ] `EEZO_SIGPOOL_BATCH_SIZE=128`

### 2. Check Sigpool Metrics

```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_sigpool
```

- `eezo_sigpool_batch_latency_seconds` should be in sub-millisecond range (< 1ms p99)
- `eezo_sigpool_batch_size` histogram should show batches filling to near `EEZO_SIGPOOL_BATCH_SIZE`
- High `eezo_sigpool_queued_total` with low `eezo_sigpool_verified_total` indicates bottleneck

### 3. Check STM Executor Metrics

```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_exec_stm
```

- `eezo_exec_stm_waves_total` should be non-zero during load
- `eezo_exec_stm_waves_built_total` should match or be close to waves_total
- High `eezo_exec_stm_conflicts_total` indicates contention (expected for hotspot)
- `eezo_exec_stm_aborted_total` should be ~0 (if non-zero, conflict pressure is severe)

### 4. Check Persistence Metrics

```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_persist
```

- `eezo_persist_block_latency_seconds` should not spike (< 100ms p99)
- `eezo_persist_queue_len` should not grow unbounded (< 100 sustained)
- If queue grows, disk I/O may be the bottleneck

### 5. Check Mempool Health

```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_mempool
```

- `eezo_mempool_len` should not stay huge for long after burst
- Sustained high mempool length may indicate executor falling behind

### 6. Common Fixes

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Low TPS with high conflicts | Hotspot workload | Expected; use disjoint pattern for max TPS |
| Low TPS with low conflicts | Missing T84.5 env vars | Source `devnet_tps.env` |
| Sigpool latency high | Too few threads | Increase `EEZO_SIGPOOL_THREADS` |
| Persist queue growing | Slow disk | Check disk I/O; consider NVMe |
| Mempool stuck high | Executor slow | Check STM metrics; increase `EEZO_EXEC_LANES` |

---

## Regression Guard Script

A lightweight regression script is provided at `scripts/t84_regression_check.sh`.

### Usage

```bash
# Start node first (in another terminal)
source devnet_tps.env
./scripts/devnet_dag_primary.sh

# Run regression check
./scripts/t84_regression_check.sh
```

### What It Does

1. Assumes node is running with T84.5 profile
2. Fires a small spam run (~2000 tx)
3. Measures TPS over a short window
4. Fails (exit 1) if TPS drops below a conservative floor (default: 100 TPS)

### Exit Codes

- `0`: TPS meets floor — regression check passed
- `1`: TPS below floor — potential regression detected
- `2`: Node not reachable or other error

### Manual Regression Procedure

If you prefer not to use the script:

```bash
# 1. Start node with T84.5 profile
source devnet_tps.env
./scripts/devnet_dag_primary.sh

# 2. Fire spam (in another terminal)
./scripts/spam_tps.sh 2000 http://127.0.0.1:8080

# 3. Measure TPS
./scripts/tps_benchmark.sh --duration 20 --warmup 5 --verbose > /tmp/t84_regression.json

# 4. Check TPS manually (should be > 100)
grep '"tps"' /tmp/t84_regression.json
```

---

## Related Documentation

- [T82.0: DAG TPS Baseline](t82_tps_baseline.md) — STM metrics and profiling
- [T83.0: Sigpool Pipeline](t83_sigpool_pipeline.md) — Signature verification optimization
- [T83.1: Multi-sender Baseline](t83_multi_sender_baseline.md) — Conflict pattern testing
- [T83.2: Async Persistence](t83_async_persistence.md) — CommittedMemHead architecture
- [Dev-Unsafe Modes](dev_unsafe_modes.md) — Build profiles for benchmarking
