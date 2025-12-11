# T82.0: DAG TPS Baseline & Profiling

> **Task:** T82.0  
> **Status:** Implemented  
> **Scope:** Measurement/instrumentation only — no changes to STM semantics, consensus, or mempool algorithms

---

## Overview

T82.0 provides a clean, reproducible DAG TPS baseline with:

1. **Executor Metrics** — Track STM waves, conflicts, retries, and aborted transactions per block
2. **CPU Profiling Hooks** — Optional profiling mode (via `EEZO_PROFILING` env var) that is `perf`/`flamegraph` friendly
3. **Automated TPS Benchmark Script** — Measure TPS over configurable time windows with warm-up support
4. **This Documentation** — How to build, run benchmarks, and interpret metrics

---

## Table of Contents

- [Quick Start](#quick-start)
- [Building the Node](#building-the-node)
- [Running the TPS Benchmark](#running-the-tps-benchmark)
- [Metrics Reference](#metrics-reference)
- [CPU Profiling](#cpu-profiling)
- [Laptop Baseline](#laptop-baseline)
- [Environment Variables](#environment-variables)

---

## Quick Start

```bash
# Terminal 1: Start the DAG-primary devnet node
./scripts/devnet_dag_primary.sh

# Terminal 2: Generate TPS load using existing spam script
# Note: spam_tps.sh is an existing script that requires ml_dsa_keygen setup.
# See scripts/spam_tps.sh for required environment variables (EEZO_TX_FROM, etc.)
./scripts/spam_tps.sh 5000

# Terminal 3: Run the TPS benchmark
./scripts/tps_benchmark.sh --duration 60 --warmup 10
```

---

## Building the Node

### Pure DAG Mode with Metrics (Recommended for T82.0)

```bash
# From repository root
cargo build -p eezo-node --release \
  --features "devnet-safe,metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus"
```

### Feature Flags Explained

| Feature | Description |
|---------|-------------|
| `devnet-safe` | Devnet-safe configuration (no unsigned tx) |
| `metrics` | Prometheus metrics on `/metrics` endpoint |
| `pq44-runtime` | ML-DSA-44 signature runtime (PQC) |
| `checkpoints` | Checkpoint/bridge functionality |
| `stm-exec` | STM (Block-STM) parallel executor |
| `dag-consensus` | DAG consensus mode |

### Using the Official Devnet Launcher

The recommended way to start a DAG-primary node:

```bash
./scripts/devnet_dag_primary.sh
```

This script:
- Sets `EEZO_CONSENSUS_MODE=dag-primary`
- Configures STM executor with `EEZO_EXEC_LANES=32`
- Enables all required features
- Exposes metrics on `http://127.0.0.1:9898/metrics`

---

## Running the TPS Benchmark

### Basic Usage

```bash
./scripts/tps_benchmark.sh
```

This measures TPS for 30 seconds with a 5-second warm-up period.

### With Custom Settings

```bash
./scripts/tps_benchmark.sh \
  --duration 60 \     # Measure for 60 seconds
  --warmup 10 \       # Wait 10 seconds before measuring
  --verbose           # Show detailed output including JSON
```

### Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `-d, --duration` | 30 | Measurement duration in seconds |
| `-w, --warmup` | 5 | Warm-up period before measurement |
| `-m, --metrics-url` | `http://127.0.0.1:9898/metrics` | Prometheus metrics URL |
| `-v, --verbose` | off | Enable verbose output with JSON |

### Sample Output

```
═══════════════════════════════════════════════════════════════════════════
  TPS Benchmark Results
═══════════════════════════════════════════════════════════════════════════

  Measurement Period:
    Duration:                 30s
    Start eezo_txs_included:  1000
    End eezo_txs_included:    5500

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  TPS (Transactions Per Second):   150.00                                
  └─────────────────────────────────────────────────────────────────────────┘

  Block Production:
    Blocks produced:          30
    Blocks per second:        1.00
    Avg txs per block:        150.00

  STM Executor Metrics (T82.0):
    Total waves:              45
    Avg waves per block:      1.50
    Total conflicts:          12
    Avg conflicts per block:  0.40
    Total retries:            15
    Total aborted:            0

═══════════════════════════════════════════════════════════════════════════
```

---

## Metrics Reference

### T82.0 Executor Metrics (`eezo_exec_*` prefix)

These metrics track STM executor behavior per block:

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_exec_stm_waves_total` | Counter | Total STM execution waves across all blocks |
| `eezo_exec_stm_conflicts_total` | Counter | Total tx conflicts detected during execution |
| `eezo_exec_stm_retries_total` | Counter | Total txs retried due to conflicts |
| `eezo_exec_stm_aborted_total` | Counter | Total txs aborted after max retries |
| `eezo_exec_stm_waves_per_block` | Histogram | Distribution of waves per block |
| `eezo_exec_stm_conflicts_per_block` | Histogram | Distribution of conflicts per block |
| `eezo_exec_stm_retries_per_block` | Histogram | Distribution of retries per block |

### TPS-Related Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_txs_included_total` | Counter | Total transactions included in blocks |
| `block_applied_total` | Counter | Total blocks applied to state |
| `eezo_block_tx_count` | Gauge | Txs in the last built block |
| `eezo_exec_txs_per_block` | Histogram | Distribution of txs per block |

### Existing STM Metrics (Legacy, `eezo_stm_*` prefix)

For backward compatibility, these older metrics are also emitted:

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_stm_block_waves_total` | Counter | Same as `eezo_exec_stm_waves_total` |
| `eezo_stm_block_conflicts_total` | Counter | Same as `eezo_exec_stm_conflicts_total` |
| `eezo_stm_block_retries_total` | Counter | Same as `eezo_exec_stm_retries_total` |
| `eezo_stm_waves_per_block` | Histogram | Same as `eezo_exec_stm_waves_per_block` |
| `eezo_stm_conflicts_per_block` | Histogram | Same as `eezo_exec_stm_conflicts_per_block` |
| `eezo_stm_retries_per_block` | Histogram | Same as `eezo_exec_stm_retries_per_block` |

### How to Interpret STM Metrics

**Waves per block:**
- Optimal: 1.0–1.5 waves (minimal conflicts)
- Acceptable: 1.5–3.0 waves (some conflicts, resolved quickly)
- Concerning: >3.0 waves (high conflict rate, consider tuning)

**Conflicts per block:**
- Low: <5% of tx count (healthy)
- Moderate: 5–15% of tx count (acceptable)
- High: >15% of tx count (investigate tx patterns)

**Retries vs Aborted:**
- Most retries should succeed (aborted should be ~0)
- High abort rate indicates max_retries is too low or severe contention

---

## CPU Profiling

### Enabling Profiling Mode

Set the `EEZO_PROFILING` environment variable:

```bash
export EEZO_PROFILING=perf
./scripts/devnet_dag_primary.sh
```

When enabled:
- Node logs: `T82.0: Profiling mode enabled (EEZO_PROFILING=perf)`
- Minimal overhead added for stack frame attribution
- Compatible with `perf record` and `flamegraph` tools

### Using perf + Flamegraph

```bash
# Start node with profiling enabled
export EEZO_PROFILING=perf
./scripts/devnet_dag_primary.sh &
NODE_PID=$!

# Generate load using the existing spam script
# (requires ml_dsa_keygen setup - see scripts/spam_tps.sh for env vars)
./scripts/spam_tps.sh 10000 &

# Record performance data (30 seconds)
sudo perf record -F 99 -p $NODE_PID -g -- sleep 30

# Generate flamegraph
perf script | stackcollapse-perf.pl | flamegraph.pl > flamegraph.svg
```

### Hot Sections for Profiling

Key areas to look for in flamegraph output:

1. **STM Execute** (`execute_stm`, `execute_tx_speculative_parallel`)
   - State snapshot cloning
   - Conflict detection
   
2. **Signature Verification** (`verify_mldsa44`, `sender_from_pubkey_first20`)
   - ML-DSA-44 verification is CPU-intensive
   
3. **DAG Ordering** (`try_order_round`, `OrderingEngine`)
   - Vertex collection and author counting

---

## Laptop Baseline

> **Placeholder for recorded baseline numbers**  
> Update this section after running benchmarks on your reference hardware.

### Reference Hardware

```
CPU:         [TODO: e.g., Apple M2 Pro / AMD Ryzen 9 / Intel i9]
Cores:       [TODO: e.g., 8 / 16 / 12]
RAM:         [TODO: e.g., 32GB]
Storage:     [TODO: e.g., NVMe SSD]
OS:          [TODO: e.g., macOS 14 / Ubuntu 22.04]
```

### Baseline Results

```
Date:        [TODO: YYYY-MM-DD]
Node Build:  [TODO: commit SHA or release tag]
Config:      
  EEZO_EXEC_LANES=32
  EEZO_EXEC_WAVE_CAP=256
  EEZO_CONSENSUS_MODE=dag-primary

Results:
  TPS:                    [TODO: e.g., 180 tx/s]
  Blocks per second:      [TODO: e.g., 1.0]
  Avg txs per block:      [TODO: e.g., 180]
  Avg waves per block:    [TODO: e.g., 1.2]
  Avg conflicts per block:[TODO: e.g., 2.5]
```

### Notes

- Baseline measured with `spam_tps.sh 10000` for load generation
- Measurement window: 60 seconds after 10 second warm-up
- Single-node devnet (no network latency)

---

## Environment Variables

### T82.0-Specific

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `EEZO_PROFILING` | `off`, `perf`, `1`, `true` | `off` | Enable CPU profiling mode |
| `EEZO_METRICS_URL` | URL | `http://127.0.0.1:9898/metrics` | Metrics endpoint for benchmark script |

### STM Executor Tuning

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `EEZO_EXEC_LANES` | 16, 32, 48, 64 | 16 | Parallel execution lanes |
| `EEZO_EXEC_WAVE_CAP` | 0 (unlimited), N | 0 | Max txs per wave |
| `EEZO_STM_MAX_RETRIES` | N | 5 | Max retry attempts before abort |
| `EEZO_STM_WAVE_TIMEOUT_MS` | N | 1000 | Wave timeout safety bound (ms) |

### Consensus Mode

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `EEZO_CONSENSUS_MODE` | `dag-primary`, `dag`, `dag-hybrid` | varies | Active consensus mode |
| `EEZO_DAG_ORDERING_ENABLED` | 0, 1 | 1 | Enable DAG ordering |

---

## Next Steps (T82.1+)

T82.0 provides instrumentation only. Future milestones will optimize:

- **T82.1**: STM executor tuning (copy-on-write state)
- **T82.2**: Mempool + admission optimization
- **T82.3**: Executor metrics & conflict analytics
- **T82.4**: Conflict-aware scheduling

See [TPS_ARCHITECT_REPORT.md](../docs/TPS_ARCHITECT_REPORT.md) for the full roadmap.
