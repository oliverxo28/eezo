# T83.1 — Multi-sender TPS & Conflict Baseline

> **Task:** T83.1  
> **Status:** Implemented  
> **Scope:** Multi-sender load generation and conflict profiling — no changes to STM semantics, consensus, or mempool algorithms

---

## Overview

T83.1 provides a realistic TPS and conflict profiling story by:

1. **Multi-sender Spam Tool** — Generate configurable conflict patterns with many senders and optional "hot" receivers
2. **Conflict Profiling Workflow** — Document how to use existing STM metrics to analyze contention
3. **Baseline Experiments** — Recommended test configurations for comparing low vs high conflict scenarios

---

## Table of Contents

- [Why Multi-sender Testing?](#why-multi-sender-testing)
- [Quick Start](#quick-start)
- [Conflict Patterns Explained](#conflict-patterns-explained)
- [Running Multi-sender Benchmarks](#running-multi-sender-benchmarks)
- [Interpreting STM Metrics](#interpreting-stm-metrics)
- [Recommended Baseline Experiments](#recommended-baseline-experiments)
- [Troubleshooting](#troubleshooting)

---

## Why Multi-sender Testing?

Single-sender spam testing (using `scripts/spam_tps.sh`) is useful for measuring raw throughput, but it doesn't stress-test the STM executor's conflict resolution capabilities:

### Limitations of Single-sender Testing

- **No write-write conflicts**: All transactions come from one sender with sequential nonces
- **No contention on receiver state**: Typically targets a single receiver address
- **Unrealistic workload**: Real blockchain traffic comes from many independent senders

### What Multi-sender Testing Provides

- **Realistic concurrency**: Multiple senders submitting transactions simultaneously
- **Configurable conflicts**: Control the level of state contention
- **STM stress testing**: Exercise the Block-STM executor's conflict detection and retry logic
- **Performance baselines**: Compare TPS under low vs high conflict scenarios

---

## Quick Start

```bash
# Terminal 1: Start the DAG-primary devnet node
./scripts/devnet_dag_primary.sh

# Terminal 2: Generate multi-sender load (high conflict)
./scripts/spam_multi_senders.sh \
  --senders 16 \
  --per-sender 200 \
  --hot-receivers 1 \
  --pattern hotspot

# Terminal 3: Run TPS benchmark
./scripts/tps_benchmark.sh --duration 60 --warmup 10 --verbose
```

---

## Conflict Patterns Explained

The `spam_multi_senders.sh` script supports two conflict patterns:

### Disjoint Pattern (Low Conflict)

```bash
./scripts/spam_multi_senders.sh --pattern disjoint --hot-receivers 16
```

- Each sender sends to receivers in a distributed manner
- Minimal write-write conflicts between senders
- STM executor should complete in few waves
- **Use case**: Measure maximum TPS with minimal contention

### Hotspot Pattern (High Conflict)

```bash
./scripts/spam_multi_senders.sh --pattern hotspot --hot-receivers 1
```

- All senders target a small set of "hot" receiver addresses
- Creates contention on shared state (receiver balances)
- STM executor will detect conflicts and retry transactions
- **Use case**: Stress-test conflict resolution, measure overhead

### Visual Comparison

```
Disjoint (16 senders, 16 receivers):
  Sender 1 → Receiver 1, Receiver 2, ...
  Sender 2 → Receiver 2, Receiver 3, ...
  ...
  (Each sender mostly targets unique receivers)

Hotspot (16 senders, 1 receiver):
  Sender 1 → Receiver 1 ←─┐
  Sender 2 → Receiver 1 ←─┤
  Sender 3 → Receiver 1 ←─┤  All competing for same state
  ...       → Receiver 1 ←─┘
```

---

## Running Multi-sender Benchmarks

### Prerequisites

1. Build the required binaries:

```bash
# Build the node with required features
cargo build -p eezo-node --features "devnet-safe,metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus"

# Build the keygen tool
cargo build -p eezo-crypto --bin ml_dsa_keygen

# Build the tx generator
cargo build -p eezo-node --bin eezo-txgen
```

2. Ensure `jq` and `curl` are installed:

```bash
# On Ubuntu/Debian
sudo apt-get install jq curl

# On macOS
brew install jq curl
```

### Command-Line Options

```bash
./scripts/spam_multi_senders.sh [OPTIONS]

Options:
  -s, --senders <num>        Number of distinct sender accounts (default: 16)
  -t, --per-sender <num>     Transactions per sender (default: 200)
  -r, --hot-receivers <num>  Number of "hot" target accounts (default: 1)
  -p, --pattern <mode>       Conflict pattern: "disjoint" or "hotspot" (default: hotspot)
  -n, --node <url>           Node HTTP URL (default: http://127.0.0.1:8080)
  -h, --help                 Show this help message
```

### Example Runs

#### Low Conflict Baseline

```bash
./scripts/spam_multi_senders.sh \
  --senders 16 \
  --per-sender 200 \
  --hot-receivers 16 \
  --pattern disjoint
```

#### High Conflict Stress Test

```bash
./scripts/spam_multi_senders.sh \
  --senders 16 \
  --per-sender 200 \
  --hot-receivers 1 \
  --pattern hotspot
```

#### Scaling Test (Many Senders)

```bash
./scripts/spam_multi_senders.sh \
  --senders 64 \
  --per-sender 100 \
  --hot-receivers 4 \
  --pattern hotspot
```

---

## Interpreting STM Metrics

The `tps_benchmark.sh` script reports STM executor metrics that are key to understanding conflict behavior:

### Core Metrics

| Metric | Description | What to Look For |
|--------|-------------|------------------|
| `eezo_exec_stm_waves_total` | Total execution waves | Higher = more retries needed |
| `eezo_exec_stm_waves_built_total` | Waves constructed | Should correlate with waves_total |
| `eezo_exec_stm_conflicts_total` | Detected conflicts | Higher with hotspot pattern |
| `eezo_exec_stm_retries_total` | Transaction retries | Higher = more contention |
| `eezo_exec_stm_aborted_total` | Aborted after max retries | Should be ~0 normally |

### Pre-screen Metrics (T82.4)

| Metric | Description | Interpretation |
|--------|-------------|----------------|
| `eezo_exec_stm_conflict_prescreen_hits_total` | Pre-screen caught conflict | Efficient early detection |
| `eezo_exec_stm_conflict_prescreen_misses_total` | Pre-screen missed conflict | Found during execution |

### Healthy vs Conflict-Heavy Patterns

**Healthy (Low Conflict)**:
```
STM Executor Metrics (T82.0):
  Total waves:              30
  Avg waves per block:      1.00        ← Close to 1.0 = minimal retries
  Total conflicts:          5
  Avg conflicts per block:  0.17        ← Low conflict rate
  Total retries:            8
  Total aborted:            0           ← No aborts = healthy
```

**Conflict-Heavy (High Conflict)**:
```
STM Executor Metrics (T82.0):
  Total waves:              90
  Avg waves per block:      3.00        ← Higher = more retry waves
  Total conflicts:          150
  Avg conflicts per block:  5.00        ← High conflict rate
  Total retries:            200
  Total aborted:            0           ← Still no aborts (good)
```

### Key Ratios to Monitor

1. **Waves per block**: 
   - Optimal: 1.0–1.5 
   - Acceptable: 1.5–3.0
   - Concerning: >3.0

2. **Conflicts as % of tx count**:
   - Low: <5%
   - Moderate: 5–15%
   - High: >15%

3. **Retries vs Total TX**:
   - If retries >> tx count, consider reducing hotspot intensity

---

## Recommended Baseline Experiments

Run these experiments to establish conflict baselines for your hardware:

### Experiment 1: Single Sender (Reference)

```bash
# Terminal 1: Start node
./scripts/devnet_dag_primary.sh

# Terminal 2: Single sender spam (requires ml_dsa_keygen setup)
# See scripts/spam_tps.sh for required env vars
./scripts/spam_tps.sh 3000

# Terminal 3: Benchmark
./scripts/tps_benchmark.sh --duration 60 --warmup 10 --verbose
```

Expected results:
- TPS: Baseline for your hardware
- Waves per block: ~1.0
- Conflicts: ~0

### Experiment 2: Multi-sender Disjoint (Low Conflict)

```bash
# Terminal 2: Multi-sender, low conflict
./scripts/spam_multi_senders.sh \
  --senders 16 \
  --per-sender 200 \
  --hot-receivers 16 \
  --pattern disjoint
```

Expected results:
- TPS: Similar to single sender (maybe slightly lower due to overhead)
- Waves per block: 1.0–1.5
- Conflicts: Low (< 5% of tx count)

### Experiment 3: Multi-sender Hotspot (High Conflict)

```bash
# Terminal 2: Multi-sender, high conflict
./scripts/spam_multi_senders.sh \
  --senders 16 \
  --per-sender 200 \
  --hot-receivers 1 \
  --pattern hotspot
```

Expected results:
- TPS: May drop 10–30% compared to disjoint
- Waves per block: 2.0–4.0
- Conflicts: High (> 15% of tx count)
- Retries: Significant increase

### Experiment 4: Scaling Senders

Try varying `NUM_SENDERS` with same total tx count:

| Senders | Tx/Sender | Total TX | Pattern |
|---------|-----------|----------|---------|
| 1       | 3200      | 3200     | N/A     |
| 4       | 800       | 3200     | hotspot |
| 16      | 200       | 3200     | hotspot |
| 64      | 50        | 3200     | hotspot |

Record TPS, waves/block, and conflicts for each configuration.

---

## Troubleshooting

### Script Exits with "ml_dsa_keygen not found"

Build the keygen binary:
```bash
cargo build -p eezo-crypto --bin ml_dsa_keygen
```

### Script Exits with "eezo-txgen not found"

Build the txgen binary:
```bash
cargo build -p eezo-node --bin eezo-txgen
```

### "Cannot reach node" Error

Ensure the node is running:
```bash
./scripts/devnet_dag_primary.sh
```

Wait a few seconds for it to start, then retry.

### No Transactions Appearing in Metrics

1. Check that transactions are being accepted:
   ```bash
   curl http://127.0.0.1:8080/health
   ```

2. Verify mempool is not rejecting transactions:
   - Check node logs for rejection reasons
   - Ensure accounts are properly funded

### High Abort Rate

If `eezo_exec_stm_aborted_total` is non-zero:
- Reduce conflict intensity (increase `--hot-receivers`)
- Check if `EEZO_STM_MAX_RETRIES` is set too low

---

## Related Documentation

- [T82.0: DAG TPS Baseline](t82_tps_baseline.md) — Single-sender TPS measurement
- [Dev-Unsafe Modes](dev_unsafe_modes.md) — Build profiles for benchmarking
- [T83.0: Sigpool Pipeline](t83_sigpool_pipeline.md) — Signature verification pipeline

---

## Metrics Reference (Quick Reference)

```bash
# Fetch all STM metrics in one shot
curl -s http://127.0.0.1:9898/metrics | grep eezo_exec_stm

# Expected output includes:
# eezo_exec_stm_waves_total <count>
# eezo_exec_stm_waves_built_total <count>
# eezo_exec_stm_conflicts_total <count>
# eezo_exec_stm_retries_total <count>
# eezo_exec_stm_aborted_total <count>
# eezo_exec_stm_conflict_prescreen_hits_total <count>
# eezo_exec_stm_conflict_prescreen_misses_total <count>
```
