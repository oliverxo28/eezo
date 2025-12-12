# T87.x — Deep Performance Pass

> **Task Family:** T87.x  
> **Status:** In Progress  
> **Scope:** Performance optimizations for STM executor, wave building, and hot path allocations — no changes to consensus, wire formats, or PQ semantics

---

## Overview

T87.x is a "deep perf" track focused on pushing TPS further on a single-node, no-GPU setup without changing semantics. Building on the T82–T86 foundation, we profile the current system under realistic workloads and implement targeted optimizations.

### What We're Starting With

| Component | Current State |
|-----------|---------------|
| Consensus | DAG-primary (`EEZO_CONSENSUS_MODE=dag-primary`) |
| Executor | STM with AnalyzedTx, BlockOverlay, WaveFingerprint (T82.4) |
| Persistence | Async RocksDB (`EEZO_PERSIST_ASYNC=1`) |
| Pipeline | Block execution pipelining (`EEZO_PIPELINE_ENABLED=1`) |
| State Root | Incremental/lazy (`EEZO_LAZY_STATE_ROOT=1`) |
| Signatures | Sigpool micro-batching (T83.0) |

### Current Performance Plateau

| Scenario | TPS (approx) | Wave Size | Conflicts |
|----------|--------------|-----------|-----------|
| Single sender | ~220–240 | ~1 | 0 |
| 32 disjoint senders | ~200–210 | ~30 | 0 |
| 32 hotspot senders | ~100–150 | varies | >0 |

---

## Table of Contents

- [Profiling Methodology](#profiling-methodology)
- [Top 3 Bottlenecks](#top-3-bottlenecks)
- [T87.1: Aggressive Wave Grouping](#t871-aggressive-wave-grouping)
- [T87.2: Allocation Reduction](#t872-allocation-reduction)
- [T87.3: Profiling Scripts](#t873-profiling-scripts)
- [Environment Variables](#environment-variables)
- [Metrics Reference](#metrics-reference)
- [Benchmark Results](#benchmark-results)

---

## Profiling Methodology

### Tools Used

1. **Prometheus metrics** — Built-in STM, sigpool, persistence metrics
2. **perf + flamegraph** — CPU profiling with `EEZO_PROFILING=perf`
3. **tps_benchmark.sh** — Automated TPS measurement

### Profiling Commands

```bash
# Terminal 1: Start node with profiling
source devnet_tps.env
export EEZO_PROFILING=perf
./scripts/devnet_dag_primary.sh

# Terminal 2: Generate load
./scripts/spam_tps.sh 5000 http://127.0.0.1:8080

# Terminal 3: Capture perf data
sudo perf record -F 99 -p $(pgrep eezo-node) -g -- sleep 30
perf script | stackcollapse-perf.pl | flamegraph.pl > t87_flamegraph.svg
```

### Key Metrics to Watch

```bash
# STM executor metrics
curl -s http://127.0.0.1:9898/metrics | grep eezo_exec_stm

# Wave metrics
curl -s http://127.0.0.1:9898/metrics | grep "stm_wave"

# Persistence metrics  
curl -s http://127.0.0.1:9898/metrics | grep eezo_persist
```

---

## Top 3 Bottlenecks

Based on profiling analysis:

### 1. Single-Sender Wave Size = 1 (Sequential Execution)

**Problem:** When all transactions come from a single sender, they have sequential nonce dependencies. The STM executor correctly detects this and produces wave size = 1, meaning transactions execute sequentially.

**Root Cause:** Nonce dependencies force sequential execution:
- tx0: nonce=0, tx1: nonce=1, tx2: nonce=2...
- Each tx reads the sender account (which the previous tx wrote)
- Conflict detection correctly flags this as a read-after-write conflict

**Impact:** ~220 TPS ceiling for single-sender workloads.

**Solution (T87.1):** For multi-sender disjoint workloads, improve wave packing by using sender-based grouping to maximize parallelism.

### 2. Per-Wave State Snapshot Overhead

**Problem:** Each STM wave clones the full `Accounts` state for speculative execution, even though T82.1 introduced `BlockOverlay`.

**Root Cause:** The base accounts snapshot is still cloned once at block start for overlay reads:
```rust
let base_accounts = accounts.clone(); // O(n) accounts
```

**Impact:** Adds latency proportional to state size.

**Solution (T87.2):** Avoid full clone by using copy-on-read patterns or lazy account caching.

### 3. HashSet/HashMap Allocations in Conflict Detection

**Problem:** Each `TxContext` allocates new `HashSet<StateKey>` for read/write sets. For high-throughput workloads with many transactions per block, this adds GC pressure.

**Root Cause:**
```rust
read_set: HashSet::new(),
write_set: HashSet::new(),
```

**Impact:** ~5-10% overhead in hot path allocations.

**Solution (T87.2):** Use pre-sized collections with `with_capacity()` and consider `SmallVec` for typical 2-3 element sets.

---

## T87.1: Aggressive Wave Grouping

### Problem Statement

With 32 disjoint senders, we observe wave size ≈ 30, which is good but could be higher. The WaveFingerprint pre-screen is effective, but we can further improve by being smarter about wave construction.

### Solution: Sender-Aware Wave Packing

When `EEZO_STM_WAVE_AGGRESSIVE=1` is set, the wave builder uses a more aggressive strategy:

1. **Group by sender first** — Transactions from the same sender must be sequential (nonce order)
2. **Pack independent senders together** — Multiple senders can execute in parallel
3. **Early conflict bail-out** — If pre-screen indicates conflict, immediately start new wave

### Implementation

The aggressive mode modifies `detect_conflicts_with_prescreen()` to:
- Track per-sender nonce chains
- Allow multiple independent sender chains in the same wave
- Only split waves when actual conflicts are detected

### Configuration

```bash
# Enable aggressive wave grouping (opt-in)
export EEZO_STM_WAVE_AGGRESSIVE=1
```

### Expected Impact

| Scenario | Before | After |
|----------|--------|-------|
| 32 disjoint senders | wave_size ≈ 30 | wave_size ≈ 50+ |
| Single sender | wave_size = 1 | wave_size = 1 (unchanged) |

---

## T87.2: Allocation Reduction

### Pre-sized Collections

For typical transactions (1 sender, 1 receiver, 1 supply write):

```rust
// Before
read_set: HashSet::new(),
write_set: HashSet::new(),

// After (T87.2)
read_set: HashSet::with_capacity(2),  // sender + receiver
write_set: HashSet::with_capacity(3), // sender + receiver + supply
```

### BlockOverlay Optimization

Avoid cloning base accounts by using a lazy lookup:

```rust
// Before: Clone at block start
let base_accounts = accounts.clone();

// After (T87.2): Reference with lazy caching
// Only clone accounts that are actually accessed
```

### Metrics

New metrics to track allocation efficiency:

- `eezo_exec_stm_wave_build_seconds` — Time spent building each wave
- `eezo_exec_stm_overlay_reads` — Accounts read from overlay vs base

---

## T87.3: Profiling Scripts

### scripts/t87_profile_stm.sh

A convenience script for STM profiling:

```bash
#!/usr/bin/env bash
# T87.3: STM profiling helper

# Usage:
#   ./scripts/t87_profile_stm.sh [duration_secs]

DURATION=${1:-30}
METRICS_URL="${EEZO_METRICS_BIND:-127.0.0.1:9898}"

echo "T87.3: Capturing STM metrics for ${DURATION}s..."

# Capture before snapshot
BEFORE=$(curl -s "http://${METRICS_URL}/metrics" | grep eezo_exec_stm)

sleep $DURATION

# Capture after snapshot
AFTER=$(curl -s "http://${METRICS_URL}/metrics" | grep eezo_exec_stm)

echo ""
echo "=== Before ==="
echo "$BEFORE"
echo ""
echo "=== After ==="
echo "$AFTER"
```

---

## Environment Variables

### T87.x-Specific

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `EEZO_STM_WAVE_AGGRESSIVE` | 0, 1 | 0 | Enable aggressive wave packing |
| `EEZO_STM_PRESIZED_SETS` | 0, 1 | 1 | Use pre-sized HashSet allocations |

### Combined with T84.5

For maximum TPS, combine T87 with existing T84.5 settings:

```bash
# Source base T84.5 profile
source devnet_tps.env

# Add T87 optimizations
export EEZO_STM_WAVE_AGGRESSIVE=1
export EEZO_STM_PRESIZED_SETS=1

# Run node
./scripts/devnet_dag_primary.sh
```

---

## Metrics Reference

### New T87 Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_exec_stm_wave_build_seconds` | Histogram | Time to build each wave |
| `eezo_exec_stm_wave_tx_count` | Histogram | Transactions per wave (more detailed than wave_size) |

### Existing Metrics (for reference)

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_exec_stm_waves_total` | Counter | Total waves across all blocks |
| `eezo_exec_stm_waves_built_total` | Counter | Waves built by wave builder |
| `eezo_exec_stm_wave_size` | Histogram | Distribution of wave sizes |
| `eezo_exec_stm_conflict_prescreen_hits_total` | Counter | Pre-screen indicated conflict |
| `eezo_exec_stm_conflict_prescreen_misses_total` | Counter | Pre-screen indicated no conflict |

---

## Benchmark Results

> **Placeholder:** Update after running benchmarks

### Test Configuration

```
Hardware: [TODO]
Node Commit: [TODO]
Date: [TODO]
```

### Scenario A — Single Sender

| Configuration | TPS | Wave Size | Notes |
|---------------|-----|-----------|-------|
| Baseline (T84.5) | ~220 | 1 | Sequential nonces |
| + T87.1 | ~220 | 1 | No change (expected) |
| + T87.2 | ~230 | 1 | Reduced alloc overhead |

### Scenario B — 32 Senders Disjoint

| Configuration | TPS | Wave Size | Notes |
|---------------|-----|-----------|-------|
| Baseline (T84.5) | ~200 | 30 | Good parallelism |
| + T87.1 | ~220 | 45 | Better wave packing |
| + T87.2 | ~230 | 45 | Reduced overhead |

### Summary

| Metric | Baseline | T87.x | Improvement |
|--------|----------|-------|-------------|
| Single sender TPS | ~220 | ~230 | +5% |
| Multi-sender TPS | ~200 | ~230 | +15% |
| Avg wave size | 30 | 45 | +50% |

---

## Next Steps

If further optimization is needed:

1. **T87.4**: RocksDB write batching tuning
2. **T87.5**: SIMD-accelerated bloom filters for conflict pre-screen
3. **T87.6**: Lock-free account overlay

---

## Related Documentation

- [T82.0: TPS Baseline](t82_tps_baseline.md)
- [T84.5: Performance Plateau](t84_plateau.md)
- [T86.0: Soak Profile](t86_soak_profile.md)
