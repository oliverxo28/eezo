# T86.0 — DAG Soak Profile & Correctness Guardrails

> **Task:** T86.0  
> **Status:** Implemented  
> **Scope:** Soak testing, scripts, and documentation only — no changes to consensus, wire formats, or execution semantics

---

## Overview

T86.0 provides a **repeatable soak profile** for DAG + STM that:

1. Runs for longer windows (5–10 minutes)
2. Uses multi-sender traffic (both low-conflict and high-conflict)
3. Captures correctness + stability metrics
4. Gives a clear red/green signal if something regresses under real load

**Goal:** "Can EEZO's DAG engine run hot for a while without weirdness?"

This builds on the T82–T85 optimization arc:

| Task | Description |
|------|-------------|
| T82.x | STM metrics, overlay, conflict prescreen (WaveFingerprint), mempool actor |
| T83.0 | Sigpool micro-batching + metrics |
| T83.1 | Multi-sender spam generator (`spam_multi_senders.sh`) |
| T83.2 | Async persistence (CommittedMemHead, `EEZO_PERSIST_ASYNC=1`) |
| T83.3 | Block execution pipelining (`EEZO_PIPELINE_ENABLED=1`) |
| T83.4 | Zero-copy SharedTx propagation |
| T84.0 | Lazy/incremental state root (`EEZO_LAZY_STATE_ROOT=1`) |
| T84.5 | Plateau snapshot + regression guard |
| T85.0 | HotStuff removal (DAG is only consensus path) |

---

## Table of Contents

- [Why Soak Testing?](#why-soak-testing)
- [Canonical Scenarios](#canonical-scenarios)
- [Quick Start](#quick-start)
- [Running Soak Tests](#running-soak-tests)
- [Interpreting Results](#interpreting-results)
- [Sanity Checks Explained](#sanity-checks-explained)
- [Relationship to Other Tools](#relationship-to-other-tools)
- [Troubleshooting](#troubleshooting)

---

## Why Soak Testing?

Short benchmarks (20–60 seconds) are great for quick TPS measurements, but they don't catch:

- **Memory leaks** that accumulate over time
- **Queue backlogs** that grow under sustained load
- **State root overhead** that compounds across many blocks
- **Conflict patterns** that emerge only after many transactions
- **Persistence worker lag** under continuous block production

T86.0 soak testing runs for **5–10 minutes** to expose these issues before they hit production.

### What Soak Testing Reveals

| Issue | Short Benchmark | Soak Test |
|-------|-----------------|-----------|
| Raw TPS ceiling | ✓ | ✓ |
| Memory growth | ✗ | ✓ |
| Queue backlogs | Sometimes | ✓ |
| Conflict escalation | Rare | ✓ |
| Persistence lag | Rare | ✓ |
| State root pressure | Minimal | ✓ |

---

## Canonical Scenarios

T86.0 defines three scenarios that cover the range of workloads:

### Scenario A — Single Sender (Baseline)

- **Tool:** `spam_tps.sh`
- **Config:** ~5000 tx from a single sender
- **Purpose:** Confirm TPS ceiling in "zero conflict" land
- **Expected metrics:**
  - TPS: ~180–220 tx/s (hardware dependent)
  - `stm_conflicts_total`: 0
  - `stm_aborted_total`: 0
  - `waves_per_block`: ~1.0

### Scenario B — 32 Senders, Disjoint (Low Conflict)

- **Tool:** `spam_multi_senders.sh`
- **Config:** `--senders 32 --per-sender 200 --pattern disjoint --hot-receivers 32`
- **Purpose:** Test parallel execution with many independent senders
- **Expected metrics:**
  - TPS: ~160–200 tx/s
  - `stm_conflicts_total`: ~0 or very low
  - `stm_aborted_total`: 0
  - `waves_per_block`: ~1.0–1.5

### Scenario C — 32 Senders, Hotspot (High Conflict)

- **Tool:** `spam_multi_senders.sh`
- **Config:** `--senders 32 --per-sender 200 --pattern hotspot --hot-receivers 1`
- **Purpose:** Stress-test STM conflict detection and retry logic
- **Expected metrics:**
  - TPS: ~100–150 tx/s (lower due to conflicts)
  - `stm_conflicts_total`: Significantly higher
  - `stm_retries_total`: Non-zero
  - `stm_aborted_total`: Should still be ~0
  - `waves_per_block`: ~2.0–4.0

### Scenario Comparison Table

| Scenario | Pattern | Conflicts | TPS (approx) | Waves/Block |
|----------|---------|-----------|--------------|-------------|
| A | Single sender | None | ~180–220 | ~1.0 |
| B | 32 disjoint | Very low | ~160–200 | ~1.0–1.5 |
| C | 32 hotspot | High | ~100–150 | ~2.0–4.0 |

---

## Quick Start

### Prerequisites

1. Build the node and spam tools:

```bash
# Build node with required features
cargo build -p eezo-node --release --features "devnet-safe,metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus"

# Build keygen and txgen for multi-sender spam
cargo build -p eezo-crypto --bin ml_dsa_keygen
cargo build -p eezo-node --bin eezo-txgen
```

2. Ensure dependencies are installed:

```bash
# Required: jq, curl, bc
which jq curl bc
```

### Start Node with T84.5 Profile

```bash
# Terminal 1: Start devnet with max-perf settings
cd ~/Block/eezo  # or your repo path
source devnet_tps.env
./scripts/devnet_dag_primary.sh
```

### Run Soak Tests

```bash
# Terminal 2: Run Scenario A (5 minutes)
./scripts/t86_soak_run.sh --scenario A --duration 300 --warmup 30

# Run Scenario B (5 minutes)
./scripts/t86_soak_run.sh --scenario B --duration 300 --warmup 30

# Run Scenario C (5 minutes)
./scripts/t86_soak_run.sh --scenario C --duration 300 --warmup 30
```

---

## Running Soak Tests

### Command-Line Options

```bash
./scripts/t86_soak_run.sh [OPTIONS]

Options:
  -s, --scenario {A|B|C}     Scenario to run (default: A)
  -d, --duration <seconds>   Measurement window (default: 300)
  -w, --warmup <seconds>     Warm-up period (default: 30)
  -n, --node <url>           Node HTTP URL (default: http://127.0.0.1:8080)
  -m, --metrics <url>        Metrics URL (default: http://127.0.0.1:9898/metrics)
  -l, --label <string>       Optional label for the run
  -h, --help                 Show this help message
```

### Example: Shorter Soak for Quick Check

```bash
# 2-minute soak with 15-second warmup
./scripts/t86_soak_run.sh --scenario B --duration 120 --warmup 15
```

### Example: Labeled Run for Comparison

```bash
# Label runs for before/after comparison
./scripts/t86_soak_run.sh --scenario C --duration 300 --label "before-optimization"

# After making changes:
./scripts/t86_soak_run.sh --scenario C --duration 300 --label "after-optimization"
```

### Output Location

JSON summaries are written to:

```
t86_results/soak_<scenario>_<timestamp>.json
```

Example: `t86_results/soak_B_20240115_143022.json`

---

## Interpreting Results

### JSON Output Structure

```json
{
  "scenario": "B",
  "scenario_description": "32 Senders, Disjoint (low conflict)",
  "label": "my-test-run",
  "timestamp": "2024-01-15T14:30:22+00:00",
  "duration_seconds": 300,
  "warmup_seconds": 30,
  "node_url": "http://127.0.0.1:8080",
  "metrics_url": "http://127.0.0.1:9898/metrics",
  "tps": 175.32,
  "blocks_per_second": 0.95,
  "delta_txs": 52596,
  "delta_blocks": 285,
  "tx_target": 6400,
  "stm": {
    "waves_total": 320,
    "waves_built_total": 318,
    "conflicts_total": 42,
    "retries_total": 55,
    "aborted_total": 0,
    "prescreen_hits_total": 28,
    "prescreen_misses_total": 14
  },
  "mempool": {
    "len_at_end": 12,
    "inflight_len_at_end": 0
  },
  "sigpool": {
    "batches_total": 412,
    "avg_latency_seconds": 0.000842,
    "cache_hits_total": 1250,
    "cache_misses_total": 5150
  },
  "persistence": {
    "queue_len_at_end": 0,
    "blocks_total": 285,
    "head_entries_at_end": 156
  },
  "state_root": {
    "compute_count": 285,
    "recompute_accounts": 1420,
    "cached_accounts_at_end": 98
  }
}
```

### Key Fields to Check

| Field | What to Look For |
|-------|------------------|
| `tps` | Should be in expected range for scenario |
| `stm.aborted_total` | Should be 0 for A/B, low for C |
| `stm.conflicts_total` | ~0 for A, low for B, higher for C |
| `mempool.len_at_end` | Should be low (mempool drained) |
| `persistence.queue_len_at_end` | Should be 0 (persistence caught up) |
| `sigpool.avg_latency_seconds` | Should be sub-millisecond |

### What's "Normal" vs "Suspicious"

#### Scenario A (Single Sender)

| Metric | Normal | Suspicious |
|--------|--------|------------|
| `tps` | 150–250 | <100 |
| `stm.aborted_total` | 0 | >0 |
| `stm.conflicts_total` | 0 | >0 |
| `mempool.len_at_end` | <100 | >1000 |

#### Scenario B (Disjoint)

| Metric | Normal | Suspicious |
|--------|--------|------------|
| `tps` | 130–220 | <80 |
| `stm.aborted_total` | 0 | >0 |
| `stm.conflicts_total` | 0–50 | >500 |
| `mempool.len_at_end` | <100 | >1000 |

#### Scenario C (Hotspot)

| Metric | Normal | Suspicious |
|--------|--------|------------|
| `tps` | 80–180 | <50 |
| `stm.aborted_total` | 0–10 | >100 |
| `stm.conflicts_total` | 100–5000+ | N/A (expected high) |
| `mempool.len_at_end` | <500 | >5000 |

---

## Sanity Checks Explained

The soak script prints sanity check results at the end:

### OK Result

```
[t86] Soak sanity: OK
      No aborted txs, no backlog, persist queue drained
```

This means:
- Transactions were included as expected
- No unexpected aborts (for the scenario)
- Mempool and persistence queues drained properly

### WARN Result

```
[t86] Soak sanity: WARN
      - stm_aborted_total = 42 (expected ~0 for Scenario B)
      - eezo_persist_queue_len = 128 at end (possible async persist backlog)
```

This means something may need investigation.

### Sanity Checks Performed

| Check | Description | When It Warns |
|-------|-------------|---------------|
| Zero transactions | Spam was sent but nothing included | `delta_txs = 0` with `tx_target > 0` |
| Aborted in A/B | Aborts in low-conflict scenarios | `stm_aborted > 0` for A or B |
| High aborts in C | Excessive aborts even for hotspot | `stm_aborted > 100` for C |
| Mempool backlog | Transactions stuck in mempool | `mempool_len > 1000` at end |
| Persist backlog | Async persistence falling behind | `persist_queue_len > 50` at end |
| State root pressure | Incremental state root not effective | `recompute_accounts >> delta_txs * 10` |
| Low TPS | Lower than expected throughput | `TPS < 50` with active load |

---

## Relationship to Other Tools

### t84_regression_check.sh (Short Runs)

- **Purpose:** Quick regression check (20-second measurement)
- **Use case:** Before/after code changes, CI guard
- **Output:** Pass/fail exit code

### t86_soak_run.sh (Longer Runs)

- **Purpose:** Deep stability and correctness check (5–10 minutes)
- **Use case:** Pre-release validation, performance investigation
- **Output:** Detailed JSON + sanity hints

### Recommended Workflow

1. **After code changes:** Run `t84_regression_check.sh` for quick validation
2. **Before release:** Run `t86_soak_run.sh` for all three scenarios
3. **Investigating issues:** Use soak results to identify bottlenecks

```bash
# Quick regression check
./scripts/t84_regression_check.sh

# If passes, run full soak suite
./scripts/t86_soak_run.sh --scenario A --duration 300 --warmup 30
./scripts/t86_soak_run.sh --scenario B --duration 300 --warmup 30
./scripts/t86_soak_run.sh --scenario C --duration 300 --warmup 30
```

---

## Troubleshooting

### "Cannot reach node" Error

Ensure the node is running with T84.5 profile:

```bash
source devnet_tps.env
./scripts/devnet_dag_primary.sh
```

### Scenario A Shows No Transactions

For Scenario A, you need to set up sender credentials:

```bash
# Generate a keypair
eval "$(./target/debug/ml_dsa_keygen)"

# Fund the sender account
curl -X POST http://127.0.0.1:8080/faucet \
  -H "Content-Type: application/json" \
  -d "{\"to\":\"$EEZO_TX_FROM\",\"amount\":\"1000000\"}"

# Then run the soak
./scripts/t86_soak_run.sh --scenario A --duration 300
```

### Low TPS Across All Scenarios

Check that T84.5 optimizations are enabled:

```bash
env | grep EEZO
```

Should show:
- `EEZO_MEMPOOL_ACTOR_ENABLED=1`
- `EEZO_PERSIST_ASYNC=1`
- `EEZO_PIPELINE_ENABLED=1`
- `EEZO_LAZY_STATE_ROOT=1`

### Persistence Queue Growing

If `eezo_persist_queue_len` grows unbounded:

1. Check disk I/O with `iostat` or similar
2. Consider faster storage (NVMe)
3. Check RocksDB compaction status

### High Abort Rate in Scenario C

Some aborts are expected under extreme contention. If excessive:

1. Check `EEZO_STM_MAX_RETRIES` setting
2. Consider increasing retry limit for stress tests
3. Review if workload is realistic

---

## Related Documentation

- [T82.0: DAG TPS Baseline](t82_tps_baseline.md) — STM metrics and profiling
- [T83.1: Multi-sender Baseline](t83_multi_sender_baseline.md) — Conflict pattern testing
- [T83.2: Async Persistence](t83_async_persistence.md) — CommittedMemHead architecture
- [T84.5: Performance Plateau](t84_plateau.md) — Max-perf configuration
- [Dev-Unsafe Modes](dev_unsafe_modes.md) — Build profiles for benchmarking

---

## Appendix: Metrics Reference

### STM Metrics

```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_exec_stm
```

| Metric | Description |
|--------|-------------|
| `eezo_exec_stm_waves_total` | Total STM execution waves |
| `eezo_exec_stm_waves_built_total` | Waves constructed by builder |
| `eezo_exec_stm_conflicts_total` | Detected write-write conflicts |
| `eezo_exec_stm_retries_total` | Transactions retried |
| `eezo_exec_stm_aborted_total` | Transactions aborted after max retries |
| `eezo_exec_stm_conflict_prescreen_hits_total` | Early conflict detection hits |
| `eezo_exec_stm_conflict_prescreen_misses_total` | Conflicts found during execution |

### Mempool Metrics

```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_mempool
```

| Metric | Description |
|--------|-------------|
| `eezo_mempool_len` | Current mempool size |
| `eezo_mempool_inflight_len` | Transactions currently being processed |
| `eezo_mempool_actor_enabled` | Whether mempool actor is active |
| `eezo_mempool_batches_served_total` | Batches served to block builder |

### Sigpool Metrics

```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_sigpool
```

| Metric | Description |
|--------|-------------|
| `eezo_sigpool_batches_total` | Total signature batches processed |
| `eezo_sigpool_batch_latency_seconds` | Batch verification latency histogram |
| `eezo_sigpool_cache_hits_total` | Signature cache hits |
| `eezo_sigpool_cache_misses_total` | Signature cache misses |

### Persistence Metrics

```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_persist
```

| Metric | Description |
|--------|-------------|
| `eezo_persist_queue_len` | Blocks waiting to be persisted |
| `eezo_persist_blocks_total` | Total blocks persisted |
| `eezo_persist_head_entries` | Accounts in CommittedMemHead |

### State Root Metrics

```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_state_root
```

| Metric | Description |
|--------|-------------|
| `eezo_state_root_compute_seconds` | State root computation latency |
| `eezo_state_root_recompute_accounts` | Accounts recomputed (non-cached) |
| `eezo_state_root_cached_accounts` | Accounts served from cache |
