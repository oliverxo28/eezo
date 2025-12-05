# T76.12: DAG-Hybrid 7-Day Canary & SLO Runbook

## Overview

This runbook defines the procedure for running a **7-day canary** of the DAG-Hybrid consensus mode on Element Zero (EEZO). The canary validates that the DAG ordering layer is stable, performant, and ready to become the default consensus mechanism.

### Background

The DAG-Hybrid mode (`EEZO_CONSENSUS_MODE=dag-hybrid`) introduces a DAG-based transaction ordering layer that runs alongside the existing Hotstuff BFT consensus. In this mode:

- Transactions are ordered via DAG consensus
- Hotstuff provides finality and acts as a fallback if DAG ordering fails
- The STM (Software Transactional Memory) executor processes transactions in parallel waves

### Goals

1. **Validate stability**: Zero hybrid fallbacks under normal load
2. **Confirm ordering correctness**: No hash mismatches between DAG and canonical ordering
3. **Ensure quality**: ≥99.9% apply success rate
4. **Measure performance**: Sustained ≥250–400 TPS on development hardware
5. **Test durability**: No lost/duplicated batches across restarts

### Roadmap Context

| Task | Description |
|------|-------------|
| **T76.11** | Current: DAG hybrid aggregation, STM executor, adaptive caps |
| **T76.12** | This task: Canary runbook and SLO scripts |
| **T77.x** | Future: Flip default to DAG, eventually remove Hotstuff |

---

## Environment Setup

### Required Environment Variables

Create or update your environment file (e.g., `devnet.env`):

```bash
# --- Core Consensus Mode ---
# Enable DAG-Hybrid mode (0=hotstuff, 1=hybrid, 2=dag)
export EEZO_CONSENSUS_MODE=dag-hybrid

# Enable DAG ordering layer
export EEZO_DAG_ORDERING_ENABLED=1

# --- STM Executor (T73/T76) ---
# Use STM executor for parallel transaction processing
export EEZO_EXECUTOR_MODE=stm

# Number of execution lanes (default: 16, recommended: 32-64)
export EEZO_EXEC_LANES=32

# Max transactions per wave (0=unlimited, recommended: 256)
export EEZO_EXEC_WAVE_CAP=256

# --- Hybrid Aggregation (T76.10) ---
# Time budget for batch aggregation in milliseconds
export EEZO_HYBRID_AGG_TIME_BUDGET_MS=100

# Max transactions per aggregated batch
export EEZO_HYBRID_AGG_MAX_TX=500

# Max bytes per aggregated batch
export EEZO_HYBRID_AGG_MAX_BYTES=$((1 * 1024 * 1024))  # 1 MiB

# Enable adaptive aggregation (adjusts budget based on load)
export EEZO_HYBRID_AGG_ADAPTIVE=1

# T77.1: Batch timeout — how long to wait for DAG batches before fallback (ms)
# Default is 30ms; increase if DAG ordering latency is high under load
# export EEZO_HYBRID_BATCH_TIMEOUT_MS=30

# --- Fast Decode Pool (T76.9) ---
# Enable zero-copy decode pool for improved tx processing
export EEZO_FAST_DECODE_ENABLED=1

# --- Block Builder ---
export EEZO_BLOCK_MAX_TX=500
export EEZO_BLOCK_TARGET_TIME_MS=1000

# --- Mempool ---
export EEZO_MEMPOOL_MAX_LEN=100000
export EEZO_MEMPOOL_MAX_BYTES=$((256 * 1024 * 1024))  # 256 MiB
export EEZO_MEMPOOL_RATE_CAP=100000
export EEZO_MEMPOOL_RATE_PER_MIN=600000

# --- Signature Pool ---
export EEZO_SIGPOOL_THREADS=8
export EEZO_SIGPOOL_QUEUE=20000

# --- Metrics ---
export EEZO_METRICS_BIND=127.0.0.1:9898
export EEZO_LISTEN=127.0.0.1:8080

# --- Data Directory ---
export EEZO_DATADIR=/tmp/eezo-canary
export EEZO_GENESIS=crates/genesis.min.json
```

### Feature Flags

Ensure the node binary is built with the required features:

```bash
cargo build --release -p eezo-node --features "metrics,pq44-runtime,checkpoints"
```

### Starting the Node

Single-node canary (local development):

```bash
# Source environment
source devnet.env

# Clear previous data (optional, for fresh start)
rm -rf /tmp/eezo-canary

# Start the node
./target/release/eezo-node
```

Verify the node is running in DAG-Hybrid mode:

```bash
# Check consensus mode gauge
curl -s http://127.0.0.1:9898/metrics | grep eezo_consensus_mode_active
# Expected: eezo_consensus_mode_active 1  (1 = hybrid)
```

---

## Load Generation

### Preparing Funded Accounts

Before running load tests, generate and fund test accounts:

```bash
# Generate ML-DSA keypairs (if using signed transactions)
./target/release/ml_dsa_keygen > keys.json

# Fund accounts via faucet
for addr in $(cat keys.json | jq -r '.[] | .address'); do
  curl -s -X POST "http://127.0.0.1:8080/faucet" \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$addr\",\"amount\":\"1000000000\"}"
done
```

### Load Generation Scripts

**Single-sender spam (for quick tests):**

```bash
# Send 1000 transactions from a single account
# Set EEZO_TX_FROM, EEZO_TX_PK_HEX, EEZO_TX_SK_HEX first
scripts/spam_tps.sh 1000 http://127.0.0.1:8080
```

**Multi-sender spam (for sustained load):**

```bash
# 2000 transactions across 20 concurrent users
scripts/spam_multi.sh 2000 20
```

### Recommended Canary Load Profile

For a 7-day canary, use a steady load pattern:

| Profile | Description | Command |
|---------|-------------|---------|
| **Baseline** | 100 tx/min steady | `while true; do scripts/spam_multi.sh 100 10; sleep 60; done` |
| **Moderate** | 1000 tx/min bursts | `while true; do scripts/spam_multi.sh 1000 20; sleep 60; done` |
| **Stress** | 2×1000 tx every 30s | `while true; do scripts/spam_multi.sh 1000 20; sleep 15; scripts/spam_multi.sh 1000 20; sleep 15; done` |

For the canary, start with **Baseline** for 24h, then increase to **Moderate** for the remaining 6 days.

---

## SLO Definitions & Metric Queries

### SLO 1: Zero Hybrid Fallbacks

**Goal**: The hybrid mode should never fall back to the legacy mempool path under normal load.

**Metric**: `eezo_dag_hybrid_fallback_total`

**Threshold**: Must remain flat (delta = 0 over 1 hour) under steady load.

**Query**:
```bash
# Check current fallback count
curl -s http://127.0.0.1:9898/metrics | grep eezo_dag_hybrid_fallback_total

# Monitor for increases (expect 0)
curl -s http://127.0.0.1:9898/metrics | grep '^eezo_dag_hybrid_fallback_total ' | awk '{print $2}'
```

**Alert Threshold**: `increase(eezo_dag_hybrid_fallback_total[1h]) > 1`

---

### SLO 2: Ordering in Sync

**Goal**: DAG ordering must match canonical Hotstuff ordering.

**Metrics**:
- `eezo_dag_shadow_hash_mismatch_total` — must be 0
- `eezo_dag_shadow_in_sync` — must be 1

**Query**:
```bash
# Check hash mismatches (should be 0)
curl -s http://127.0.0.1:9898/metrics | grep eezo_dag_shadow_hash_mismatch_total

# Check sync status (should be 1)
curl -s http://127.0.0.1:9898/metrics | grep eezo_dag_shadow_in_sync
```

**Alert Threshold**: `eezo_dag_shadow_hash_mismatch_total > 0` or `eezo_dag_shadow_in_sync != 1`

---

### SLO 3: Healthy Queue

**Goal**: DAG ordered batches should be consumed promptly.

**Metrics**:
- `eezo_dag_ordered_ready` — queue gauge, should stay small (<10)

**Query**:
```bash
# Check ordered queue depth
curl -s http://127.0.0.1:9898/metrics | grep eezo_dag_ordered_ready
```

**Alert Threshold**: `eezo_dag_ordered_ready > 10` for 5 minutes

---

### SLO 4: Apply Quality ≥99.9%

**Goal**: At least 99.9% of transactions from DAG batches should apply successfully.

**Metrics**:
- `eezo_dag_hybrid_apply_ok_total`
- `eezo_dag_hybrid_apply_fail_total`

**Formula**: `apply_ok / (apply_ok + apply_fail) >= 0.999`

**Query**:
```bash
# Get apply counts
OK=$(curl -s http://127.0.0.1:9898/metrics | grep '^eezo_dag_hybrid_apply_ok_total ' | awk '{print $2}')
FAIL=$(curl -s http://127.0.0.1:9898/metrics | grep '^eezo_dag_hybrid_apply_fail_total ' | awk '{print $2}')
echo "Apply OK: $OK, Fail: $FAIL, Ratio: $(echo "scale=6; $OK / ($OK + $FAIL)" | bc -l)"
```

**Alert Threshold**: 
```
(rate(eezo_dag_hybrid_apply_ok_total[5m]) / 
 (rate(eezo_dag_hybrid_apply_ok_total[5m]) + rate(eezo_dag_hybrid_apply_fail_total[5m]))) < 0.999
```

**Note**: `eezo_dag_hybrid_bad_nonce_prefilter_total` may increase during spam tests with multiple senders; this is expected and does not count as apply failures.

---

### SLO 5: Durability

**Goal**: No lost or duplicated batches across crash/restart cycles.

**Metrics**:
- `eezo_block_height` — must be strictly increasing
- `eezo_txs_included_total` — should increase monotonically

**Verification**:
```bash
# Before restart
H1=$(curl -s http://127.0.0.1:9898/metrics | grep '^eezo_block_height ' | awk '{print $2}')

# After restart
H2=$(curl -s http://127.0.0.1:9898/metrics | grep '^eezo_block_height ' | awk '{print $2}')

# H2 should equal or exceed H1 (no rollback)
echo "Before: $H1, After: $H2"
[ "$H2" -ge "$H1" ] && echo "OK: Height preserved" || echo "FAIL: Height rolled back"
```

---

### SLO 6: Performance ≥250-400 TPS

**Goal**: Sustain at least 250-400 TPS on development hardware.

**Metric**: `eezo_txs_included_total` (rate over time window)

**Query using built-in script**:
```bash
# Measure TPS over 30 seconds
scripts/measure_tps.sh 30 http://127.0.0.1:9898/metrics
```

**Manual calculation**:
```bash
# Take two samples 60s apart
T1=$(curl -s http://127.0.0.1:9898/metrics | grep '^eezo_txs_included_total ' | awk '{print $2}')
sleep 60
T2=$(curl -s http://127.0.0.1:9898/metrics | grep '^eezo_txs_included_total ' | awk '{print $2}')
TPS=$(echo "scale=2; ($T2 - $T1) / 60" | bc -l)
echo "TPS: $TPS"
```

**Target Thresholds**:
| Hardware | Target TPS |
|----------|------------|
| Laptop (M1/i7) | 250-400 |
| Workstation | 500-800 |
| Server | 1000+ |

---

## SLO Checker Script

A helper script is provided to summarize all SLO metrics:

```bash
# Basic check
scripts/t76_dag_canary_check.sh http://127.0.0.1:9898/metrics

# Verbose output with TPS measurement
scripts/t76_dag_canary_check.sh http://127.0.0.1:9898/metrics --tps
```

See `scripts/t76_dag_canary_check.sh` for implementation details.

---

## Practical TPS vs Theoretical TPS

### Practical TPS Measurement

Practical TPS is measured by observing `eezo_txs_included_total` over a time window:

```
Practical TPS = Δ(eezo_txs_included_total) / Δt
```

This represents **real-world throughput** including:
- Network latency
- Mempool admission
- DAG ordering
- STM execution
- Block finalization

### Theoretical TPS Formulas

**Compute-bound ceiling** (single-core, sequential execution):
```
TPS_compute = 1 / avg_tx_exec_time
```

**Bandwidth-bound ceiling** (network/IO limited):
```
TPS_bandwidth = network_throughput_bytes / avg_tx_size
```

**DAG-parallel ceiling** (with STM executor):
```
TPS_parallel = TPS_compute × parallelism_factor
parallelism_factor ≈ min(EEZO_EXEC_LANES, #independent_txs)
```

### Bridging Theory and Practice

The canary establishes the **practical TPS** that can be quoted in whitepapers:

| Metric | Formula | Typical Value |
|--------|---------|---------------|
| Theoretical Max | `EEZO_EXEC_LANES × 1000 / avg_exec_ms` | ~1000-2000 TPS |
| Practical Observed | `scripts/measure_tps.sh` | 250-400 TPS |
| Efficiency | `practical / theoretical` | 25-40% |

The gap between theoretical and practical TPS accounts for:
- Consensus overhead (~20%)
- Serialization/deserialization (~10%)
- Network latency (~15%)
- Block finalization (~10%)
- OS/runtime overhead (~5%)

---

## Failure Handling & Rollback

### If Fallbacks Occur

```bash
# 1. Check fallback count and reason
curl -s http://127.0.0.1:9898/metrics | grep eezo_dag_hybrid

# 2. Check if DAG ordering is lagging
curl -s http://127.0.0.1:9898/metrics | grep eezo_dag_ordered_ready

# 3. If persistent, reduce load or increase aggregation budget
export EEZO_HYBRID_AGG_TIME_BUDGET_MS=200
```

### If Hash Mismatches Occur

```bash
# 1. Immediately capture logs
cp /tmp/eezo-canary/*.log /tmp/eezo-canary-debug/

# 2. Check shadow sync status
curl -s http://127.0.0.1:9898/metrics | grep eezo_dag_shadow

# 3. Report bug with logs and metrics snapshot
```

### Rollback to Pure Hotstuff

If critical issues are discovered, rollback immediately:

```bash
# Stop the node
pkill -f eezo-node  # Or use proper service stop

# Switch to pure Hotstuff mode
export EEZO_CONSENSUS_MODE=hotstuff
export EEZO_DAG_ORDERING_ENABLED=0

# Restart
./target/release/eezo-node
```

Verify rollback:
```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_consensus_mode_active
# Expected: eezo_consensus_mode_active 0  (0 = hotstuff)
```

---

## Next Steps

After the 7-day canary passes all SLOs:

1. **T77.0**: Flip default consensus mode to DAG-Hybrid
   - Change default `EEZO_CONSENSUS_MODE` from `hotstuff` to `dag-hybrid`
   - Update documentation and deployment guides

2. **T77.1**: Extended canary on testnet
   - Run 30-day canary on public testnet
   - Monitor with external validators

3. **T77.2**: Mainnet rollout
   - Gradual rollout with feature flags
   - Canary percentage: 10% → 50% → 100%

4. **T78.x**: Remove Hotstuff fallback
   - Delete legacy consensus code paths
   - Simplify hybrid mode to pure DAG

---

## Appendix: Full Metrics Reference

### Core DAG Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_consensus_mode_active` | Gauge | 0=hotstuff, 1=hybrid, 2=dag |
| `eezo_dag_ordered_ready` | Gauge | Batches ready for consumption |
| `eezo_dag_hybrid_fallback_total` | Counter | Fallbacks to mempool |
| `eezo_dag_hybrid_batches_used_total` | Counter | DAG batches consumed |
| `eezo_dag_ordering_latency_seconds` | Histogram | DAG ordering latency (T77.1) |

### Apply Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_dag_hybrid_apply_ok_total` | Counter | Successful applies |
| `eezo_dag_hybrid_apply_fail_total` | Counter | Failed applies |
| `eezo_dag_hybrid_apply_fail_bad_nonce_total` | Counter | Bad nonce failures |
| `eezo_dag_hybrid_apply_fail_insufficient_funds_total` | Counter | Insufficient funds |

### Shadow Sync Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_dag_shadow_in_sync` | Gauge | 1=in sync, 0=out of sync |
| `eezo_dag_shadow_lag_blocks` | Gauge | Blocks behind canonical |
| `eezo_dag_shadow_hash_mismatch_total` | Counter | Ordering mismatches |

### Aggregation Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_hybrid_agg_cap_reason_total{reason="..."}` | Counter | Why aggregation ended |
| `eezo_hybrid_agg_time_budget_ms` | Gauge | Current time budget |
| `eezo_hybrid_agg_adaptive_enabled` | Gauge | 1=adaptive, 0=fixed |

### Executor Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_exec_lanes` | Gauge | Configured execution lanes |
| `eezo_exec_wave_cap` | Gauge | Max tx per wave |
| `eezo_stm_waves_per_block` | Histogram | Waves per block |
| `eezo_stm_conflicts_per_block` | Histogram | Conflicts per block |

### General Node Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_txs_included_total` | Counter | Total txs in blocks |
| `eezo_block_height` | Gauge | Current block height |
| `eezo_mempool_len` | Gauge | Mempool queue size |