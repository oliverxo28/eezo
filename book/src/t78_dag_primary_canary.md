# T78.6: DAG-Primary Canary & SLO Runbook

## Overview

This runbook defines the procedure for running a **dag-primary canary** on Element Zero (EEZO). The dag-primary mode uses DAG as the **only** source of transaction ordering for committed blocks, with HotStuff running as a shadow checker (no effect on block production).

### Background

The `dag-primary` mode (`EEZO_CONSENSUS_MODE=dag-primary`) is a stepping stone toward pure DAG consensus:

- Transactions are ordered **exclusively** via DAG consensus
- No mempool fallback (empty blocks if no valid DAG txs)
- HotStuff runs as a shadow checker to validate DAG ordering correctness
- Mismatch detection ensures DAG produces correct ordering before removing HotStuff entirely

### Goals

1. **Validate DAG-only ordering**: All transactions processed through DAG path
2. **Zero shadow mismatches**: DAG ordering matches expected behavior
3. **Confirm liveness**: Transactions included under load (no stalls)
4. **Monitor performance**: Sustained TPS with dev-unsafe enabled

### Roadmap Context

| Task | Description |
|------|-------------|
| **T78.5** | Completed: dag-primary mode with real shadow HotStuff checker |
| **T78.6** | This task: Canary runbook, SLO scripts, and alerts |
| **T78.7+** | Future: Remove HotStuff entirely |

---

## Environment Setup

### Required Environment Variables

Create or update your environment file (e.g., `devnet.env`):

```bash
# --- Core Consensus Mode ---
# Enable DAG-Primary mode (3 = dag-primary)
export EEZO_CONSENSUS_MODE=dag-primary

# Enable DAG ordering layer (required)
export EEZO_DAG_ORDERING_ENABLED=1

# Enable shadow HotStuff checker
export EEZO_DAG_PRIMARY_SHADOW_ENABLED=1

# Enable strict hybrid profile (recommended for dag-primary)
export EEZO_HYBRID_STRICT_PROFILE=1

# --- STM Executor (T73/T76) ---
export EEZO_EXECUTOR_MODE=stm
export EEZO_EXEC_LANES=32
export EEZO_EXEC_WAVE_CAP=256

# --- Aggregation ---
export EEZO_HYBRID_AGG_TIME_BUDGET_MS=50
export EEZO_HYBRID_AGG_MAX_TX=500
export EEZO_HYBRID_AGG_MAX_BYTES=$((1 * 1024 * 1024))  # 1 MiB

# --- Mempool ---
export EEZO_MEMPOOL_MAX_LEN=100000
export EEZO_MEMPOOL_MAX_BYTES=$((256 * 1024 * 1024))  # 256 MiB
export EEZO_MEMPOOL_RATE_CAP=100000
export EEZO_MEMPOOL_RATE_PER_MIN=600000

# --- Metrics ---
export EEZO_METRICS_BIND=127.0.0.1:9898
export EEZO_LISTEN=127.0.0.1:8080

# --- Data Directory ---
export EEZO_DATADIR=/tmp/eezo-canary
```

### Feature Flags

**For benchmarking with dev-unsafe (local testing only):**

Build the node with dev-unsafe mode for local TPS testing:

```bash
cargo build --release -p eezo-node --features "metrics,pq44-runtime,checkpoints,dev-unsafe,stm-exec,dag-consensus"
```

> ⚠️ **WARNING**: Dev-unsafe builds should NEVER be deployed to any network.
> They are only for local development benchmarks.

**For devnet-safe deployment:**

Build the node without dev-unsafe for real devnet:

```bash
# Option 1: Using devnet-safe meta-feature
cargo build --release -p eezo-node --features "devnet-safe"

# Option 2: Manual feature selection
cargo build --release -p eezo-node --features "metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus"

# Option 3: With HotStuff shadow checker for observability
cargo build --release -p eezo-node --features "devnet-safe,hotstuff-shadow"
```

---

## Terminal Setup

### Terminal 1: Start the Node (Benchmark Mode)

**For local benchmarking with unsigned transactions:**

```bash
# Source environment
source devnet.env

# Clear previous data (optional, for fresh start)
rm -rf /tmp/eezo-canary

# Set dev-unsafe mode for unsigned tx benchmarking
# NOTE: This only works in dev-unsafe builds!
export EEZO_DEV_ALLOW_UNSIGNED_TX=1

# Start the node
./target/release/eezo-node
```

### Terminal 1: Start the Node (Devnet-Safe Mode)

**For real devnet deployment:**

```bash
# Source environment (or use defaults)
source devnet.env

# Clear previous data (optional, for fresh start)
rm -rf /tmp/eezo-canary

# Do NOT set EEZO_DEV_ALLOW_UNSIGNED_TX - it has no effect in devnet-safe builds
# Start the node (dag-primary is the default)
./target/release/eezo-node
```

Verify the node is running in dag-primary mode:

```bash
# Check consensus mode gauge (expect 3 = dag-primary)
curl -s http://127.0.0.1:9898/metrics | grep eezo_consensus_mode_active
# Expected: eezo_consensus_mode_active 3
```

### Terminal 2: Generate Keys and Fund Accounts

```bash
# Generate ML-DSA keypair
./target/release/ml_dsa_keygen

# Export the generated keys (copy from ml_dsa_keygen output)
export EEZO_TX_FROM=0x<your_address>
export EEZO_TX_PK_HEX=<your_public_key_hex>
export EEZO_TX_SK_HEX=<your_secret_key_hex>

# Fund the account via faucet
curl -s -X POST "http://127.0.0.1:8080/faucet" \
  -H "Content-Type: application/json" \
  -d "{\"to\":\"$EEZO_TX_FROM\",\"amount\":\"1000000000000\"}"

# Verify balance
curl -s "http://127.0.0.1:8080/account/${EEZO_TX_FROM,,}"
```

Run spam test:

```bash
# Submit 1000 transactions
scripts/spam_tps.sh 1000 http://127.0.0.1:8080
```

### Terminal 3: Run SLO Checker

```bash
# Run the dag-primary canary check
scripts/t78_dag_primary_canary_check.sh http://127.0.0.1:9898/metrics

# With custom TPS window (default 60s)
scripts/t78_dag_primary_canary_check.sh http://127.0.0.1:9898/metrics --tps-window=30
```

---

## SLO Definitions

### SLO 1: Correct Consensus Mode

**Goal**: Node must be running in dag-primary mode.

**Metric**: `eezo_consensus_mode_active`

**Threshold**: Must equal `3` (dag-primary)

**Query**:
```bash
curl -s http://127.0.0.1:9898/metrics | grep '^eezo_consensus_mode_active '
# Expected: eezo_consensus_mode_active 3
```

---

### SLO 2: Shadow Checker Active

**Goal**: Shadow HotStuff checker must be running.

**Metric**: `eezo_dag_primary_shadow_checks_total`

**Threshold**: Must be > 0 and increasing over the monitoring window.

**Query**:
```bash
curl -s http://127.0.0.1:9898/metrics | grep '^eezo_dag_primary_shadow_checks_total '
# Expected: Steadily increasing counter
```

**Prometheus Expression**:
```
increase(eezo_dag_primary_shadow_checks_total[5m]) > 0
```

---

### SLO 3: Zero Shadow Mismatches

**Goal**: DAG ordering must match shadow HotStuff ordering.

**Metric**: `eezo_dag_primary_shadow_mismatch_total`

**Threshold**: Must be `0` (any mismatch is critical)

**Query**:
```bash
curl -s http://127.0.0.1:9898/metrics | grep '^eezo_dag_primary_shadow_mismatch_total '
# Expected: eezo_dag_primary_shadow_mismatch_total 0
```

**Prometheus Expression**:
```
increase(eezo_dag_primary_shadow_mismatch_total[5m]) == 0
```

---

### SLO 4: Transaction Liveness

**Goal**: Transactions must be included under load.

**Metric**: `eezo_txs_included_total`

**Threshold**: Must be increasing over the monitoring window when load is present.

**Query**:
```bash
curl -s http://127.0.0.1:9898/metrics | grep '^eezo_txs_included_total '
```

**Prometheus Expression**:
```
increase(eezo_txs_included_total[5m]) > 0
```

---

### SLO 5: TPS Performance (dev-unsafe)

**Goal**: Sustain ≥150 TPS with dev-unsafe enabled.

**Metric**: `eezo_txs_included_total` (rate over window)

**Threshold**: `increase(eezo_txs_included_total[60s]) / 60 >= 150`

**Query using script**:
```bash
scripts/measure_tps.sh 60 http://127.0.0.1:9898/metrics
```

---

## Failure Interpretation

### Shadow Mismatch > 0

**Symptom**: `eezo_dag_primary_shadow_mismatch_total` is non-zero

**Meaning**: DAG ordering produced a different result than the shadow HotStuff checker. This indicates a potential bug in DAG ordering logic.

**Actions**:
1. Immediately capture logs:
   ```bash
   cp /tmp/eezo-canary/*.log /tmp/eezo-canary-debug/
   ```
2. Check mismatch reason:
   ```bash
   curl -s http://127.0.0.1:9898/metrics | grep eezo_dag_primary_shadow_mismatch_reason_total
   ```
3. **Stop the canary** - do not proceed with dag-only transition
4. Report bug with logs and metrics snapshot

### No Shadow Checks While Blocks Apply

**Symptom**: `block_applied_total` is increasing but `eezo_dag_primary_shadow_checks_total` is flat

**Meaning**: Shadow checker is not running despite blocks being committed. This could indicate:
- Shadow checker disabled
- Shadow checker crashed
- Configuration issue

**Actions**:
1. Verify environment variable:
   ```bash
   echo $EEZO_DAG_PRIMARY_SHADOW_ENABLED
   # Expected: 1
   ```
2. Check node logs for shadow checker errors
3. Restart node if necessary

### TPS Drops to 0 with Mempool Load

**Symptom**: `eezo_txs_included_total` flat while `eezo_mempool_len` > 0

**Meaning**: Transactions are queued but not being included. In dag-primary mode, this could indicate:
- DAG ordering stalled
- All transactions filtered by nonce contiguity filter
- No valid DAG batches available

**Actions**:
1. Check DAG ordered queue:
   ```bash
   curl -s http://127.0.0.1:9898/metrics | grep eezo_dag_ordered_ready
   ```
2. Check nonce gap drops:
   ```bash
   curl -s http://127.0.0.1:9898/metrics | grep eezo_dag_hybrid_nonce_gap_dropped_total
   ```
3. For single-sender workloads, high nonce gaps are expected - use multi-sender spam for better throughput

---

## Rollback Procedure

If critical issues are discovered, rollback to dag-hybrid mode:

```bash
# Stop the node
pkill -f eezo-node  # Or use proper service stop

# Switch to dag-hybrid mode (with fallback)
export EEZO_CONSENSUS_MODE=dag-hybrid
unset EEZO_DAG_PRIMARY_SHADOW_ENABLED

# Restart
./target/release/eezo-node
```

Verify rollback:
```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_consensus_mode_active
# Expected: eezo_consensus_mode_active 1  (1 = hybrid)
```

---

## SLO Checker Script

A helper script is provided to validate all SLOs:

```bash
# Basic check
scripts/t78_dag_primary_canary_check.sh http://127.0.0.1:9898/metrics

# With custom TPS window
scripts/t78_dag_primary_canary_check.sh http://127.0.0.1:9898/metrics --tps-window=30
```

The script checks:
1. ✓ Consensus mode is exactly 3 (dag-primary)
2. ✓ Shadow checks are > 0 and increasing
3. ✓ Shadow mismatches are 0
4. ✓ Transactions included over the window
5. ✓ Optional: TPS >= threshold

Exit codes:
- `0`: All SLOs passing
- `1`: One or more SLOs failing
- `2`: Metrics endpoint unreachable

---

## Metrics Reference

### Mode Detection

| Metric | Value | Mode |
|--------|-------|------|
| `eezo_consensus_mode_active` | 0 | hotstuff |
| `eezo_consensus_mode_active` | 1 | dag-hybrid |
| `eezo_consensus_mode_active` | 2 | dag |
| `eezo_consensus_mode_active` | 3 | dag-primary |

### Shadow Checker Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_dag_primary_shadow_checks_total` | Counter | Shadow checks performed |
| `eezo_dag_primary_shadow_mismatch_total` | Counter | Ordering mismatches detected |
| `eezo_dag_primary_shadow_mismatch_reason_total{reason="..."}` | Counter | Mismatch breakdown by reason |

### Performance Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_txs_included_total` | Counter | Total transactions in blocks |
| `block_applied_total` | Counter | Blocks applied |
| `eezo_block_height` | Gauge | Current block height |
| `eezo_mempool_len` | Gauge | Mempool queue size |

---

## References

- [T78: DAG-Only Devnet & Strict Hybrid Tuning](t78_dag_only_devnet.md)
- [T76: DAG-Hybrid Canary & SLO Runbook](t76_dag_hybrid_canary.md)
- [Dev Unsafe Modes](dev_unsafe_modes.md)