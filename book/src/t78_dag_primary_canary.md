# T78.6: DAG-Primary Canary & SLO Runbook

## Overview

This runbook defines the procedure for running a **dag-primary canary** on Element Zero (EEZO). The dag-primary mode uses DAG as the **only** source of transaction ordering for committed blocks.

### Background

The `dag-primary` mode (`EEZO_CONSENSUS_MODE=dag-primary`) is the production consensus mode:

- Transactions are ordered **exclusively** via DAG consensus
- No mempool fallback (empty blocks if no valid DAG txs)
- Pure DAG consensus with no legacy code paths

### Goals

1. **Validate DAG-only ordering**: All transactions processed through DAG path
2. **Confirm liveness**: Transactions included under load (no stalls)
3. **Monitor performance**: Sustained TPS with signed transactions

### Roadmap Context

| Task | Description |
|------|-------------|
| **T78.5** | Completed: dag-primary mode implementation |
| **T78.6** | This task: Canary runbook, SLO scripts, and alerts |
| **T81** | Completed: HotStuff removed from live codebase |

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

**For production deployment (recommended):**

Build the node with dag-only for production:

```bash
# Option 1: Using dag-only feature (recommended for production)
cargo build --release -p eezo-node --features "dag-only"

# Option 2: Using devnet-safe meta-feature
cargo build --release -p eezo-node \
  --features "devnet-safe,metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus"
```

**Run using the official launcher script:**
```bash
./scripts/devnet_dag_primary.sh
```

---

## Terminal Setup

### Terminal 1: Start the Node (Devnet-Safe Mode - Recommended)

**For official devnet deployment:**

```bash
# Use the official launcher script (recommended)
./scripts/devnet_dag_primary.sh
```

Or manually:

```bash
# Source environment
source devnet.env

# Clear previous data (optional, for fresh start)
rm -rf /tmp/eezo-canary

# Do NOT set EEZO_DEV_ALLOW_UNSIGNED_TX - it has no effect in devnet-safe builds
# Start the node (dag-primary is the default)
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

### SLO 2: Transaction Liveness

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

### SLO 3: Block Height Progress

**Goal**: Blocks must be produced consistently.

**Metric**: `eezo_block_height`

**Threshold**: Must be increasing over the monitoring window.

**Query**:
```bash
curl -s http://127.0.0.1:9898/metrics | grep '^eezo_block_height '
```

---

### SLO 4: TPS Performance

**Goal**: Sustain expected TPS with load.

**Metric**: `eezo_txs_included_total` (rate over window)

**Threshold**: TPS should be consistent with expected throughput.

**Query using script**:
```bash
scripts/measure_tps.sh 60 http://127.0.0.1:9898/metrics
```

---

## Failure Interpretation

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

If critical issues are discovered, investigate the metrics and logs:

```bash
# Check node logs for errors
journalctl -u eezo-node --since "10 minutes ago" | grep -i error

# Check DAG metrics
curl -s http://127.0.0.1:9898/metrics | grep -E "eezo_(dag|block|tx)"
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
2. ✓ Transactions included over the window
3. ✓ Block height is progressing
4. ✓ Optional: TPS >= threshold

Exit codes:
- `0`: All SLOs passing
- `1`: One or more SLOs failing
- `2`: Metrics endpoint unreachable

---

## Metrics Reference

### Mode Detection

| Metric | Value | Mode |
|--------|-------|------|
| `eezo_consensus_mode_active` | 3 | dag-primary (production) |

### Performance Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_txs_included_total` | Counter | Total transactions in blocks |
| `block_applied_total` | Counter | Blocks applied |
| `eezo_block_height` | Gauge | Current block height |
| `eezo_mempool_len` | Gauge | Mempool queue size |

---

## TPS Window Options for Canary Check

The `scripts/t78_dag_primary_canary_check.sh` script supports a `--tps-window` option for different testing scenarios:

```bash
# Short burst (1000 tx spam test)
scripts/t78_dag_primary_canary_check.sh http://127.0.0.1:9898/metrics --tps-window=5

# Standard window (default)
scripts/t78_dag_primary_canary_check.sh http://127.0.0.1:9898/metrics --tps-window=60

# Long-running soak test
scripts/t78_dag_primary_canary_check.sh http://127.0.0.1:9898/metrics --tps-window=300
```

| Window | Use Case | Expected TPS (dev-unsafe) |
|--------|----------|---------------------------|
| 5s | Short 1000-tx burst | ≥150 TPS |
| 30s | Medium test | ≥150 TPS |
| 60s | Standard canary (default) | ≥150 TPS |
| 300s | Long soak test | ≥150 TPS sustained |

---

## Optional: Local-Only Dev-Unsafe Benchmark Profile

For local TPS experiments with unsigned transactions, use the dev-unsafe profile.

> ⚠️ **WARNING**: Dev-unsafe builds should **NEVER** be deployed to any network.
> They are only for local development benchmarks.

**Build with dev-unsafe:**
```bash
cargo build -p eezo-node \
  --features "dev-unsafe,metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus"
```

**Run with unsigned tx enabled:**
```bash
# Set environment for dev-unsafe mode
export EEZO_DEV_ALLOW_UNSIGNED_TX=1
export EEZO_CONSENSUS_MODE=dag-primary
export EEZO_DAG_ORDERING_ENABLED=1
export EEZO_HYBRID_STRICT_PROFILE=1
export EEZO_EXECUTOR_MODE=stm
export EEZO_EXEC_LANES=32
export EEZO_DATADIR=/tmp/eezo-bench

# Clear previous data
rm -rf /tmp/eezo-bench

# Start the node
./target/debug/eezo-node --genesis genesis.min.json --datadir /tmp/eezo-bench
```

**Run unsigned tx spam test:**
```bash
# Terminal 2: Spam unsigned transactions
scripts/spam_tps.sh 1000 http://127.0.0.1:8080

# Terminal 3: Check metrics
scripts/t78_dag_primary_canary_check.sh http://127.0.0.1:9898/metrics --tps-window=5
```

**Expected in dev-unsafe mode:**
- `[DEV-UNSAFE]` warnings visible in node logs
- Unsigned transactions accepted
- TPS ≥ 150 with spam test

---

## T78.9: Nonce-Gap Pitfall

### Understanding Nonce Gaps

A **nonce gap** occurs when transactions are submitted with non-contiguous nonces. For example, if you submit transactions with nonces [0, 1, 7, 8], there is a gap at nonces 2-6.

**Why does this matter?**

The mempool uses strict nonce ordering to prevent double-spending and maintain transaction ordering guarantees. When a gap exists:

1. **Transactions before the gap are processed normally**: nonces 0 and 1 are included in blocks
2. **Transactions after the gap are queued but NOT processed**: nonces 7 and 8 wait in the mempool
3. **A WARN log is emitted**: `mempool: X sender(s) skipped due to nonce gaps`

### Common Causes of Nonce Gaps

1. **Faucet funding wrong address**: If you fund `0xABC` but submit transactions from `0xDEF`, the transactions from `0xDEF` will have insufficient funds for nonce 0, but higher nonces may be admitted. This creates a gap.

2. **Transaction nonce 0 rejected**: If the first transaction (nonce=0) is rejected due to `InsufficientFunds`, but subsequent transactions with higher nonces are admitted (via `admit_signed_tx` future nonce allowance), a gap is created.

3. **Parallel submission race**: If you submit transactions in parallel and some fail while others succeed, gaps may form.

### How to Avoid Nonce Gaps

> ⚠️ **Always fund the EXACT address that will submit transactions.**

```bash
# 1. Generate keypair and get address
./target/release/ml_dsa_keygen
# Output: EEZO_TX_FROM=0x<your_address>

# 2. Fund THIS EXACT address via faucet
curl -X POST "http://127.0.0.1:8080/faucet" \
  -H "Content-Type: application/json" \
  -d '{"to":"0x<your_address>","amount":"1000000000000"}'

# 3. Verify balance BEFORE submitting transactions
curl "http://127.0.0.1:8080/account/0x<your_address>"

# 4. Only then submit transactions
scripts/spam_tps.sh 1000 http://127.0.0.1:8080
```

### Diagnosing Nonce Gaps

**Symptoms:**
- `eezo_mempool_len` stays > 0 but `eezo_txs_included_total` is flat
- WARN log: `mempool: N sender(s) skipped due to nonce gaps`

**Check metrics:**
```bash
# Check for nonce gap drops
curl -s http://127.0.0.1:9898/metrics | grep nonce

# Expected metrics:
# eezo_dag_hybrid_nonce_gap_dropped_total - transactions dropped due to gaps
# eezo_dag_hybrid_bad_nonce_prefilter_total - transactions with nonce too low
```

---

## T78.9: dev-unsafe vs devnet-safe Differences

### Build Profile Comparison

| Aspect | **dag-only** | **devnet-safe** | **dev-unsafe** |
|--------|-------------|-----------------|----------------|
| **Use case** | Production deployments | Official devnet | Local TPS benchmarks only |
| **Unsigned tx** | ❌ Never allowed | ❌ Never allowed | ✅ With `EEZO_DEV_ALLOW_UNSIGNED_TX=1` |
| **Signature verification** | ✅ Always enforced | ✅ Always enforced | ⚠️ Can be bypassed |
| **Default consensus mode** | dag-primary (forced) | dag-primary | configurable |
| **Safe for network?** | ✅ Yes | ✅ Yes | ❌ **NEVER** deploy |

### Build Commands

**dag-only (recommended for production):**
```bash
cargo build --release -p eezo-node --features "dag-only"
```

**Devnet-safe (recommended for devnet):**
```bash
cargo build --release -p eezo-node \
  --features "devnet-safe,metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus"
```

**Dev-unsafe (local benchmarks ONLY):**
```bash
cargo build -p eezo-node \
  --features "dev-unsafe,metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus"
```

### Key Differences in Behavior

1. **Signature verification**
   - `dag-only/devnet-safe`: All transactions MUST have valid ML-DSA signatures
   - `dev-unsafe`: With `EEZO_DEV_ALLOW_UNSIGNED_TX=1`, signature verification is skipped

2. **Startup logging**
   - `dag-only`: `[T80.0 dag-only] build profile active: DAG is the only consensus mode`
   - `devnet-safe`: `[T78.8] Build profile: devnet-safe`
   - `dev-unsafe`: `[DEV-UNSAFE]` warnings visible

### Security Warning

> 🚨 **NEVER** deploy a dev-unsafe build to any network (devnet, testnet, or mainnet).
> Dev-unsafe builds bypass critical security checks and should only be used for local TPS experiments.

---

## T78.9: Understanding eezo_block_tx_count Metric

### Behavior Between Blocks

The `eezo_block_tx_count` metric is a **gauge** that reports the number of transactions in the **most recently committed block**. It is updated when a new block is committed.

**Important notes:**

1. **May show 0 between blocks**: If the last committed block was empty (no transactions), the gauge will show 0 until a non-empty block is committed.

2. **Empty blocks are normal in dag-primary mode**: In dag-primary mode without mempool fallback, empty blocks can occur when:
   - No transactions in the DAG queue
   - All DAG transactions were filtered by nonce contiguity

3. **Use `eezo_txs_included_total` for transaction counts**: This counter monotonically increases and provides a more reliable view of total throughput.

### Metrics Interpretation

```bash
# Check current block tx count (may be 0 between non-empty blocks)
curl -s http://127.0.0.1:9898/metrics | grep eezo_block_tx_count

# Better: Check total transactions included (always increasing)
curl -s http://127.0.0.1:9898/metrics | grep eezo_txs_included_total

# Check TPS over time window
BEFORE=$(curl -s http://127.0.0.1:9898/metrics | grep '^eezo_txs_included_total ' | awk '{print $2}')
sleep 10
AFTER=$(curl -s http://127.0.0.1:9898/metrics | grep '^eezo_txs_included_total ' | awk '{print $2}')
echo "TPS: $(echo "scale=2; ($AFTER - $BEFORE) / 10" | bc)"
```

---

## References

- [T81: EEZO Consensus History & DAG-Only Runtime](t81_consensus_history.md)
- [T80: Pure DAG Consensus Cutover](t80_dag_consensus_cutover.md)
- [T78: DAG-Only Devnet & Strict Hybrid Tuning](t78_dag_only_devnet.md)
- [Dev Unsafe Modes](dev_unsafe_modes.md)

---

## T79.0: dag-primary Health Probe & Ops Polish

### Overview

T79.0 introduces a structured HTTP health endpoint (`/health/dag_primary`) designed for Kubernetes readiness/liveness probes and operational monitoring. This endpoint provides a machine-readable health check that verifies the node is operating correctly in dag-primary mode.

### Purpose

The `/health/dag_primary` endpoint differs from the general `/health` endpoint:

| Endpoint | Purpose | Response |
|----------|---------|----------|
| `/health` | Basic liveness check | Always returns `"ok"` |
| `/health/dag_primary` | dag-primary mode readiness | JSON with status and metrics |

The dag-primary health endpoint checks:

1. **Consensus mode**: Must be `dag-primary` (mode value `3`)
2. **Shadow checker activity**: `eezo_dag_primary_shadow_checks_total` must have increased recently
3. **Transaction liveness**: `eezo_txs_included_total` must have increased recently

### HTTP Response Codes

| Status | Meaning |
|--------|---------|
| `200 OK` | All health checks pass - node is healthy |
| `503 Service Unavailable` | One or more checks failed - node is degraded |

### Response Format

**Healthy response (HTTP 200):**
```json
{
  "status": "healthy",
  "consensus_mode": 3,
  "shadow_checks_total": 1234,
  "txs_included_total": 5678,
  "window_secs": 60
}
```

**Degraded response (HTTP 503):**
```json
{
  "status": "degraded",
  "reason": "wrong_mode",
  "consensus_mode": 1,
  "shadow_checks_total": 0,
  "txs_included_total": 0,
  "window_secs": 60
}
```

### Degraded Reasons

| Reason | Meaning |
|--------|---------|
| `wrong_mode` | Consensus mode is not dag-primary (mode ≠ 3) |
| `no_shadow_checks_recently` | Shadow checker has not run within the window |
| `no_txs_recently` | No transactions included within the window |

### Configuration

The health check window (how recently metrics must have changed) is configurable:

```bash
# Default: 60 seconds
export EEZO_DAG_PRIMARY_HEALTH_WINDOW_SECS=60
```

### Usage Examples

**Basic health check:**
```bash
# Check if node is healthy (will return exit code 0 for 200, non-zero otherwise)
curl -sf http://127.0.0.1:8080/health/dag_primary > /dev/null && echo "healthy" || echo "degraded"

# Get full JSON response
curl -s http://127.0.0.1:8080/health/dag_primary | jq .
```

**Kubernetes readiness probe:**
```yaml
readinessProbe:
  httpGet:
    path: /health/dag_primary
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
```

**Kubernetes liveness probe:**
```yaml
livenessProbe:
  httpGet:
    path: /health/dag_primary
    port: 8080
  initialDelaySeconds: 60
  periodSeconds: 30
  timeoutSeconds: 10
  failureThreshold: 5
```

### Devnet Launcher Script

The `scripts/devnet_dag_primary.sh` launcher script now prints endpoint URLs including the health endpoint:

```bash
./scripts/devnet_dag_primary.sh
```

Output:
```
═══════════════════════════════════════════════════════════════
  T79.0: Official devnet-safe DAG-primary Launcher
═══════════════════════════════════════════════════════════════

Configuration:
  EEZO_CONSENSUS_MODE=dag-primary
  EEZO_DAG_ORDERING_ENABLED=1
  ...

Endpoints (once started):
  Mode:                 dag-primary
  HTTP Base URL:        http://127.0.0.1:8080
  Metrics URL:          http://127.0.0.1:9898/metrics
  Health (general):     http://127.0.0.1:8080/health
  Health (dag-primary): http://127.0.0.1:8080/health/dag_primary
```

### Ops Notes

#### Recommended Probe Settings

For production Kubernetes deployments:

| Setting | Recommended Value | Rationale |
|---------|-------------------|-----------|
| `initialDelaySeconds` | 30-60 | Allow node startup time |
| `periodSeconds` | 10-30 | Balance responsiveness vs overhead |
| `timeoutSeconds` | 5-10 | Network latency buffer |
| `failureThreshold` | 3-5 | Avoid false positives |

#### Activity Window Semantics

The health check uses a **"must have increased recently"** semantic:

- Metrics are considered active if they changed within the last `EEZO_DAG_PRIMARY_HEALTH_WINDOW_SECS` seconds
- Default window is 60 seconds, matching typical Prometheus scrape intervals
- For high-throughput scenarios, consider shorter windows (30s)
- For low-traffic environments, consider longer windows (120s)

#### Monitoring Integration

The health endpoint is designed to complement Prometheus metrics:

```bash
# Check health endpoint
curl -s http://127.0.0.1:8080/health/dag_primary | jq .status

# Check raw Prometheus metrics
curl -s http://127.0.0.1:9898/metrics | grep -E "(consensus_mode|shadow_checks|txs_included)"
```

Use both for comprehensive monitoring:
- Health endpoint for quick pass/fail status
- Prometheus metrics for detailed time-series analysis