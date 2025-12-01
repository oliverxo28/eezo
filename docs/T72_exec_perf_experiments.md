# T72 — Executor Performance Experiments

## Rationale

From T72.0 metrics over a 5000-tx spam run:

- **Executor time**: ~10.85s total → ~2.2 ms per tx
- **Observed TPS**: ~100

The executor itself is fast (~2.2 ms/tx), but throughput is limited because we produce many near-empty blocks. Under heavy spam, the histogram shows:

- 362 blocks with ≤1 tx (mostly empty)
- A small number of heavy blocks carry most transactions

**Hypothesis**: We are block-timing bound, not executor-bound. By adjusting `EEZO_BLOCK_TARGET_TIME_MS` and `EEZO_BLOCK_MAX_TX`, we can pack more transactions per block and increase TPS.

## Test Scenarios

| Scenario       | EEZO_BLOCK_TARGET_TIME_MS | EEZO_BLOCK_MAX_TX |
|----------------|---------------------------|-------------------|
| baseline       | 1000                      | 500               |
| faster_500ms   | 500                       | 500               |
| faster_250ms   | 250                       | 500               |

## Prerequisites

- GPU is disabled for these experiments: `EEZO_NODE_GPU_HASH=off`
- All scenarios use: `EEZO_CONSENSUS_MODE=hotstuff`, `EEZO_BLOCK_TX_SOURCE=dag`, `EEZO_DAG_TEMPLATE_POLICY=clean_only`, `EEZO_PERF_MODE=dag_source`

## Runbook

### Scenario 1: baseline (1000 ms block time)

#### Terminal 1 — Start node

```bash
cd ~/Block/eezo

export EEZO_CONSENSUS_MODE=hotstuff
export EEZO_BLOCK_TX_SOURCE=dag
export EEZO_DAG_TEMPLATE_POLICY=clean_only
export EEZO_PERF_MODE=dag_source
export EEZO_NODE_GPU_HASH=off
export EEZO_BLOCK_MAX_TX=500
export EEZO_BLOCK_TARGET_TIME_MS=1000

RUST_LOG=info \
cargo run -p eezo-node --bin eezo-node --features "pq44-runtime,persistence,checkpoints,metrics" -- \
  --genesis genesis.min.json \
  --datadir /tmp/eezo-t72-baseline
```

#### Terminal 2 — Run experiment

```bash
cd ~/Block/eezo

# Generate dev key and sender address
eval "$(cargo run -p eezo-crypto --features pq44-runtime --bin ml_dsa_keygen)"
export EEZO_TX_FROM="0x$(echo -n "${EEZO_TX_PK_HEX#0x}" | head -c 40)"

export EEZO_TX_TO="0xcafebabecafebabecafebabecafebabecafebabe"
export EEZO_TX_CHAIN_ID="0x0000000000000000000000000000000000000001"
export EEZO_TX_AMOUNT="1000"
export EEZO_TX_FEE="1"

# Fund account
curl -s -X POST http://127.0.0.1:8080/faucet \
  -H "Content-Type: application/json" \
  -d "{\"to\":\"$EEZO_TX_FROM\",\"amount\":\"100000000\"}" > /dev/null

# Send 5000 tx
scripts/spam_tps.sh 5000 http://127.0.0.1:8080

# Measure TPS over 60s window
scripts/measure_tps.sh 60 http://127.0.0.1:9898/metrics

# Capture executor metrics for this scenario
scripts/t72_capture_metrics.sh baseline
```

---

### Scenario 2: faster_500ms (500 ms block time)

#### Terminal 1 — Start node

```bash
cd ~/Block/eezo

export EEZO_CONSENSUS_MODE=hotstuff
export EEZO_BLOCK_TX_SOURCE=dag
export EEZO_DAG_TEMPLATE_POLICY=clean_only
export EEZO_PERF_MODE=dag_source
export EEZO_NODE_GPU_HASH=off
export EEZO_BLOCK_MAX_TX=500
export EEZO_BLOCK_TARGET_TIME_MS=500

RUST_LOG=info \
cargo run -p eezo-node --bin eezo-node --features "pq44-runtime,persistence,checkpoints,metrics" -- \
  --genesis genesis.min.json \
  --datadir /tmp/eezo-t72-fast500
```

#### Terminal 2 — Run experiment

```bash
cd ~/Block/eezo

# Generate dev key and sender address
eval "$(cargo run -p eezo-crypto --features pq44-runtime --bin ml_dsa_keygen)"
export EEZO_TX_FROM="0x$(echo -n "${EEZO_TX_PK_HEX#0x}" | head -c 40)"

export EEZO_TX_TO="0xcafebabecafebabecafebabecafebabecafebabe"
export EEZO_TX_CHAIN_ID="0x0000000000000000000000000000000000000001"
export EEZO_TX_AMOUNT="1000"
export EEZO_TX_FEE="1"

# Fund account
curl -s -X POST http://127.0.0.1:8080/faucet \
  -H "Content-Type: application/json" \
  -d "{\"to\":\"$EEZO_TX_FROM\",\"amount\":\"100000000\"}" > /dev/null

# Send 5000 tx
scripts/spam_tps.sh 5000 http://127.0.0.1:8080

# Measure TPS over 60s window
scripts/measure_tps.sh 60 http://127.0.0.1:9898/metrics

# Capture executor metrics for this scenario
scripts/t72_capture_metrics.sh fast500
```

---

### Scenario 3: faster_250ms (250 ms block time)

#### Terminal 1 — Start node

```bash
cd ~/Block/eezo

export EEZO_CONSENSUS_MODE=hotstuff
export EEZO_BLOCK_TX_SOURCE=dag
export EEZO_DAG_TEMPLATE_POLICY=clean_only
export EEZO_PERF_MODE=dag_source
export EEZO_NODE_GPU_HASH=off
export EEZO_BLOCK_MAX_TX=500
export EEZO_BLOCK_TARGET_TIME_MS=250

RUST_LOG=info \
cargo run -p eezo-node --bin eezo-node --features "pq44-runtime,persistence,checkpoints,metrics" -- \
  --genesis genesis.min.json \
  --datadir /tmp/eezo-t72-fast250
```

#### Terminal 2 — Run experiment

```bash
cd ~/Block/eezo

# Generate dev key and sender address
eval "$(cargo run -p eezo-crypto --features pq44-runtime --bin ml_dsa_keygen)"
export EEZO_TX_FROM="0x$(echo -n "${EEZO_TX_PK_HEX#0x}" | head -c 40)"

export EEZO_TX_TO="0xcafebabecafebabecafebabecafebabecafebabe"
export EEZO_TX_CHAIN_ID="0x0000000000000000000000000000000000000001"
export EEZO_TX_AMOUNT="1000"
export EEZO_TX_FEE="1"

# Fund account
curl -s -X POST http://127.0.0.1:8080/faucet \
  -H "Content-Type: application/json" \
  -d "{\"to\":\"$EEZO_TX_FROM\",\"amount\":\"100000000\"}" > /dev/null

# Send 5000 tx
scripts/spam_tps.sh 5000 http://127.0.0.1:8080

# Measure TPS over 60s window
scripts/measure_tps.sh 60 http://127.0.0.1:9898/metrics

# Capture executor metrics for this scenario
scripts/t72_capture_metrics.sh fast250
```

---

## Output Files

Each scenario writes metrics to:

- `/tmp/eezo-t72-baseline-metrics.txt`
- `/tmp/eezo-t72-fast500-metrics.txt`
- `/tmp/eezo-t72-fast250-metrics.txt`

These files contain all `eezo_exec_*` metrics, `eezo_block_exec_seconds`, and `eezo_txs_included_total`.

## Interpreting Results

### Key Metrics

| Metric | Description |
|--------|-------------|
| `eezo_txs_included_total` | Total transactions included in blocks |
| `eezo_exec_block_apply_seconds_sum` | Total time spent applying blocks |
| `eezo_exec_block_commit_seconds_sum` | Total time spent committing blocks |
| `eezo_exec_block_prepare_seconds_sum` | Total time spent preparing blocks |
| `eezo_exec_txs_per_block_*` | Histogram of transactions per block |

### What to Look For

- **Block-timing bound**: If reducing `EEZO_BLOCK_TARGET_TIME_MS` from 1000ms to 500ms results in significantly higher TPS (e.g., >30% increase) while `eezo_exec_block_apply_seconds` per block remains similar, then we are block-timing bound rather than executor-bound.

- **Under-packing blocks**: If the `eezo_exec_txs_per_block` histogram shows many blocks with ≤1 tx even under heavy spam (e.g., >50% of blocks are near-empty), we are under-packing blocks. The block proposal frequency is too low relative to transaction arrival rate.

- **Executor scaling**: If `eezo_exec_block_apply_seconds_sum / eezo_exec_block_apply_seconds_count` (average apply time per block) grows proportionally with average transactions per block, the executor is scaling well. Compare this ratio across scenarios to verify.

### Comparing Runs

To compare two scenarios, diff the captured metrics files:

```bash
diff /tmp/eezo-t72-baseline-metrics.txt /tmp/eezo-t72-fast500-metrics.txt
```

Or extract specific values:

```bash
grep 'eezo_txs_included_total' /tmp/eezo-t72-*.txt
grep 'eezo_exec_block_apply_seconds_sum' /tmp/eezo-t72-*.txt
```
