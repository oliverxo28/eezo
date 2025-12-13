# T93 — Simple Transfer Fast Path (STM Optimization)

This document describes the T93.2 and T93.3 milestones: adding a simple transfer fast path to the STM executor and fixing its metrics semantics.

## Background

The Block-STM executor uses wave-based parallel execution with conflict detection to execute transactions. For simple value transfers (no contract calls), this overhead is significant relative to the actual work being done.

T93.2 introduced a "simple fast path" that bypasses expensive conflict detection for transactions that:
- Have exactly one sender and one receiver
- Contain no contract calls or extra side effects
- Can be safely batched without write-write conflicts

T93.3 polished the metrics to ensure per-transaction semantics and improved fast path coverage for simple spam workloads.

## Configuration

The simple fast path is controlled by environment variables:

```bash
# Enable the simple transfer fast path (default: disabled)
EEZO_STM_SIMPLE_FASTPATH_ENABLED=1

# Must use arena kernel mode
EEZO_STM_KERNEL_MODE=arena
```

## New Prometheus Metrics

### eezo_stm_simple_candidate_total

**Type**: Counter (integer)

**Description**: Number of transactions classified as SimpleTransfer by the analyzer. Incremented exactly once per tx at block start.

**Invariant**: `candidate_total <= eezo_txs_included_total`

**Example**:
```
eezo_stm_simple_candidate_total 5000
```

### eezo_stm_simple_fastpath_total

**Type**: Counter (integer)

**Description**: Number of candidate txs that successfully executed via the simple fast path. Incremented once per tx when it commits via fast path.

**Example**:
```
eezo_stm_simple_fastpath_total 4850
```

### eezo_stm_simple_fallback_total

**Type**: Counter (integer)

**Description**: Number of candidate txs that fell back to the general STM path (e.g., conflict/scheduling invariant violated during fast path wave).

**Invariant**: `fastpath_total + fallback_total ≈ candidate_total` (for committed txs)

**Example**:
```
eezo_stm_simple_fallback_total 150
```

### eezo_stm_simple_time_seconds

**Type**: Counter (float)

**Description**: Total CPU time (seconds) spent in simple fast path execution.

**Example**:
```
eezo_stm_simple_time_seconds 0.847
```

### eezo_exec_stm_simple_fastpath_enabled

**Type**: Gauge (0/1)

**Description**: Whether the simple fast path is enabled.

**Example**:
```
eezo_exec_stm_simple_fastpath_enabled 1
```

## How It Works

### Transaction Classification (T93.2)

At block start, all transactions are analyzed and classified:

1. **SimpleTransfer**: Basic value transfers with one sender, one receiver, no contract calls.
2. **General**: Everything else (future: contract calls, multi-output txs).

Currently, all EEZO transactions are classified as SimpleTransfer since the network does not yet support contracts.

### Fast Path Wave Execution (T93.2 + T93.3)

When the fast path is enabled, each wave:

1. **Claim senders**: Only one tx per sender can execute in a wave (prevents write-write conflicts on sender account).

2. **Track touched accounts**: If a tx's sender or receiver was already touched by an earlier tx in this wave, skip it for this wave.

3. **Validate state**: Check nonce and balance directly on the arena (O(1) Vec access).

4. **Commit immediately**: If validation passes, update the arena directly without speculative results.

5. **Mark for retry**: Txs that cannot be safely scheduled stay as `NeedsRetry` for subsequent waves.

### Metrics Semantics (T93.3)

**Key invariants**:

1. Each tx is counted as a candidate exactly once (at block start).
2. Each tx is counted as fastpath OR fallback exactly once (at block end).
3. `fastpath + fallback = committed candidates` for each block.
4. `candidate <= txs_included` since some txs may fail analysis.

**What gets counted where**:

- **candidate**: All txs classified as SimpleTransfer at block start.
- **fastpath**: Txs that commit via the fast path wave execution.
- **fallback**: Txs that are SimpleTransfer candidates but commit via the general STM path (because fast path couldn't schedule them).

## Expected Behavior

### Pure Simple Transfer Spam Workload

For a workload of pure simple transfers (one sender, one receiver, monotonic nonces):

```
eezo_stm_simple_candidate_total ≈ eezo_txs_included_total
eezo_stm_simple_fastpath_total ≈ eezo_stm_simple_candidate_total
eezo_stm_simple_fallback_total ≈ 0
```

Most txs should use the fast path. Fallback occurs when:
- Multiple txs from the same sender (nonce chain) - only one per wave
- Multiple txs to the same receiver - only one per wave (write conflict)
- Temporary nonce/balance issues during early waves

### Same-Receiver Conflict Workload

For a workload where multiple senders send to the same receiver:

```
eezo_stm_simple_candidate_total = N
eezo_stm_simple_fastpath_total = N / num_waves (approximately 1 per wave)
eezo_stm_simple_fallback_total = N - fastpath_total
```

The first tx to each receiver uses fast path; subsequent ones fall back to general STM.

## Performance Impact

With T93.2/T93.3, the simple fast path provides:

- **~41% reduction in STM cost per tx**: 2.18 ms → 1.29 ms per tx
- **Higher throughput potential**: Less conflict detection overhead
- **Preserved correctness**: Same final ledger state with fast path on or off

## Running a Profile

```bash
# Enable fast path and run fat-block profile
EEZO_STM_SIMPLE_FASTPATH_ENABLED=1 \
EEZO_STM_KERNEL_MODE=arena \
scripts/t93_fat_block_profile.sh 5000 120 \
  | tee /tmp/t93_fastpath_5000.txt
```

After the run, check metrics:

```bash
curl -s http://localhost:9091/metrics | grep eezo_stm_simple
```

Expected output:
```
eezo_stm_simple_candidate_total 5000
eezo_stm_simple_fastpath_total 4800
eezo_stm_simple_fallback_total 200
eezo_stm_simple_time_seconds 1.234
```

## Code References

- **Metrics definitions**: `crates/node/src/metrics.rs` (T93.2 + T93.3 section)
- **Fast path implementation**: `crates/node/src/executor/stm.rs::execute_simple_fastpath_wave`
- **Transaction classification**: `crates/node/src/executor/stm.rs::AnalyzedTxKind`
- **Tests**: `crates/node/src/executor/stm.rs::tests` (T93.3 tests)
