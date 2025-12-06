# T78: DAG-Only Devnet & Strict Hybrid Tuning

## Overview

T78 is a multi-phase task focused on refining the DAG-hybrid consensus mode and eventually transitioning to a pure DAG-based consensus system. This document describes the implementation phases and configuration options.

## Background

Building on the stable DAG-hybrid implementation validated in T76.12 (~150 TPS in dev-unsafe mode), T78 focuses on:
1. Making DAG aggregation more tunable without disrupting stable defaults
2. Providing preset configurations for different deployment scenarios
3. Preparing for an eventual DAG-only mode

## Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| **T78.0** | Design documentation & stable baseline validation | ✅ Complete |
| **T78.1** | Strict Hybrid DAG Tuning (Phase 1) | ✅ Implemented |
| **T78.2** | Advanced tuning profiles | 🔜 Future |
| **T78.3** | DAG-only mode (no fallback) | 🔜 Future |

---

## T78.1: Strict Hybrid DAG Tuning (Phase 1)

### Goals

1. **Tunable aggregation without breaking existing defaults**: Add a configuration "profile" mechanism that exposes DAG aggregation tuning via environment variables without hard-coding new constants.

2. **Better logging for hybrid decisions**: Provide compact, single-line logs for each hybrid aggregation tick to understand behavior during canary runs.

3. **Documentation**: Clear runbook-style documentation of the new configuration options.

### Configuration

#### Environment Variables

T78.1 introduces a new optional environment variable to enable preset configurations:

##### `EEZO_HYBRID_STRICT_PROFILE`

**Values**: `0` (disabled, default) or `1` (enabled)

**Purpose**: When set to `1`, applies a "strict hybrid / devnet" preset configuration that uses recommended defaults for development and testing scenarios.

**Behavior**:
- When `EEZO_HYBRID_STRICT_PROFILE=1` AND no explicit override variables are set:
  - Uses `STRICT_PROFILE_TIME_BUDGET_MS=30` (30ms aggregation window)
  - Uses `STRICT_PROFILE_MAX_TX=500` (max 500 transactions per batch)
  - Uses `STRICT_PROFILE_MAX_BYTES=1048576` (1 MiB per batch)
  - Logs: `T78.1: hybrid strict profile enabled (time_budget_ms=30, max_tx=500, max_bytes=1048576)`

- When `EEZO_HYBRID_STRICT_PROFILE=1` BUT explicit overrides are set:
  - The explicit environment variables take precedence
  - The profile is NOT considered "active"
  - Standard logging is used

- When `EEZO_HYBRID_STRICT_PROFILE` is unset or `0`:
  - Behaves exactly as before (no change to existing defaults)
  - Standard adaptive aggregation behavior

**Interaction with Existing Variables**:

The strict profile provides preset defaults but always defers to explicit environment variable overrides:

```bash
# Explicit env vars (if set) override profile
EEZO_HYBRID_AGG_TIME_BUDGET_MS=<value>     # Overrides profile time budget
EEZO_HYBRID_AGG_MAX_TX=<value>             # Overrides profile max tx
EEZO_HYBRID_AGG_MAX_BYTES=<value>          # Overrides profile max bytes
```

**Priority Order**:
1. Explicit `EEZO_HYBRID_AGG_*` environment variables (highest priority)
2. Strict profile defaults (when `EEZO_HYBRID_STRICT_PROFILE=1` and no explicit overrides)
3. Standard defaults (when profile is disabled)

### Configuration Table

#### Baseline Dev Settings (Current Stable)

These are the default settings when no profile or overrides are set:

| Setting | Variable | Default Value |
|---------|----------|---------------|
| Time Budget | `EEZO_HYBRID_AGG_TIME_BUDGET_MS` | Unset (adaptive mode) |
| Max Transactions | `EEZO_HYBRID_AGG_MAX_TX` | 500 |
| Max Bytes | `EEZO_HYBRID_AGG_MAX_BYTES` | 1048576 (1 MiB) |
| Batch Timeout | `EEZO_HYBRID_BATCH_TIMEOUT_MS` | 50 (T78.2: increased from 30) |
| Min DAG Transactions | `EEZO_HYBRID_MIN_DAG_TX` | 1 |

#### Strict Hybrid Profile (T78.2 Updated)

These settings are applied when `EEZO_HYBRID_STRICT_PROFILE=1` (and no explicit overrides):

| Setting | Variable | Profile Value | Change |
|---------|----------|---------------|--------|
| Time Budget | `EEZO_HYBRID_AGG_TIME_BUDGET_MS` | 50 (fixed, not adaptive) | T78.2: +20ms |
| Max Transactions | `EEZO_HYBRID_AGG_MAX_TX` | 500 | Unchanged |
| Max Bytes | `EEZO_HYBRID_AGG_MAX_BYTES` | 1048576 (1 MiB) | Unchanged |
| Min DAG Transactions | `EEZO_HYBRID_MIN_DAG_TX` | 0 | T78.2: New override |
| Batch Timeout | `EEZO_HYBRID_BATCH_TIMEOUT_MS` | 50 | T78.2: New override |

**T78.2 Changes**: The strict profile has been tuned based on the DAG-hybrid fallback audit to favor DAG usage:
- **Time Budget**: Increased from 30ms to 50ms to give DAG ordering more time to produce usable batches
- **Min DAG TX**: Set to 0 (down from 1) to use any DAG batch, even with 1-2 transactions after filtering
- **Batch Timeout**: Increased from 30ms to 50ms to wait longer for DAG batches before falling back

These changes are designed to reduce fallback rate and increase `batches_used_total` while maintaining 100% apply success via the nonce contiguity filter.

### Enhanced Logging

T78.1 introduces compact, structured logging for each hybrid aggregation tick:

**Log Format**:
```
T78.1 hybrid-agg: time_budget_ms=<ms> batches=<count> candidates=<total> used=<count> cap_reason=<reason> strict_profile=<on|off>
```

**Fields**:
- `time_budget_ms`: Current aggregation time budget in milliseconds
- `batches`: Number of DAG batches aggregated for this block
- `candidates`: Total number of candidate transactions (after de-dup filtering)
- `used`: Number of transactions actually used in the block
- `cap_reason`: Why aggregation stopped (`time`, `bytes`, `tx`, or `empty`)
- `strict_profile`: Whether strict profile is active (`on` or `off`)

**Example**:
```
T78.1 hybrid-agg: time_budget_ms=30 batches=3 candidates=425 used=398 cap_reason=time strict_profile=on
```

This log line is emitted at `INFO` level once per successful hybrid aggregation, making it easy to understand aggregation behavior without log spam.

### Usage Examples

#### Example 1: Enable Strict Profile (Default Settings)

```bash
# Enable strict hybrid profile with defaults
export EEZO_HYBRID_STRICT_PROFILE=1

# Run the node
./target/release/eezo-node
```

**Expected behavior (T78.2 updated)**:
- Fixed 50ms aggregation time budget (adaptive mode disabled)
- Max 500 transactions per batch
- Max 1 MiB per batch
- Min DAG TX: 0 (use any DAG batch)
- Batch timeout: 50ms
- Logs will show: `T78.2: hybrid strict profile enabled (time_budget_ms=50, max_tx=500, max_bytes=1048576, min_dag_tx=0, batch_timeout_ms=50)`
- Aggregation logs will show: `strict_profile=on`

#### Example 2: Override Specific Settings

```bash
# Enable strict profile but override time budget
export EEZO_HYBRID_STRICT_PROFILE=1
export EEZO_HYBRID_AGG_TIME_BUDGET_MS=50
export EEZO_HYBRID_AGG_MAX_TX=1000

# Run the node
./target/release/eezo-node
```

**Expected behavior**:
- Time budget: 50ms (explicit override)
- Max transactions: 1000 (explicit override)
- Max bytes: 1048576 (standard default, profile not active due to overrides)
- Profile is NOT considered "active" because explicit envs are set
- Logs will show: `adaptive-agg: fixed time budget configured: 50 ms`
- Aggregation logs will show: `strict_profile=off`

#### Example 3: Disable Profile (Standard Behavior)

```bash
# Don't set EEZO_HYBRID_STRICT_PROFILE or set to 0
export EEZO_HYBRID_STRICT_PROFILE=0

# Run the node
./target/release/eezo-node
```

**Expected behavior**:
- Adaptive aggregation mode (no fixed time budget)
- Standard defaults for all settings
- Logs will show: `adaptive-agg: adaptive mode enabled`
- Aggregation logs will show: `strict_profile=off`

### Testing & Validation

#### Acceptance Criteria

- ✅ `cargo check --all-targets --all-features` passes
- ✅ `cargo test -p eezo-node --features "pq44-runtime,persistence,checkpoints,metrics,stm-exec,dag-consensus"` passes
- ✅ Behavior with all envs unset is identical to before T78.1
- ✅ `EEZO_HYBRID_STRICT_PROFILE=1` applies preset defaults when no explicit envs are set
- ✅ Explicit env vars override the strict profile
- ✅ Logs show clear single-line summary per aggregation tick with `cap_reason` and `strict_profile` status

#### Unit Tests

T78.1 includes comprehensive unit tests in `crates/node/src/adaptive_agg.rs`:

- `test_strict_profile_unset_uses_defaults`: Verifies unchanged behavior when profile is unset
- `test_strict_profile_enabled_without_overrides`: Verifies profile defaults are applied
- `test_strict_profile_with_explicit_overrides`: Verifies explicit envs win over profile
- `test_strict_profile_with_partial_overrides`: Verifies partial overrides deactivate profile
- `test_strict_profile_zero_is_disabled`: Verifies `EEZO_HYBRID_STRICT_PROFILE=0` disables profile

### Implementation Notes

- T78.1: Established the strict profile mechanism with baseline defaults
- T78.2: Tuned strict profile based on single-sender spam audit (see T78.2 section below)
- The profile mechanism is purely additive - it does not change any existing behavior when disabled.

---

## T78.2: DAG-Hybrid Fallback Shaping & Audit

### Goals

1. **Audit Current Behavior**: Understand why single-sender spam shows high fallback rate (470/500 ticks) despite 100% transaction inclusion
2. **Confirm Safety**: Verify no BadNonce stall paths exist
3. **Propose Tuning**: Recommend safe adjustments to increase DAG usage without sacrificing correctness

### Key Findings

**Executive Summary**: The high fallback rate under single-sender spam is **expected and correct behavior**, not a bug. The DAG ordering layer doesn't respect sender nonce constraints, leading to nonce gaps that the safety filter (nonce contiguity filter) correctly drops. These dropped transactions remain in the mempool and are included via fallback.

#### Metrics Analysis (1000 tx single-sender spam)

| Metric | Value | Interpretation |
|--------|-------|----------------|
| `eezo_txs_included_total` | 1000 | ✅ All transactions eventually included (100% liveness) |
| `eezo_dag_hybrid_batches_used_total` | 6 | DAG used in 1.2% of consensus ticks |
| `eezo_dag_hybrid_fallback_total` | 470 | Fallback used in 94% of ticks |
| `eezo_dag_hybrid_nonce_gap_dropped_total` | 361 | T78.SAFE filter prevented 361 BadNonce failures |
| TPS | 150-160 | Consistent with single-sender bottleneck |

**Why High Fallback Rate?**:
1. **Single-sender nonce bottleneck**: DAG reorders transactions (0,2,1,4,3,...), creating gaps
2. **Nonce contiguity filter**: T78.SAFE filter drops out-of-order txs to prevent BadNonce
3. **Small usable batches**: After filtering, batches fall below `min_dag_tx` threshold → fallback
4. **Strict timeouts**: 30ms batch timeout insufficient for DAG to produce usable (gap-free) batches

**Confirmed Safety**: No BadNonce stall paths exist. The nonce contiguity filter in `dag_consensus_runner.rs` guarantees that only sequential nonce sequences reach the executor. Fallback path uses sequential mempool drain (naturally contiguous).

### Implemented Changes (T78.2)

Based on the audit, we made minimal, safe tuning adjustments:

#### 1. Increased Default Batch Timeout

```rust
// Before (T77.1)
pub const DEFAULT_BATCH_TIMEOUT_MS: u64 = 30;

// After (T78.2)
pub const DEFAULT_BATCH_TIMEOUT_MS: u64 = 50;
```

**Rationale**: Give DAG ordering more time to produce usable batches before falling back. 30ms was chosen conservatively in T77.1; 50ms aligns with single-sender workload needs.

**Expected Impact**: 
- `batches_used_total` should increase by 2-3x
- `fallback_total` should decrease proportionally
- Slight increase in proposal latency (+20ms) is acceptable for devnet

#### 2. Updated Strict Profile for DAG-Favoring Behavior

```rust
// T78.2 additions to strict profile
pub const STRICT_PROFILE_TIME_BUDGET_MS: u64 = 50;  // +20ms from T78.1
pub const STRICT_PROFILE_MIN_DAG_TX: usize = 0;     // New: use any batch
pub const STRICT_PROFILE_BATCH_TIMEOUT_MS: u64 = 50; // New: override default
```

**Rationale**: Strict profile should favor DAG usage in devnet/testing scenarios. Setting `min_dag_tx=0` means "use DAG batch even if only 1-2 txs after filtering".

**Expected Impact**:
- Single-sender spam: `batches_used` increases to ~20-30 (from 6)
- Multi-sender workloads: Even better DAG utilization (natural nonce independence)
- No correctness impact (nonce contiguity filter remains active)

### Testing & Validation

**Acceptance Criteria** (T78.2):
- ✅ `cargo test -p eezo-node` passes with updated defaults
- ✅ Behavior with no envs set shows increased DAG usage (fallback rate should drop)
- ✅ `EEZO_HYBRID_STRICT_PROFILE=1` applies new tuned defaults
- ✅ Explicit env vars still override profile
- ✅ 100% transaction inclusion maintained (no BadNonce failures)

**Test Matrix**:
| Workload | Config | Expected batches_used | Expected fallback |
|----------|--------|-----------------------|-------------------|
| Single-sender 1000 tx | Default (T78.2) | ~15-20 | ~400-450 |
| Single-sender 1000 tx | Strict Profile | ~20-30 | ~350-400 |
| Multi-sender 1000 tx | Default | ~50+ | ~200 |

### Documentation

**See**:
- `book/src/t78_2_dag_hybrid_audit_report.md`: Full audit report with detailed analysis
- `book/src/t76_dag_hybrid_canary.md`: Updated with T78.2 tuning recommendations

### Future Work (T78.3+)

Potential enhancements for future phases:

1. **Additional Profiles**: 
   - `EEZO_HYBRID_AGGRESSIVE_PROFILE`: Higher time budget, larger batches
   - `EEZO_HYBRID_CONSERVATIVE_PROFILE`: Lower time budget, smaller batches

2. **Profile-Specific Tuning**:
   - Adjust strict profile defaults based on canary performance data
   - Add profile-specific min_dag_tx and batch_timeout settings

3. **DAG-Only Mode**:
   - Remove fallback to mempool entirely
   - Pure DAG-based transaction ordering
   - Remove legacy Hotstuff code paths

---

## References

- [T76: DAG-Hybrid Canary & SLO Runbook](t76_dag_hybrid_canary.md)
- [Dev Unsafe Modes](dev_unsafe_modes.md)