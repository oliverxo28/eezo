# T78.0: DAG-Only Devnet Cutover Plan

## Overview

This document outlines the strategic plan for transitioning EEZO's consensus mechanism from **DAG-Hybrid** (HotStuff + DAG ordering) to **DAG-Only** mode in devnet. This is a design-only task (T78.0) that establishes the blueprint for subsequent implementation tasks (T78.1, T78.2, etc.).

### Document Status

- **Task ID**: T78.0
- **Type**: Design Document (No Code Changes)
- **Date**: 2025-12-06
- **Status**: Draft

---

## Current State Recap

### Architecture Summary

As of T77 completion, EEZO runs in **DAG-Hybrid** consensus mode with the following characteristics:

**Consensus Configuration:**
- **Mode**: `EEZO_CONSENSUS_MODE=dag-hybrid`
- **DAG Ordering**: Enabled (`EEZO_DAG_ORDERING_ENABLED=1`)
- **HotStuff Role**: Provides finality and acts as fallback if DAG ordering fails
- **Transaction Ordering**: Primarily via DAG consensus layer
- **Block Finalization**: HotStuff BFT consensus

**Executor Configuration:**
- **Executor Type**: STM (Software Transactional Memory)
- **Execution Lanes**: 32 parallel lanes (`EEZO_EXEC_LANES=32`)
- **Wave Cap**: 256 transactions per wave (`EEZO_EXEC_WAVE_CAP=256`)
- **Fast Decode Pool**: Enabled (`EEZO_FAST_DECODE_ENABLED=1`)

**Mempool & TTL:**
- **Mempool TTL**: 0 seconds (`EEZO_MEMPOOL_TTL_SECS=0`) - disabled for maximum throughput
- **Mempool Max Length**: 100,000 transactions
- **Rate Cap**: 100,000 tx/s

**Performance Baseline:**
- **Current TPS**: ~150 TPS under `scripts/spam_tps.sh 1000` on development hardware
- **Target TPS**: ≥250-400 TPS (established in T76.12 canary)
- **Apply Success Rate**: ≥99.9% (SLO from T76.12)

### Completed T77 SAFE Work

The following security and stability improvements were completed in T77:

1. **SAFE-1**: Nonce-gap fix
   - Prevents transactions with non-sequential nonces from being accepted
   - Ensures mempool integrity and prevents replay attacks

2. **SAFE-2**: Dev-unsafe mode hardening ([dev_unsafe_modes.md](./dev_unsafe_modes.md))
   - `dev-unsafe` feature gate protects signature verification bypass
   - `EEZO_DEV_ALLOW_UNSIGNED_TX` only works with `dev-unsafe` feature
   - Compile-time and runtime safety checks
   - Prominent startup warnings for dev-unsafe builds
   - Production builds never include dev-unsafe features

3. **SAFE-3**: TTL (Time-To-Live) caps for mempool entries
   - Configurable TTL via `EEZO_MEMPOOL_TTL_SECS`
   - Prevents stale transactions from lingering in mempool
   - Metrics: `eezo_mempool_ttl_expired_total`
   - Currently set to 0 (disabled) for maximum throughput in canary testing

4. **Nonce-gap Fix**: Transaction ordering integrity
   - Ensures sequential nonce processing
   - Prevents out-of-order transaction execution
   - Metrics: `eezo_dag_hybrid_bad_nonce_prefilter_total`

5. **T76.12 Canary Validation**: 7-day canary completed successfully
   - Zero hybrid fallbacks under normal load
   - No hash mismatches between DAG and canonical ordering
   - ≥99.9% apply success rate achieved
   - Sustained TPS validated
   - No lost/duplicated batches across restarts

### Key Metrics Validated

The following metrics from T76.12 demonstrate system stability:

| Metric | Target | Status |
|--------|--------|--------|
| `eezo_dag_hybrid_fallback_total` | 0 (no increases) | ✅ Achieved |
| `eezo_dag_shadow_hash_mismatch_total` | 0 | ✅ Achieved |
| `eezo_dag_shadow_in_sync` | 1 | ✅ Achieved |
| `eezo_dag_ordered_ready` | <10 | ✅ Achieved |
| Apply Success Rate | ≥99.9% | ✅ Achieved |
| TPS (dev hardware) | ~150 TPS | ✅ Baseline established |

---

## Target Architecture: DAG-Only Devnet

### Vision

The target architecture eliminates HotStuff as the canonical consensus mechanism and promotes DAG to be the **sole ordering and finality engine** for devnet. This represents a fundamental shift in the consensus model:

**Current (DAG-Hybrid):**
```
Transactions → DAG Ordering → HotStuff Finality → Block Builder → Execution
                    ↓ (fallback)
                 Mempool (HotStuff direct)
```

**Target (DAG-Only):**
```
Transactions → DAG Ordering → DAG Finality → Block Builder → Execution
                    ↓ (no fallback - DAG must succeed)
                 [HotStuff removed or feature-gated]
```

### Key Differences

| Aspect | DAG-Hybrid | DAG-Only |
|--------|------------|----------|
| **Consensus Authority** | HotStuff decides commits | DAG decides commits |
| **Ordering Mechanism** | DAG with HotStuff fallback | DAG only |
| **Finality** | HotStuff BFT | DAG-based finality |
| **Fallback Path** | Mempool → HotStuff | None (DAG must work) |
| **Mode Value** | `dag-hybrid` (1) | `dag-only` (2) |
| **HotStuff Role** | Active (fallback + finality) | Disabled or shadow-only |

### Architectural Benefits

1. **Simplicity**: Single consensus path reduces code complexity
2. **Performance**: No overhead from dual consensus coordination
3. **Clarity**: Clear ownership of ordering and finality
4. **Scalability**: DAG's inherent parallelism fully utilized
5. **Innovation**: Enables DAG-specific optimizations without HotStuff constraints

### Risks & Mitigation

| Risk | Mitigation Strategy |
|------|---------------------|
| **DAG ordering failure** | Phase 2 includes shadow HotStuff for validation |
| **Performance regression** | Extensive canary testing at each phase |
| **Hash mismatches** | Comprehensive metrics and alerting |
| **Rollback complexity** | Feature flags allow rapid reversion |
| **Production readiness** | Devnet-only initially; testnet requires extended validation |

---

## Phased Migration Plan

### Phase 1: Strict Hybrid (HotStuff in Charge, DAG Heavily Used)

**Objective**: Maximize DAG usage while keeping HotStuff as the authoritative consensus layer.

**Description**: 
This phase maintains the current DAG-Hybrid mode but tunes configuration to push more transactions through the DAG path. HotStuff remains the canonical decision-maker and fallback is still available, but we aim for zero fallbacks under all load conditions.

**Subtasks:**

- **T78.1**: Tune DAG ordering aggressiveness
  - Increase `EEZO_HYBRID_AGG_TIME_BUDGET_MS` from 100ms to 150-200ms
  - Adjust adaptive aggregation thresholds for faster batch formation
  - Monitor `eezo_hybrid_agg_cap_reason_total` to understand batch completion triggers
  
- **T78.2**: Enhance DAG ordering latency monitoring
  - Add histogram buckets to `eezo_dag_ordering_latency_seconds` (p50, p95, p99)
  - Create alerting rules for latency degradation
  - Correlate latency with batch size and wave contention
  
- **T78.3**: Stress test fallback elimination
  - Run sustained load tests (1000+ TPS bursts)
  - Verify `eezo_dag_hybrid_fallback_total` remains at 0
  - Test recovery from simulated DAG stalls
  - Document any conditions that trigger fallbacks

- **T78.4**: Shadow metrics expansion
  - Add `eezo_dag_shadow_ordering_divergence_total` counter
  - Track DAG batch acceptance rate vs. HotStuff
  - Monitor `eezo_dag_shadow_lag_blocks` under stress

**Code Areas:**

| File/Module | Changes |
|-------------|---------|
| `crates/node/src/dag_consensus_runner.rs` | Add histogram metrics for ordering latency |
| `crates/node/src/adaptive_agg.rs` | Tune adaptive aggregation parameters |
| `crates/node/src/metrics.rs` | Add shadow divergence metrics |
| `crates/ledger/src/consensus.rs` | Document optimal configuration ranges |
| `devnet.env` | Update environment variable recommendations |
| `scripts/t76_dag_canary_check.sh` | Add Phase 1 validation checks |

**Acceptance Metrics:**

| Metric | Target | Measurement Window |
|--------|--------|-------------------|
| `eezo_dag_hybrid_fallback_total` | 0 | 7-day canary |
| `eezo_dag_ordering_latency_seconds` (p99) | <50ms | 24-hour stress test |
| `eezo_dag_shadow_in_sync` | 1 | Continuous |
| TPS under load | ≥200 TPS | Peak load test |
| Apply success rate | ≥99.9% | 7-day canary |

**Exit Criteria:**
- Zero fallbacks for 7 consecutive days
- No hash mismatches under sustained load
- All ledger and node integration tests pass
- Performance meets or exceeds baseline (≥150 TPS)

---

### Phase 2: DAG-Primary with HotStuff Shadow-Only Mode

**Objective**: Flip the authority to DAG while keeping HotStuff running in shadow mode for safety validation.

**Description**:
In this phase, DAG becomes the canonical ordering engine that decides which transactions commit to blocks. HotStuff continues to run but **only for metrics and validation**—it no longer controls finality or fallback. This is a critical validation phase before fully removing HotStuff.

**Subtasks:**

- **T78.5**: Introduce `dag-primary` consensus mode
  - Add new consensus mode value: `EEZO_CONSENSUS_MODE=dag-primary`
  - Update `ConsensusMode` enum in `crates/ledger/src/consensus.rs`
  - Add mode value 3 for `dag-primary` in metrics (`eezo_consensus_mode_active`)
  
- **T78.6**: Implement HotStuff shadow runner
  - Modify `crates/node/src/consensus_runner.rs` to operate in shadow-only mode
  - Shadow HotStuff validates DAG decisions but cannot override
  - Add `eezo_hotstuff_shadow_active` gauge (1 when in shadow mode)
  
- **T78.7**: Add shadow validation metrics
  - `eezo_hotstuff_shadow_divergence_total`: Counter for when HotStuff disagrees with DAG
  - `eezo_hotstuff_shadow_lag_blocks`: Gauge for HotStuff lag behind DAG
  - `eezo_hotstuff_shadow_validation_ok_total`: Counter for agreement with DAG
  - `eezo_hotstuff_shadow_validation_fail_total`: Counter for disagreement
  
- **T78.8**: Disable fallback path
  - Remove or feature-gate mempool fallback in `dag-primary` mode
  - DAG ordering failures must be explicit and logged
  - Add `eezo_dag_ordering_failed_total` metric for critical failures
  
- **T78.9**: Add emergency rollback mechanism
  - Feature flag: `EEZO_ENABLE_HOTSTUFF_FALLBACK_OVERRIDE=1` (emergency only)
  - Document rollback procedure in runbook
  - Test rollback under simulated DAG failure

**Code Areas:**

| File/Module | Changes |
|-------------|---------|
| `crates/ledger/src/consensus.rs` | Add `dag-primary` mode enum value |
| `crates/node/src/consensus_runner.rs` | Implement shadow-only operation mode |
| `crates/node/src/dag_consensus_runner.rs` | Remove fallback logic, add failure metrics |
| `crates/node/src/main.rs` | Parse and initialize `dag-primary` mode |
| `crates/node/src/metrics.rs` | Add shadow validation metrics |
| `book/src/t78_dag_only_devnet.md` | Document Phase 2 rollback procedures |
| `devnet.env` | Add `EEZO_CONSENSUS_MODE=dag-primary` |
| `scripts/spam_tps.sh` | Add stress tests for dag-primary mode |

**Acceptance Metrics:**

| Metric | Target | Measurement Window |
|--------|--------|-------------------|
| `eezo_hotstuff_shadow_divergence_total` | 0 | 14-day canary |
| `eezo_hotstuff_shadow_validation_ok_total` | 100% of blocks | 14-day canary |
| `eezo_dag_ordering_failed_total` | 0 | 14-day canary |
| `eezo_dag_shadow_hash_mismatch_total` | 0 | 14-day canary |
| TPS under load | ≥250 TPS | Peak load test |
| Apply success rate | ≥99.9% | 14-day canary |

**Exit Criteria:**
- Zero divergence between DAG and shadow HotStuff for 14 consecutive days
- No DAG ordering failures under stress tests
- TPS improvement (≥250 TPS sustained)
- All SAFE tests (T77) pass
- Emergency rollback procedure validated

---

### Phase 3: DAG-Only Devnet (HotStuff Disabled or Feature-Gated)

**Objective**: Complete the transition to pure DAG consensus by disabling or removing HotStuff entirely for devnet.

**Description**:
This is the final phase where HotStuff is either disabled via feature flag or completely removed from the devnet build. DAG is the sole consensus mechanism with no fallback or shadow validation. This represents the target architecture for DAG-Only mode.

**Subtasks:**

- **T78.10**: Introduce `dag-only` consensus mode
  - Add new consensus mode value: `EEZO_CONSENSUS_MODE=dag-only`
  - Update `ConsensusMode` enum with value 2 (replacing old hybrid value)
  - Mode gauge `eezo_consensus_mode_active` reports 2 for `dag-only`
  
- **T78.11**: Feature-gate HotStuff code
  - Create `hotstuff-consensus` feature flag (default off for devnet)
  - Wrap HotStuff runner code with `#[cfg(feature = "hotstuff-consensus")]`
  - Update `crates/node/Cargo.toml` default features to exclude HotStuff
  
- **T78.12**: DAG finality mechanism
  - Implement or verify DAG-native finality (depth-based or voting-based)
  - Add `eezo_dag_finality_depth` gauge
  - Add `eezo_dag_finalized_blocks_total` counter
  - Ensure finality is deterministic and matches across nodes
  
- **T78.13**: Remove or disable fallback paths
  - Remove all mempool fallback code in `dag-only` mode
  - Simplify `dag_consensus_runner.rs` to remove hybrid logic
  - Update block builder to only accept DAG-ordered batches
  
- **T78.14**: Update configuration and scripts
  - Set `EEZO_CONSENSUS_MODE=dag-only` as devnet default
  - Remove or comment out HotStuff-related env vars in `devnet.env`
  - Update `scripts/spam_tps.sh` and `scripts/spam_multi.sh` for dag-only testing
  - Create `scripts/t78_dag_only_check.sh` for validation
  
- **T78.15**: Documentation and runbook updates
  - Update `book/src/t76_dag_hybrid_canary.md` with deprecation notice
  - Create operational runbook for DAG-only mode
  - Document known limitations and troubleshooting steps
  - Add migration guide for testnet/mainnet operators

**Code Areas:**

| File/Module | Changes |
|-------------|---------|
| `crates/ledger/src/consensus.rs` | Add `dag-only` mode, document finality |
| `crates/node/src/consensus_runner.rs` | Feature-gate with `hotstuff-consensus` |
| `crates/node/src/dag_consensus_runner.rs` | Simplify to pure DAG operation |
| `crates/node/src/dag_runner.rs` | Implement/verify finality mechanism |
| `crates/node/src/main.rs` | Parse `dag-only` mode, skip HotStuff init |
| `crates/node/src/metrics.rs` | Add DAG finality metrics |
| `crates/node/Cargo.toml` | Add `hotstuff-consensus` feature (default off) |
| `book/src/t76_dag_hybrid_canary.md` | Add deprecation notice for hybrid mode |
| `devnet.env` | Set `EEZO_CONSENSUS_MODE=dag-only` |
| `scripts/t78_dag_only_check.sh` | Create DAG-only validation script |

**Acceptance Metrics:**

| Metric | Target | Measurement Window |
|--------|--------|-------------------|
| `eezo_consensus_mode_active` | 2 (dag-only) | Continuous |
| `eezo_dag_finalized_blocks_total` | Monotonically increasing | Continuous |
| `eezo_dag_finality_depth` | Stable (e.g., 3-5 blocks) | 24-hour test |
| `eezo_txs_included_total` rate | ≥250 TPS | Sustained load test |
| Apply success rate | ≥99.9% | 30-day canary |
| Block height continuity | No rollbacks/gaps | Restart tests |

**Exit Criteria:**
- 30-day canary with zero hash mismatches
- TPS meets or exceeds Phase 2 baseline (≥250 TPS)
- All SAFE tests (T77) pass in dag-only mode
- Zero fallbacks (no fallback path exists)
- Finality validated across multi-node devnet
- No dev-unsafe flags in devnet build config

---

## Devnet Readiness Criteria for DAG-Only

Before declaring DAG-Only mode ready for devnet production and progression to testnet, the following criteria must be met:

### 1. Stability & Correctness

| Criterion | Requirement | Validation Method |
|-----------|-------------|-------------------|
| **Minimum Run Duration** | 30 consecutive days under load | Continuous canary monitoring |
| **Hash Mismatches** | Zero (`eezo_dag_shadow_hash_mismatch_total` = 0) | Metrics validation |
| **HotStuff Fallbacks** | Zero (no fallback path in dag-only) | Architecture verification |
| **Block Height Continuity** | No rollbacks or gaps across restarts | Restart cycle testing (10+ restarts) |
| **Finality Consistency** | All nodes agree on finalized blocks | Multi-node devnet validation |

### 2. Performance

| Criterion | Requirement | Validation Method |
|-----------|-------------|-------------------|
| **TPS Baseline** | ≥150 TPS (current baseline) | `scripts/measure_tps.sh` over 1-hour window |
| **TPS Target** | ≥250 TPS (stretch goal: 400 TPS) | Peak load test with `scripts/spam_multi.sh` |
| **Ordering Latency** | p99 <50ms | `eezo_dag_ordering_latency_seconds` histogram |
| **Apply Success Rate** | ≥99.9% | `eezo_dag_hybrid_apply_ok_total` / total |
| **No Performance Regression** | TPS ≥ Phase 2 baseline | Comparative benchmarking |

### 3. Test Coverage

| Criterion | Requirement | Validation Method |
|-----------|-------------|-------------------|
| **All SAFE Tests Pass** | 100% of T77 SAFE-1/2/3 tests | `cargo test --workspace` |
| **Ledger Tests** | 100% pass in dag-only mode | `cargo test -p eezo-ledger` |
| **Node Tests** | 100% pass in dag-only mode | `cargo test -p eezo-node` |
| **Integration Tests** | Multi-node consensus tests pass | `crates/net/tests/consensus_sim.rs` |
| **Stress Tests** | Sustained load (1000+ tx/min) for 24h | Custom load generation scripts |

### 4. Security & Safety

| Criterion | Requirement | Validation Method |
|-----------|-------------|-------------------|
| **No Dev-Unsafe Flags** | `dev-unsafe` feature not in devnet build | Verify `Cargo.toml` default features |
| **Signature Verification** | All transactions verified (no bypass) | Audit of devnet config |
| **TTL Configuration** | Appropriate TTL set (not 0 in production) | Review `devnet.env` |
| **Nonce Gap Protection** | SAFE-1 nonce-gap fix active | Test with out-of-order transactions |
| **No Critical CodeQL Alerts** | Zero critical vulnerabilities | `cargo audit` and CodeQL scan |

### 5. Operational Readiness

| Criterion | Requirement | Validation Method |
|-----------|-------------|-------------------|
| **Monitoring & Alerting** | All key metrics exported and tested | Prometheus/Grafana dashboard |
| **Runbook Documentation** | Complete operational runbook for dag-only | Review `book/src/t78_dag_only_devnet.md` |
| **Rollback Procedure** | Documented and tested rollback to hybrid | Simulate failure and rollback |
| **Log Analysis** | No unexpected errors or warnings | Review logs for 24-hour period |
| **Emergency Contact Plan** | On-call rotation and escalation defined | Team documentation |

### 6. Feature Completeness

| Criterion | Requirement | Validation Method |
|-----------|-------------|-------------------|
| **DAG Finality** | Deterministic finality implemented | Multi-node finality agreement tests |
| **Metrics Coverage** | All Phase 3 metrics implemented | Review metrics endpoint |
| **Configuration Validation** | Invalid configs rejected gracefully | Test with malformed `devnet.env` |
| **Error Handling** | DAG failures logged and handled | Simulate network partition |
| **State Persistence** | State survives crashes/restarts | Kill node, restart, verify continuity |

### 7. Documentation

| Criterion | Requirement | Validation Method |
|-----------|-------------|-------------------|
| **Architecture Diagram** | Updated to reflect dag-only | Review documentation |
| **Configuration Guide** | Complete env var documentation | Cross-reference with code |
| **Migration Guide** | Hybrid → dag-only migration steps | Peer review by team |
| **Troubleshooting Guide** | Common issues and resolutions | Community feedback |
| **API Documentation** | RPC endpoints updated if needed | API documentation review |

---

## Risk Assessment & Contingency Planning

### High-Priority Risks

1. **DAG Ordering Failure in Production**
   - **Risk**: DAG fails to order transactions under unexpected load patterns
   - **Probability**: Low (validated in Phase 1 & 2)
   - **Impact**: High (network halt)
   - **Mitigation**: Emergency rollback to dag-primary with shadow HotStuff
   - **Detection**: `eezo_dag_ordering_failed_total` metric

2. **Finality Divergence Across Nodes**
   - **Risk**: Different nodes finalize different blocks
   - **Probability**: Medium (new finality mechanism)
   - **Impact**: Critical (chain split)
   - **Mitigation**: Extensive multi-node testing in Phase 3
   - **Detection**: `eezo_dag_finality_depth` discrepancies across nodes

3. **Performance Degradation**
   - **Risk**: TPS drops below baseline (150 TPS)
   - **Probability**: Low (Phase 2 should reveal issues)
   - **Impact**: Medium (poor user experience)
   - **Mitigation**: Rollback to hybrid mode, tune aggregation parameters
   - **Detection**: `scripts/measure_tps.sh` continuous monitoring

4. **Undetected Hash Mismatches**
   - **Risk**: Ordering correctness issues not caught by metrics
   - **Probability**: Very Low (validated in Phase 1 & 2)
   - **Impact**: Critical (data corruption)
   - **Mitigation**: Shadow HotStuff in Phase 2 catches this early
   - **Detection**: Multi-node state comparison scripts

### Contingency Procedures

#### Emergency Rollback to DAG-Primary (Phase 3 → Phase 2)

```bash
# Stop the node
pkill -f eezo-node

# Switch back to dag-primary mode with shadow HotStuff
export EEZO_CONSENSUS_MODE=dag-primary

# Restart node
./target/release/eezo-node
```

**Validation:**
```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_consensus_mode_active
# Expected: eezo_consensus_mode_active 3 (dag-primary)
curl -s http://127.0.0.1:9898/metrics | grep eezo_hotstuff_shadow_active
# Expected: eezo_hotstuff_shadow_active 1
```

#### Emergency Rollback to DAG-Hybrid (Phase 2 → Phase 1)

```bash
# Stop the node
pkill -f eezo-node

# Switch back to dag-hybrid mode
export EEZO_CONSENSUS_MODE=dag-hybrid
export EEZO_DAG_ORDERING_ENABLED=1

# Restart node
./target/release/eezo-node
```

**Validation:**
```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_consensus_mode_active
# Expected: eezo_consensus_mode_active 1 (dag-hybrid)
```

#### Emergency Rollback to Pure HotStuff (Any Phase → Phase 0)

```bash
# Stop the node
pkill -f eezo-node

# Switch to pure HotStuff mode
export EEZO_CONSENSUS_MODE=hotstuff
export EEZO_DAG_ORDERING_ENABLED=0

# Restart node
./target/release/eezo-node
```

**Validation:**
```bash
curl -s http://127.0.0.1:9898/metrics | grep eezo_consensus_mode_active
# Expected: eezo_consensus_mode_active 0 (hotstuff)
```

---

## Timeline & Dependencies

### Estimated Timeline

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| **Phase 1: Strict Hybrid** | 4-6 weeks | T77 completion |
| **Phase 2: DAG-Primary** | 6-8 weeks | Phase 1 exit criteria met |
| **Phase 3: DAG-Only** | 8-10 weeks | Phase 2 exit criteria met |
| **Total Estimated Duration** | 18-24 weeks | - |

### Task Dependencies

```
T77 (SAFE-1/2/3) [COMPLETE]
    ↓
T78.1-T78.4 (Phase 1: Strict Hybrid)
    ↓
T78.5-T78.9 (Phase 2: DAG-Primary)
    ↓
T78.10-T78.15 (Phase 3: DAG-Only)
    ↓
Extended Devnet Canary (30 days)
    ↓
Testnet Migration Planning (T79.x)
```

### Parallel Work Opportunities

- **T78.2** (latency monitoring) can be developed in parallel with **T78.1** (tuning)
- **T78.7** (shadow metrics) can be developed in parallel with **T78.6** (shadow runner)
- **T78.14** (scripts) and **T78.15** (docs) can be developed in parallel with **T78.10-T78.13**

---

## Success Metrics & KPIs

### Key Performance Indicators (KPIs)

| KPI | Baseline (T77) | Phase 1 Target | Phase 2 Target | Phase 3 Target |
|-----|---------------|----------------|----------------|----------------|
| **TPS (sustained)** | ~150 TPS | ≥200 TPS | ≥250 TPS | ≥250 TPS |
| **TPS (peak)** | ~200 TPS | ≥300 TPS | ≥400 TPS | ≥400 TPS |
| **Ordering Latency (p99)** | <100ms | <75ms | <50ms | <50ms |
| **Apply Success Rate** | ≥99.9% | ≥99.9% | ≥99.9% | ≥99.9% |
| **Fallback Rate** | 0/hr | 0/hr | 0/hr (none) | N/A (no fallback) |
| **Hash Mismatch Rate** | 0/day | 0/day | 0/day | 0/day |

### Monitoring Dashboard

A Grafana dashboard should track the following panels:

1. **Consensus Mode** (`eezo_consensus_mode_active`)
2. **DAG Ordering Latency** (`eezo_dag_ordering_latency_seconds` histogram)
3. **Fallback Count** (`eezo_dag_hybrid_fallback_total` - Phase 1 & 2 only)
4. **Hash Mismatches** (`eezo_dag_shadow_hash_mismatch_total`)
5. **TPS** (derived from `eezo_txs_included_total`)
6. **Apply Success Rate** (ratio of `apply_ok` / `apply_total`)
7. **Shadow Divergence** (`eezo_hotstuff_shadow_divergence_total` - Phase 2 only)
8. **DAG Finality Depth** (`eezo_dag_finality_depth` - Phase 3)

---

## Next Steps (Post-T78)

### T79.x: Testnet Migration

Once DAG-Only mode is stable in devnet:

1. **T79.1**: Multi-node testnet deployment
   - Deploy DAG-only mode to 4-10 node testnet
   - Validate finality consensus across nodes
   - Test network partition recovery

2. **T79.2**: Extended testnet canary (90 days)
   - Public testnet with external validators
   - Monitor for Byzantine behavior
   - Stress test with high transaction volumes

3. **T79.3**: Testnet upgrade procedure
   - Document in-place upgrade from hybrid → dag-only
   - Test coordinated network upgrade
   - Validate state continuity

### T80.x: Mainnet Readiness

1. **T80.1**: Security audit
   - Third-party audit of DAG consensus implementation
   - Formal verification of finality mechanism (if applicable)
   - Penetration testing

2. **T80.2**: Economic analysis
   - Finality impact on settlement times
   - Gas cost modeling for DAG-only transactions
   - Validator incentive alignment

3. **T80.3**: Mainnet migration strategy
   - Gradual rollout with canary percentage (10% → 50% → 100%)
   - Feature flag strategy for rapid rollback
   - Communication plan for validators and users

---

## References

- [T76.12: DAG-Hybrid 7-Day Canary & SLO Runbook](./t76_dag_hybrid_canary.md)
- [Dev-Unsafe Modes (T77.SAFE-2)](./dev_unsafe_modes.md)
- [T77.SAFE-1: Nonce-gap fix](../issue.txt) *(if available)*
- [T77.SAFE-3: TTL caps implementation](./dev_unsafe_modes.md#ttl-configuration)

---

## Appendix A: Consensus Mode Values

| Mode | Value | Description | Status |
|------|-------|-------------|--------|
| `hotstuff` | 0 | Pure HotStuff BFT (legacy) | Deprecated after T78 |
| `dag-hybrid` | 1 | HotStuff + DAG ordering (current) | Active (T77) |
| `dag-only` | 2 | DAG-only consensus (target) | Future (T78.10) |
| `dag-primary` | 3 | DAG primary with shadow HotStuff | Intermediate (T78.5) |

## Appendix B: Feature Flag Strategy

| Feature Flag | Default (Devnet) | Default (Testnet) | Default (Mainnet) | Purpose |
|--------------|------------------|-------------------|-------------------|---------|
| `hotstuff-consensus` | `false` (Phase 3) | `true` (initially) | `true` | Enable/disable HotStuff code |
| `dag-ordering` | `true` | `true` | `true` | Enable/disable DAG ordering |
| `dev-unsafe` | `false` | `false` | `false` | Dev-only signature bypass (T77.SAFE-2) |
| `pq44-runtime` | `true` | `true` | `true` | Post-quantum cryptography |
| `metrics` | `true` | `true` | `true` | Prometheus metrics export |

## Appendix C: Environment Variables Summary

| Variable | Phase 1 | Phase 2 | Phase 3 | Purpose |
|----------|---------|---------|---------|---------|
| `EEZO_CONSENSUS_MODE` | `dag-hybrid` | `dag-primary` | `dag-only` | Consensus mode selection |
| `EEZO_DAG_ORDERING_ENABLED` | `1` | `1` | `1` | Enable DAG ordering layer |
| `EEZO_EXECUTOR_MODE` | `stm` | `stm` | `stm` | STM executor |
| `EEZO_EXEC_LANES` | `32` | `32` | `32` | Parallel execution lanes |
| `EEZO_EXEC_WAVE_CAP` | `256` | `256` | `256` | Max tx per execution wave |
| `EEZO_MEMPOOL_TTL_SECS` | `0` | `300` (5min) | `300` | TTL for mempool entries |
| `EEZO_HYBRID_AGG_TIME_BUDGET_MS` | `150-200` | `200` | N/A | Batch aggregation budget |
| `EEZO_ENABLE_HOTSTUFF_FALLBACK_OVERRIDE` | N/A | `0` (emergency only) | N/A | Emergency fallback (Phase 2) |

---

## Document Change Log

| Date | Version | Author | Changes |
|------|---------|--------|---------|
| 2025-12-06 | 1.0 | Design Team | Initial draft for T78.0 |

---

**Status**: This is a design document. No code changes are included in T78.0. Implementation will proceed in subsequent tasks (T78.1-T78.15).
