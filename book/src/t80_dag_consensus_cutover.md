# T80.0: Pure DAG Consensus Cutover

## Overview

**EEZO's production consensus is pure DAG.** HotStuff exists only as an optional "lab/shadow" mode and never drives decisions.

This document describes the T80.0 Pure DAG Consensus Cutover, which establishes DAG as the canonical consensus mechanism for all EEZO network deployments (devnet, testnet, mainnet).

## Key Principles

1. **DAG is Production**: DAG consensus is the sole source of block finality, ordering, and liveness.
2. **HotStuff is Legacy**: HotStuff is retained only for shadow/lab observability, not for production decisions.
3. **Shadow Never Decides**: The shadow checker may verify, log, and emit metrics, but never affects block production.
4. **Feature-Gated**: HotStuff code is completely excluded in dag-only builds.

## Architecture

### Consensus Hierarchy

| Mode | Description | Production Use |
|------|-------------|----------------|
| `dag-only` build | DAG is sole consensus, no HotStuff code | ✅ **Recommended** |
| `devnet-safe` + `dag-primary` | DAG primary with optional shadow checker | ✅ Production |
| `dag-hybrid` | DAG primary with mempool fallback | Transition only |
| `hotstuff` | Pure HotStuff (legacy) | ❌ Not for production |

### Safety Properties

The shadow HotStuff checker (when enabled) **NEVER**:
- Decides block finality
- Causes the node to reject or roll back a committed DAG block
- Alters the behavior of DAG block production or commit
- Panics the node (even on mismatch detection)
- Affects block ordering or liveness

The shadow checker **ONLY**:
- Verifies DAG decisions (height monotonicity, basic consistency)
- Emits metrics for observability
- Logs warnings on detected mismatches

---

## Build Commands

### DAG-Only Build (Recommended for Production)

The canonical production build excludes all HotStuff code:

```bash
# Pure DAG consensus — no HotStuff compiled
cargo build --release -p eezo-node --features "dag-only"
```

This build:
- Compiles successfully ✅
- Uses DAG as the only consensus mode
- Has no HotStuff types, handlers, or threads linked
- Runs a single-node dag-primary devnet
- Passes all DAG integration tests

### DAG + Shadow Build (Development/Observability)

For development and transition observability, include the shadow checker:

```bash
# DAG primary with HotStuff shadow checker
cargo build --release -p eezo-node --features "devnet-safe,hotstuff-shadow"
```

This build:
- Uses dag-primary mode as default
- Includes the shadow HotStuff checker for metrics
- Shadow checker only logs and emits metrics
- Suitable for canary deployments during transition

### Legacy/Testing Builds

For backward compatibility testing only (NOT for production):

```bash
# Generic build (HotStuff available but not recommended)
cargo build --release -p eezo-node --features "default"

# Run in dag-primary mode explicitly
EEZO_CONSENSUS_MODE=dag-primary ./target/release/eezo-node
```

---

## Configuration

### Environment Variables

| Variable | Default (dag-only) | Default (devnet-safe) | Default (generic) | Description |
|----------|-------------------|----------------------|-------------------|-------------|
| `EEZO_CONSENSUS_MODE` | `dag-primary` (forced) | `dag-primary` | `hotstuff` | Consensus mode |
| `EEZO_DAG_ORDERING_ENABLED` | `true` (forced) | `true` | `false` | Enable DAG ordering |
| `EEZO_DAG_PRIMARY_SHADOW_ENABLED` | N/A | `0` | `0` | Enable shadow checker |

### Mode Selection Behavior

| Build Feature | `EEZO_CONSENSUS_MODE=hotstuff` | `EEZO_CONSENSUS_MODE=dag-primary` | Unset |
|--------------|-------------------------------|-----------------------------------|-------|
| `dag-only` | ⚠️ Ignored → dag-primary | dag-primary | dag-primary |
| `devnet-safe` | hotstuff (with warning) | dag-primary | dag-primary |
| Generic | hotstuff | dag-primary | hotstuff |

---

## Metrics

### Consensus Mode Gauge

```
# HELP eezo_consensus_mode_active Active consensus mode: 0=hotstuff, 1=hybrid, 2=dag, 3=dag-primary
# TYPE eezo_consensus_mode_active gauge
eezo_consensus_mode_active 3
```

Values:
- `0` = HotStuff (legacy, not for production)
- `1` = dag-hybrid (transition)
- `2` = dag (legacy)
- `3` = dag-primary (PRODUCTION)

### Shadow Checker Metrics (when enabled)

```
# Total shadow checks performed
eezo_dag_primary_shadow_checks_total

# Total mismatches detected (informational only)
eezo_dag_primary_shadow_mismatch_total

# Mismatch by reason (informational only)
eezo_dag_primary_shadow_mismatch_reason_total{reason="height_regress"}
eezo_dag_primary_shadow_mismatch_reason_total{reason="height_equal"}
eezo_dag_primary_shadow_mismatch_reason_total{reason="hash_mismatch"}
```

**Important**: Shadow mismatch metrics are for observability only. A non-zero mismatch count does NOT indicate a consensus failure — DAG decisions are canonical.

---

## Verification

### Verify DAG-Only Build

```bash
# Build with dag-only feature
cargo build --release -p eezo-node --features "dag-only"

# Start the node
./target/release/eezo-node --genesis genesis.min.json --datadir /tmp/eezo-dag

# Check consensus mode (should be 3 = dag-primary)
curl -s http://localhost:9898/metrics | grep eezo_consensus_mode_active
# Expected: eezo_consensus_mode_active 3

# Verify no HotStuff fallback occurs
curl -s http://localhost:9898/metrics | grep eezo_dag_hybrid_fallback_total
# Expected: eezo_dag_hybrid_fallback_total 0 (or not present)
```

### Verify DAG + Shadow Build

```bash
# Build with shadow checker
cargo build --release -p eezo-node --features "devnet-safe,hotstuff-shadow"

# Start with shadow enabled
EEZO_DAG_PRIMARY_SHADOW_ENABLED=1 ./target/release/eezo-node \
  --genesis genesis.min.json --datadir /tmp/eezo-shadow

# Check shadow checks are running
curl -s http://localhost:9898/metrics | grep eezo_dag_primary_shadow_checks_total
# Expected: Increasing counter

# Check for mismatches (should be 0 in healthy operation)
curl -s http://localhost:9898/metrics | grep eezo_dag_primary_shadow_mismatch_total
# Expected: 0 (mismatches are informational only)
```

---

## Migration Guide

### From HotStuff to DAG

1. **Update build command**: Change from default features to `dag-only` or `devnet-safe`
2. **Remove HotStuff configuration**: `EEZO_CONSENSUS_MODE=hotstuff` is no longer needed
3. **Verify metrics**: Check `eezo_consensus_mode_active = 3`
4. **Monitor shadow metrics** (if using shadow build): Observe `shadow_mismatch_total = 0`

### Example Migration Script

```bash
#!/bin/bash
# migrate_to_dag.sh — T80.0 migration helper

echo "Building DAG-only node..."
cargo build --release -p eezo-node --features "dag-only"

echo "Migrating configuration..."
# Remove legacy HotStuff config (if present)
unset EEZO_CONSENSUS_MODE
unset EEZO_HOTSTUFF_VIEW_TIMEOUT

echo "Starting DAG node..."
./target/release/eezo-node --genesis genesis.json --datadir /var/eezo

echo "Verifying consensus mode..."
sleep 5
curl -s http://localhost:9898/metrics | grep eezo_consensus_mode_active
```

---

## Feature Flag Summary

| Feature | Description | HotStuff Code | Shadow Checker |
|---------|-------------|---------------|----------------|
| `dag-only` | Pure DAG production build | ❌ Not compiled | ❌ Not available |
| `devnet-safe` | DAG-primary with optional shadow | ✅ Available | ❌ By default |
| `devnet-safe` + `hotstuff-shadow` | DAG + shadow checker | ✅ Available | ✅ Available |
| Default | Generic build | ✅ Available | ❌ Not available |
| `dev-unsafe` | Local benchmarks only | ✅ Available | ❌ Not available |

---

## Acceptance Criteria (T80.0)

✅ **DAG-only build command exists**: `cargo build --release -p eezo-node --features "dag-only"`

✅ **DAG-only build**:
- Compiles successfully
- Runs a single-node dag-primary devnet
- Passes main DAG integration tests (consensus, liveness, health)

✅ **DAG + shadow build command exists**: `cargo build --release -p eezo-node --features "devnet-safe,hotstuff-shadow"`

✅ **DAG + shadow build**:
- Behaves like current dag-primary + shadow devnet
- Keeps shadow metrics (shadow checks, mismatches)
- Passes dag-primary shadow integration tests

✅ **In DAG-only builds**:
- No HotStuff code linked into the binary
- All core consensus, checkpoint, state sync, and bridge paths use DAG semantics only

✅ **In both builds**:
- No changes to block/tx formats or cryptographic behavior
- All existing non-HotStuff tests still pass

---

## References

- [T78: DAG-Only Devnet & Strict Hybrid Tuning](t78_dag_only_devnet.md)
- [T78.6: DAG-Primary Canary & SLO Runbook](t78_dag_primary_canary.md)
- [T76: DAG-Hybrid Canary & SLO Runbook](t76_dag_hybrid_canary.md)
- [Dev Unsafe Modes & Build Profiles Matrix](dev_unsafe_modes.md)
