# T80.0: Pure DAG Consensus Cutover

## Overview

**EEZO's production consensus is pure DAG.** As of T81, HotStuff has been removed from the live codebase and exists only in historical context (earlier milestones).

This document describes the T80.0 Pure DAG Consensus Cutover, which established DAG as the canonical consensus mechanism for all EEZO network deployments (devnet, testnet, mainnet).

## Key Principles

1. **DAG is Production**: DAG consensus is the sole source of block finality, ordering, and liveness.
2. **HotStuff is Historical**: HotStuff was removed in T81 and exists only in historical documentation.
3. **No Shadow Mode in Production**: The shadow checker was a transition tool; production builds exclude it.
4. **Feature-Gated**: In dag-only builds, only DAG code is compiled.

## Architecture

### Consensus Hierarchy

| Mode | Description | Production Use |
|------|-------------|----------------|
| `dag-only` build | DAG is sole consensus, pure DAG code | ✅ **Recommended** |
| `devnet-safe` | DAG-primary with dev features | ✅ Production |

Note: Legacy modes (`dag-hybrid`, `hotstuff`) existed in earlier milestones but have been removed as of T81.

### Safety Properties

In dag-only builds:
- DAG is the only consensus implementation
- No fallback or shadow modes exist
- All consensus decisions are made by DAG

---

## Build Commands

### DAG-Only Build (Recommended for Production)

The canonical production build uses pure DAG consensus:

```bash
# Pure DAG consensus — recommended for production
cargo build --release -p eezo-node --features "dag-only"
```

This build:
- Compiles successfully ✅
- Uses DAG as the only consensus mode
- Runs a single-node dag-primary devnet
- Passes all DAG integration tests

### Devnet-Safe Build (Development)

For development with additional features:

```bash
# Devnet-safe with all recommended features
cargo build --release -p eezo-node --features "devnet-safe"
```

This build:
- Uses dag-primary mode as default
- Includes metrics and checkpointing
- Suitable for development and testing

---

## Configuration

### Environment Variables

| Variable | Default (dag-only) | Default (devnet-safe) | Description |
|----------|-------------------|----------------------|-------------|
| `EEZO_CONSENSUS_MODE` | `dag-primary` (forced) | `dag-primary` | Consensus mode |
| `EEZO_DAG_ORDERING_ENABLED` | `true` (forced) | `true` | Enable DAG ordering |

Note: In dag-only builds, the consensus mode is always dag-primary regardless of environment variable settings.

---

## Metrics

### Consensus Mode Gauge

```
# HELP eezo_consensus_mode_active Active consensus mode (3 = dag-primary)
# TYPE eezo_consensus_mode_active gauge
eezo_consensus_mode_active 3
```

Value `3` indicates dag-primary mode (the production mode).

### DAG Health Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_block_height` | Gauge | Current block height |
| `eezo_txs_included_total` | Counter | Total transactions included |
| `eezo_dag_ordered_ready` | Gauge | DAG batches ready for commit |

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

# Check health endpoint
curl -s http://localhost:8080/health/dag_primary | jq .
```

---

## Migration Guide

### Upgrading to DAG-Only

1. **Update build command**: Use `--features dag-only` or `--features devnet-safe`
2. **Remove legacy configuration**: Legacy consensus mode environment variables are ignored
3. **Verify metrics**: Check `eezo_consensus_mode_active = 3`

### Example Start Script

```bash
#!/bin/bash
# start_dag_node.sh — T81 DAG-only node starter

echo "Building DAG-only node..."
cargo build --release -p eezo-node --features "dag-only"

echo "Starting DAG node..."
./target/release/eezo-node --genesis genesis.json --datadir /var/eezo

echo "Verifying consensus mode..."
sleep 5
curl -s http://localhost:9898/metrics | grep eezo_consensus_mode_active
```

---

## Feature Flag Summary

| Feature | Description | Production Use |
|---------|-------------|----------------|
| `dag-only` | Pure DAG production build | ✅ Recommended |
| `devnet-safe` | DAG-primary with dev features | ✅ Devnet |
| `metrics` | Prometheus metrics endpoint | ✅ Recommended |
| `checkpoints` | Block checkpointing | ✅ Recommended |

---

## Acceptance Criteria (T80.0 / T81)

✅ **DAG-only build command exists**: `cargo build --release -p eezo-node --features "dag-only"`

✅ **DAG-only build**:
- Compiles successfully
- Runs a single-node dag-primary devnet
- Passes main DAG integration tests (consensus, liveness, health)

✅ **In DAG-only builds**:
- DAG is the only consensus mode
- All core consensus, checkpoint, state sync, and bridge paths use DAG semantics only

✅ **In both builds**:
- No changes to block/tx formats or cryptographic behavior
- All existing tests still pass

---

## References

- [T81: EEZO Consensus History & DAG-Only Runtime](t81_consensus_history.md)
- [T78: DAG-Only Devnet & Strict Hybrid Tuning](t78_dag_only_devnet.md)
- [T78.6: DAG-Primary Canary & SLO Runbook](t78_dag_primary_canary.md)
- [Dev Unsafe Modes & Build Profiles Matrix](dev_unsafe_modes.md)