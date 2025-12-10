# T81: EEZO Consensus History & DAG-Only Runtime

## Overview

**EEZO's production consensus is pure DAG.** This document describes the consensus history and the T80/T81 transition that established DAG as the sole consensus mechanism.

## Current State (Post-T81)

As of T81, EEZO uses **pure DAG consensus** for all production deployments:

- **DAG is the only consensus mechanism** — no HotStuff code is compiled in production builds
- **HotStuff exists only in historical context** — earlier milestones (T27, T76, T78) used HotStuff
- **Health and metrics surfaces are DAG-only** — all observability is centered on DAG consensus

## Consensus History

### T27: HotStuff-like Pipeline (Historical)

The original EEZO consensus was based on a HotStuff-like 3-phase pipeline:
- Prepare → PreCommit → Commit
- Used for early development and testing
- Provided a foundation for understanding BFT consensus

### T76: DAG-Hybrid Mode (Transition)

T76 introduced hybrid mode where:
- DAG provided transaction ordering
- HotStuff provided finality as a fallback
- This allowed gradual validation of DAG behavior

### T78: DAG-Primary Mode (Validation)

T78 made DAG the primary consensus:
- DAG was the sole source of transaction ordering
- HotStuff ran as a shadow checker for comparison
- Validated that pure DAG ordering was correct

### T80: Pure DAG Consensus Cutover

T80 established DAG as the canonical consensus:
- `dag-only` feature flag introduced
- HotStuff code can be completely excluded from builds
- Production builds use `--features dag-only`

### T81: HotStuff Removal from Live Codebase

T81 completed the transition:
- T81.1: Removed HotStuff from live code paths
- T81.2: Updated health and metrics to be DAG-only
- T81.3: Documentation cleanup and final verification

## Build Commands

### Official Production Build

The recommended build command for production (devnet/testnet/mainnet):

```bash
# Pure DAG consensus — no legacy code compiled
cargo build --release -p eezo-node --features "dag-only"
```

This build:
- Uses DAG as the only consensus mode
- Has no HotStuff types, handlers, or threads linked
- Provides the smallest binary size
- Is suitable for all network deployments

### Devnet-Safe Build

For development with additional features:

```bash
# Devnet-safe with all recommended features
cargo build --release -p eezo-node --features "devnet-safe"
```

This build:
- Defaults to dag-primary mode
- Includes metrics and checkpointing
- Does NOT include unsigned transaction support

## Run Commands

### Single-Node DAG-Primary Devnet

Start a single-node devnet with metrics and health endpoints:

```bash
# Set data directory
export EEZO_DATADIR=/tmp/eezo-devnet

# Enable metrics endpoint
export EEZO_METRICS_BIND=127.0.0.1:9898

# Start the node (dag-primary is the default in dag-only/devnet-safe builds)
./target/release/eezo-node --genesis genesis.min.json --datadir /tmp/eezo-devnet
```

Or use the official launcher script:

```bash
./scripts/devnet_dag_primary.sh
```

### Verify Consensus Mode

After starting the node, verify it's running in dag-primary mode:

```bash
# Check consensus mode gauge (expect 3 = dag-primary)
curl -s http://127.0.0.1:9898/metrics | grep eezo_consensus_mode_active
# Expected: eezo_consensus_mode_active 3

# Check health endpoint
curl -s http://127.0.0.1:8080/health/dag_primary | jq .
```

## Metrics

### Consensus Mode Gauge

```
# HELP eezo_consensus_mode_active Active consensus mode (3 = dag-primary)
# TYPE eezo_consensus_mode_active gauge
eezo_consensus_mode_active 3
```

Value `3` indicates dag-primary mode (the only production mode).

### DAG Health Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_block_height` | Gauge | Current block height |
| `eezo_txs_included_total` | Counter | Total transactions included |
| `eezo_dag_ordered_ready` | Gauge | DAG batches ready for commit |

## Feature Flags

| Feature | Description | Production Use |
|---------|-------------|----------------|
| `dag-only` | Pure DAG build, no legacy code | ✅ Recommended |
| `devnet-safe` | DAG-primary with dev features | ✅ Devnet |
| `metrics` | Prometheus metrics endpoint | ✅ Recommended |
| `checkpoints` | Block checkpointing | ✅ Recommended |

## Legacy Code Note

The codebase retains some references to HotStuff for:
- Historical documentation (this file, earlier milestone docs)
- Test infrastructure that validates consensus message signing
- Type definitions used by the generic consensus message system

These are **historical artifacts** and do not affect production behavior. In `dag-only` builds, HotStuff-specific code paths are not compiled.

## References

- [T80: Pure DAG Consensus Cutover](t80_dag_consensus_cutover.md)
- [T78: DAG-Only Devnet & Strict Hybrid Tuning](t78_dag_only_devnet.md)
- [Dev Unsafe Modes & Build Profiles](dev_unsafe_modes.md)
