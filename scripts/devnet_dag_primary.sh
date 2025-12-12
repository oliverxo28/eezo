#!/usr/bin/env bash
set -euo pipefail

# T78.9/T79.0: Official devnet-safe DAG-primary launcher (no unsigned tx).
#
# This script is the canonical entrypoint for running a devnet-safe DAG-primary node.
# It configures the recommended environment variables and starts the node with
# the devnet-safe feature set.
#
# IMPORTANT: This script does NOT set EEZO_DEV_ALLOW_UNSIGNED_TX.
# The devnet-safe build profile does not support unsigned transactions.
# For local TPS benchmarks with unsigned tx, see the dev-unsafe profile in:
#   book/src/dev_unsafe_modes.md
#
# ═══════════════════════════════════════════════════════════════════════════════
# T84.5: High-Throughput TPS Profile
# ═══════════════════════════════════════════════════════════════════════════════
# For maximum TPS benchmarking (150–250 TPS on laptop), source the T84.5
# configuration before running this script:
#
#   source devnet_tps.env
#   ./scripts/devnet_dag_primary.sh
#
# Or run with explicit env vars:
#   EEZO_MEMPOOL_ACTOR_ENABLED=1 \
#   EEZO_PERSIST_ASYNC=1 \
#   EEZO_PIPELINE_ENABLED=1 \
#   EEZO_LAZY_STATE_ROOT=1 \
#   EEZO_SIGPOOL_THREADS=4 \
#   EEZO_SIGPOOL_BATCH_SIZE=128 \
#   ./scripts/devnet_dag_primary.sh
#
# See book/src/t84_plateau.md for complete documentation.
# ═══════════════════════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/devnet_dag_primary.sh
#
# Optional: Override any variable by exporting it before running this script.
# Example:
#   export EEZO_EXEC_LANES=64
#   ./scripts/devnet_dag_primary.sh

# Change to repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "═══════════════════════════════════════════════════════════════"
echo "  T79.0: Official devnet-safe DAG-primary Launcher"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ───────────────────────────────────────────────────────────────────────────────
# Core Consensus Mode (dag-primary is the default in devnet-safe, but set explicitly)
# ───────────────────────────────────────────────────────────────────────────────
export EEZO_CONSENSUS_MODE="${EEZO_CONSENSUS_MODE:-dag-primary}"
export EEZO_DAG_ORDERING_ENABLED="${EEZO_DAG_ORDERING_ENABLED:-1}"
export EEZO_DAG_PRIMARY_SHADOW_ENABLED="${EEZO_DAG_PRIMARY_SHADOW_ENABLED:-1}"
export EEZO_HYBRID_STRICT_PROFILE="${EEZO_HYBRID_STRICT_PROFILE:-1}"

# ───────────────────────────────────────────────────────────────────────────────
# STM Executor Configuration (T73/T76)
# ───────────────────────────────────────────────────────────────────────────────
export EEZO_EXECUTOR_MODE="${EEZO_EXECUTOR_MODE:-stm}"
export EEZO_EXEC_LANES="${EEZO_EXEC_LANES:-32}"
export EEZO_EXEC_WAVE_CAP="${EEZO_EXEC_WAVE_CAP:-256}"

# ───────────────────────────────────────────────────────────────────────────────
# T79.0: Health Check Window (seconds for activity checks)
# ───────────────────────────────────────────────────────────────────────────────
export EEZO_DAG_PRIMARY_HEALTH_WINDOW_SECS="${EEZO_DAG_PRIMARY_HEALTH_WINDOW_SECS:-60}"

# ───────────────────────────────────────────────────────────────────────────────
# T84.5: High-Throughput Performance Settings (preserve from env if set)
# These are optional; if not set, the node runs without these optimizations.
# For max TPS, source devnet_tps.env first (see header comments).
# ───────────────────────────────────────────────────────────────────────────────
# EEZO_MEMPOOL_ACTOR_ENABLED - Enable mempool actor for better admission
# EEZO_PERSIST_ASYNC         - Async RocksDB persistence (T83.2)
# EEZO_PIPELINE_ENABLED      - Block execution pipelining (T83.3)
# EEZO_LAZY_STATE_ROOT       - Incremental state root (T84.0)
# EEZO_SIGPOOL_THREADS       - Signature verification threads (T83.0)
# EEZO_SIGPOOL_BATCH_SIZE    - Signature micro-batch size (T83.0)

# ───────────────────────────────────────────────────────────────────────────────
# Data Directory (clean start by default)
# ───────────────────────────────────────────────────────────────────────────────
export EEZO_DATADIR="${EEZO_DATADIR:-/tmp/eezo-devnet}"

# ───────────────────────────────────────────────────────────────────────────────
# Network Bindings
# NOTE: Defaults to localhost (127.0.0.1) for local development.
# For external access (e.g., devnet deployment), override with:
#   export EEZO_LISTEN=0.0.0.0:8080
#   export EEZO_METRICS_BIND=0.0.0.0:9898
# ───────────────────────────────────────────────────────────────────────────────
export EEZO_LISTEN="${EEZO_LISTEN:-127.0.0.1:8080}"
export EEZO_METRICS_BIND="${EEZO_METRICS_BIND:-127.0.0.1:9898}"

# ───────────────────────────────────────────────────────────────────────────────
# Clean start (remove old data directory)
# ───────────────────────────────────────────────────────────────────────────────
if [[ "${EEZO_KEEP_DATA:-0}" != "1" ]]; then
    echo "Cleaning data directory: $EEZO_DATADIR"
    rm -rf "$EEZO_DATADIR"
else
    echo "Keeping existing data directory: $EEZO_DATADIR"
fi

# ───────────────────────────────────────────────────────────────────────────────
# Print Configuration Summary
# ───────────────────────────────────────────────────────────────────────────────
echo ""
echo "Configuration:"
echo "  EEZO_CONSENSUS_MODE=$EEZO_CONSENSUS_MODE"
echo "  EEZO_DAG_ORDERING_ENABLED=$EEZO_DAG_ORDERING_ENABLED"
echo "  EEZO_DAG_PRIMARY_SHADOW_ENABLED=$EEZO_DAG_PRIMARY_SHADOW_ENABLED"
echo "  EEZO_HYBRID_STRICT_PROFILE=$EEZO_HYBRID_STRICT_PROFILE"
echo "  EEZO_EXECUTOR_MODE=$EEZO_EXECUTOR_MODE"
echo "  EEZO_EXEC_LANES=$EEZO_EXEC_LANES"
echo "  EEZO_EXEC_WAVE_CAP=$EEZO_EXEC_WAVE_CAP"
echo "  EEZO_DAG_PRIMARY_HEALTH_WINDOW_SECS=$EEZO_DAG_PRIMARY_HEALTH_WINDOW_SECS"
echo "  EEZO_DATADIR=$EEZO_DATADIR"
echo "  EEZO_LISTEN=$EEZO_LISTEN"
echo "  EEZO_METRICS_BIND=$EEZO_METRICS_BIND"
echo ""
echo "T84.5 TPS Profile (if set):"
echo "  EEZO_MEMPOOL_ACTOR_ENABLED=${EEZO_MEMPOOL_ACTOR_ENABLED:-<not set>}"
echo "  EEZO_PERSIST_ASYNC=${EEZO_PERSIST_ASYNC:-<not set>}"
echo "  EEZO_PIPELINE_ENABLED=${EEZO_PIPELINE_ENABLED:-<not set>}"
echo "  EEZO_LAZY_STATE_ROOT=${EEZO_LAZY_STATE_ROOT:-<not set>}"
echo "  EEZO_SIGPOOL_THREADS=${EEZO_SIGPOOL_THREADS:-<not set>}"
echo "  EEZO_SIGPOOL_BATCH_SIZE=${EEZO_SIGPOOL_BATCH_SIZE:-<not set>}"
echo ""
echo "Build features: devnet-safe,metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Endpoints (once started):"
echo "  Mode:                 $EEZO_CONSENSUS_MODE"
echo "  HTTP Base URL:        http://${EEZO_LISTEN}"
echo "  Metrics URL:          http://${EEZO_METRICS_BIND}/metrics"
echo "  Health (general):     http://${EEZO_LISTEN}/health"
echo "  Health (dag-primary): http://${EEZO_LISTEN}/health/dag_primary"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ───────────────────────────────────────────────────────────────────────────────
# Run the node with devnet-safe feature set
# ───────────────────────────────────────────────────────────────────────────────
exec cargo run -p eezo-node --bin eezo-node \
  --features "devnet-safe,metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus" -- \
  --genesis genesis.min.json \
  --datadir "$EEZO_DATADIR"
