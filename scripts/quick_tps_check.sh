#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# T97.0: Quick TPS Check
# ═══════════════════════════════════════════════════════════════════════════════
#
# This script performs a one-shot TPS verification using the high-TPS devnet preset.
# It starts a fresh node, runs a spam workload, measures TPS, and prints metrics.
#
# Expected TPS: ~330-380 TPS in short burst scenarios with all optimizations.
#
# Usage:
#   ./scripts/quick_tps_check.sh [TX_COUNT] [TPS_WINDOW_SECONDS]
#
# Arguments:
#   TX_COUNT           - Number of transactions to submit (default: 2000)
#   TPS_WINDOW_SECONDS - Measurement window in seconds (default: 10)
#
# The node is left running after the test so you can attach profilers.
# Press Ctrl+C to shut down.
#
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Arguments
# ─────────────────────────────────────────────────────────────────────────────
TX_COUNT="${1:-2000}"
TPS_WINDOW="${2:-10}"

# ─────────────────────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

NODE_URL="http://127.0.0.1:8080"
METRICS_URL="http://127.0.0.1:9898/metrics"

# Check for required tools
MISSING_TOOLS=()
for cmd in jq curl awk bc; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        MISSING_TOOLS+=("$cmd")
    fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    echo "[quick_tps] ERROR: Missing required tools: ${MISSING_TOOLS[*]}" >&2
    echo "  Ubuntu/Debian: sudo apt-get install bc jq curl gawk" >&2
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Source the high-TPS preset
# ─────────────────────────────────────────────────────────────────────────────
if [[ ! -f "$REPO_ROOT/high_tps_devnet.env" ]]; then
    echo "[quick_tps] ERROR: high_tps_devnet.env not found in $REPO_ROOT" >&2
    exit 1
fi

echo "═══════════════════════════════════════════════════════════════════════════════════"
echo "  T97.0: Quick TPS Check"
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "Loading high-TPS preset..."
set -a
source "$REPO_ROOT/high_tps_devnet.env"
set +a

# Override datadir for this test
export EEZO_DATADIR="/tmp/eezo-quick-tps"

NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8)

echo ""
echo "Configuration:"
echo "  TX_COUNT:              $TX_COUNT"
echo "  TPS_WINDOW:            ${TPS_WINDOW}s"
echo "  NPROC:                 $NPROC"
echo "  DATADIR:               $EEZO_DATADIR"
echo ""
echo "High-TPS Settings:"
echo "  EEZO_CONSENSUS_MODE:           $EEZO_CONSENSUS_MODE"
echo "  EEZO_DAG_ORDERING_ENABLED:     $EEZO_DAG_ORDERING_ENABLED"
echo "  EEZO_STM_KERNEL_MODE:          $EEZO_STM_KERNEL_MODE"
echo "  EEZO_STM_SIMPLE_FASTPATH_ENABLED: $EEZO_STM_SIMPLE_FASTPATH_ENABLED"
echo "  EEZO_CUDA_HASH_ENABLED:        $EEZO_CUDA_HASH_ENABLED"
echo "  EEZO_BLOCK_MAX_TX:             $EEZO_BLOCK_MAX_TX"
echo "  EEZO_BLOCK_TARGET_TIME_MS:     $EEZO_BLOCK_TARGET_TIME_MS"
echo ""
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Helper: Get metric value from Prometheus endpoint
# ─────────────────────────────────────────────────────────────────────────────
get_metric() {
    local name="$1"
    local url="$2"
    local val
    val=$(curl -sf "$url" 2>/dev/null | awk -v n="$name" '$1 == n { print $2; exit }' || echo "")
    if [[ -z "$val" ]]; then
        echo "0"
    else
        echo "$val"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper: Convert a value to integer (handles both "123" and "123.0" formats)
# ─────────────────────────────────────────────────────────────────────────────
to_int() {
    local val="$1"
    local result
    if [[ "$val" == *"."* ]]; then
        result=${val%.*}
    else
        result="$val"
    fi
    if [[ -z "$result" ]] || ! [[ "$result" =~ ^-?[0-9]+$ ]]; then
        echo "0"
    else
        echo "$result"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper: Wait for node to be ready
# ─────────────────────────────────────────────────────────────────────────────
wait_for_ready() {
    local url="$1"
    local max_wait="${2:-60}"
    local waited=0
    
    while [[ $waited -lt 15 ]]; do
        if curl -sf "${url}/health" >/dev/null 2>&1; then
            break
        fi
        sleep 1
        ((waited++))
    done
    
    if [[ $waited -ge 15 ]]; then
        echo "[quick_tps] ERROR: Node HTTP server did not start within 15s" >&2
        return 1
    fi
    
    while [[ $waited -lt $max_wait ]]; do
        if curl -sf "${url}/ready" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        ((waited++))
    done
    echo "[quick_tps] ERROR: Node /ready did not return 200 within ${max_wait}s" >&2
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper: Cleanup background node process
# ─────────────────────────────────────────────────────────────────────────────
cleanup_node() {
    local pid="$1"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        echo ""
        echo "[quick_tps] Shutting down node (PID: $pid)..."
        kill "$pid" 2>/dev/null || true
        sleep 2
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Kill any existing eezo-node process
# ─────────────────────────────────────────────────────────────────────────────
echo "[quick_tps] Stopping any existing eezo-node..."
pkill -f "eezo-node" 2>/dev/null || true
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
# Build binaries
# ─────────────────────────────────────────────────────────────────────────────
NODE_FEATURES="pq44-runtime,metrics,checkpoints,stm-exec,dag-consensus,cuda-hash"

echo "[quick_tps] Building eezo-node (release)..."
cargo build -p eezo-node --bin eezo-node \
    --features "$NODE_FEATURES" \
    --release --quiet 2>/dev/null || \
cargo build -p eezo-node --bin eezo-node \
    --features "$NODE_FEATURES" \
    --release

echo "[quick_tps] Building helper binaries..."
cargo build -p eezo-crypto --bin ml_dsa_keygen --release --quiet 2>/dev/null || \
    cargo build -p eezo-crypto --bin ml_dsa_keygen --release
cargo build -p eezo-node --bin eezo-txgen --release --quiet 2>/dev/null || \
    cargo build -p eezo-node --bin eezo-txgen --release

# Ensure target/debug/eezo-txgen exists (spam_tps.sh needs it)
if [[ ! -x "target/debug/eezo-txgen" ]]; then
    if [[ -x "target/release/eezo-txgen" ]]; then
        mkdir -p target/debug
        ln -sf ../release/eezo-txgen target/debug/eezo-txgen
    fi
fi

NODE_BIN="$REPO_ROOT/target/release/eezo-node"
if [[ ! -x "$NODE_BIN" ]]; then
    echo "[quick_tps] ERROR: eezo-node binary not found at $NODE_BIN" >&2
    exit 1
fi

echo "[quick_tps] Build complete"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Wipe datadir and start fresh node
# ─────────────────────────────────────────────────────────────────────────────
rm -rf "$EEZO_DATADIR"

echo "[quick_tps] Starting node with high-TPS config..."

NODE_PID=""
trap 'cleanup_node "$NODE_PID"' EXIT

"$NODE_BIN" --genesis genesis.min.json --datadir "$EEZO_DATADIR" >"$EEZO_DATADIR.log" 2>&1 &
NODE_PID=$!

echo "[quick_tps] Node started (PID: $NODE_PID, log: $EEZO_DATADIR.log)"

# Wait for node to be ready
echo "[quick_tps] Waiting for node to be ready..."
if ! wait_for_ready "$NODE_URL" 60; then
    echo "[quick_tps] ERROR: Node failed to start" >&2
    cat "$EEZO_DATADIR.log" | tail -50 >&2
    exit 1
fi
echo "[quick_tps] Node ready"
echo ""

# Small delay for metrics to initialize
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
# Capture baseline metrics
# ─────────────────────────────────────────────────────────────────────────────
echo "[quick_tps] Capturing baseline metrics..."
STM_BEFORE=$(get_metric "eezo_exec_stm_time_seconds" "$METRICS_URL")
HASH_BEFORE=$(get_metric "eezo_hash_cpu_time_seconds" "$METRICS_URL")
TX_BEFORE=$(get_metric "eezo_txs_included_total" "$METRICS_URL")

echo "  Baseline: stm=$STM_BEFORE hash=$HASH_BEFORE tx=$TX_BEFORE"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Run fund + spam
# ─────────────────────────────────────────────────────────────────────────────
echo "[quick_tps] Running fund + spam ($TX_COUNT transactions)..."
echo ""

SPAM_START=$(date +%s)

if ! "$SCRIPT_DIR/t93_fund_and_spam.sh" "$TX_COUNT" "$NODE_URL"; then
    echo "[quick_tps] ERROR: Spam failed" >&2
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Measure TPS over the window
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "[quick_tps] Measuring TPS over ${TPS_WINDOW}s window..."

# Get start counts
TPS_TX_START=$(get_metric "eezo_txs_included_total" "$METRICS_URL")
TPS_TS_START=$(date +%s)

sleep "$TPS_WINDOW"

# Get end counts
TPS_TX_END=$(get_metric "eezo_txs_included_total" "$METRICS_URL")
TPS_TS_END=$(date +%s)

# Compute TPS
TPS_TX_DELTA=$(echo "$TPS_TX_END - $TPS_TX_START" | bc)
TPS_TIME_DELTA=$((TPS_TS_END - TPS_TS_START))

if [[ "$TPS_TIME_DELTA" -gt 0 ]]; then
    MEASURED_TPS=$(echo "scale=2; $TPS_TX_DELTA / $TPS_TIME_DELTA" | bc -l)
else
    MEASURED_TPS="N/A"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Wait for remaining transactions to be included
# ─────────────────────────────────────────────────────────────────────────────
echo "[quick_tps] Waiting for remaining transactions..."
sleep 5

SPAM_END=$(date +%s)
WALL_ELAPSED=$((SPAM_END - SPAM_START))

# ─────────────────────────────────────────────────────────────────────────────
# Capture final metrics
# ─────────────────────────────────────────────────────────────────────────────
echo "[quick_tps] Capturing final metrics..."
STM_AFTER=$(get_metric "eezo_exec_stm_time_seconds" "$METRICS_URL")
HASH_AFTER=$(get_metric "eezo_hash_cpu_time_seconds" "$METRICS_URL")
TX_AFTER=$(get_metric "eezo_txs_included_total" "$METRICS_URL")
BLOCKS_AFTER=$(get_metric "block_applied_total" "$METRICS_URL")

# DAG ordering metrics
DAG_ORDERING_ENABLED=$(get_metric "eezo_dag_ordering_enabled" "$METRICS_URL")
DAG_ORDERED_TXS=$(get_metric "eezo_dag_ordered_txs_total" "$METRICS_URL")

# STM fastpath metrics
FASTPATH_ENABLED=$(get_metric "eezo_exec_stm_simple_fastpath_enabled" "$METRICS_URL")
FASTPATH_CANDIDATES=$(get_metric "eezo_stm_simple_candidate_total" "$METRICS_URL")
FASTPATH_TOTAL=$(get_metric "eezo_stm_simple_fastpath_total" "$METRICS_URL")
FASTPATH_FALLBACK=$(get_metric "eezo_stm_simple_fallback_total" "$METRICS_URL")

# T97.0 metrics
ARC_CLONES=$(get_metric "eezo_stm_tx_arc_clones_total" "$METRICS_URL")
ACCOUNT_CLONES=$(get_metric "eezo_stm_account_clones_total" "$METRICS_URL")

# Compute deltas
DELTA_STM=$(echo "$STM_AFTER - $STM_BEFORE" | bc -l)
DELTA_HASH=$(echo "$HASH_AFTER - $HASH_BEFORE" | bc -l)
DELTA_TX=$(echo "$TX_AFTER - $TX_BEFORE" | bc)

DELTA_TX_INT=$(to_int "$DELTA_TX")
BLOCKS_INT=$(to_int "$BLOCKS_AFTER")

# Compute derived metrics
if [[ "$DELTA_TX_INT" -gt 0 ]]; then
    STM_PER_TX=$(echo "scale=8; $DELTA_STM / $DELTA_TX_INT" | bc -l)
    HASH_PER_TX=$(echo "scale=10; $DELTA_HASH / $DELTA_TX_INT" | bc -l)
    STM_PER_TX_MS=$(echo "scale=4; $STM_PER_TX * 1000" | bc -l)
    HASH_PER_TX_US=$(echo "scale=4; $HASH_PER_TX * 1000000" | bc -l)
else
    STM_PER_TX_MS="N/A"
    HASH_PER_TX_US="N/A"
fi

if [[ "$BLOCKS_INT" -gt 0 ]]; then
    TX_PER_BLOCK=$(echo "scale=2; $DELTA_TX_INT / $BLOCKS_INT" | bc -l)
else
    TX_PER_BLOCK="N/A"
fi

if [[ "$WALL_ELAPSED" -gt 0 ]] && [[ "$DELTA_TX_INT" -gt 0 ]]; then
    OVERALL_TPS=$(echo "scale=2; $DELTA_TX_INT / $WALL_ELAPSED" | bc -l)
else
    OVERALL_TPS="N/A"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Print summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo "  Quick TPS Check Results"
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "TPS Measurements:"
echo "  Measured TPS (${TPS_WINDOW}s window): $MEASURED_TPS"
echo "  Overall TPS (wall time):          $OVERALL_TPS"
echo "  Tx in window:                     $(to_int "$TPS_TX_DELTA")"
echo "  Total tx included:                $DELTA_TX_INT"
echo "  Total blocks:                     $BLOCKS_INT"
echo "  Tx per block:                     $TX_PER_BLOCK"
echo ""
echo "Timing Metrics:"
printf "  Δeezo_exec_stm_time_seconds:    %.4f s\n" "$DELTA_STM"
printf "  Δeezo_hash_cpu_time_seconds:    %.6f s\n" "$DELTA_HASH"
if [[ "$STM_PER_TX_MS" != "N/A" ]]; then
    echo "  STM per tx:                     ${STM_PER_TX_MS} ms"
    echo "  Hash per tx:                    ${HASH_PER_TX_US} µs"
fi
echo "  Wall time:                      ${WALL_ELAPSED}s"
echo ""
echo "DAG Ordering Metrics:"
echo "  eezo_dag_ordering_enabled:      $(to_int "$DAG_ORDERING_ENABLED")"
echo "  eezo_dag_ordered_txs_total:     $(to_int "$DAG_ORDERED_TXS")"
echo ""
echo "STM Simple Fastpath Metrics:"
echo "  eezo_exec_stm_simple_fastpath_enabled: $(to_int "$FASTPATH_ENABLED")"
echo "  eezo_stm_simple_candidate_total:       $(to_int "$FASTPATH_CANDIDATES")"
echo "  eezo_stm_simple_fastpath_total:        $(to_int "$FASTPATH_TOTAL")"
echo "  eezo_stm_simple_fallback_total:        $(to_int "$FASTPATH_FALLBACK")"
echo ""
echo "T97.0 Arc-Free Metrics:"
echo "  eezo_stm_tx_arc_clones_total:   $(to_int "$ARC_CLONES")"
echo "  eezo_stm_account_clones_total:  $(to_int "$ACCOUNT_CLONES")"
echo ""
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "  Node is still running (PID: $NODE_PID) for profiler attachment."
echo "  Log file: $EEZO_DATADIR.log"
echo ""
echo "  To attach a profiler:"
echo "    sudo perf record -F 99 -p $NODE_PID -g -- sleep 20"
echo ""
echo "  Press Ctrl+C to shut down the node."
echo ""
echo "═══════════════════════════════════════════════════════════════════════════════════"

# Keep node alive indefinitely until user presses Ctrl+C
trap - EXIT  # Remove the cleanup trap
echo "[quick_tps] Node running. Press Ctrl+C to stop..."
wait "$NODE_PID" || true
