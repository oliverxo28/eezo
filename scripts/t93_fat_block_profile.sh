#!/usr/bin/env bash
# T93.1: Fat-Block STM Profiler
#
# This script runs a single eezo-node instance with aggressive "fat-block"
# configuration to maximize transactions per block and minimize per-block
# overhead. It's designed for profiling the STM inner loop under load.
#
# After running the spam workload, the node is kept alive so an external
# profiler (e.g., perf, flamegraph) can be attached for detailed analysis.
#
# Usage:
#   scripts/t93_fat_block_profile.sh [TX_COUNT] [KEEP_ALIVE_SECONDS]
#
# Arguments:
#   TX_COUNT          - Number of transactions to submit (default: 5000)
#   KEEP_ALIVE_SECONDS - How long to keep node running after spam (default: 60)
#
# Fat-Block Configuration:
#   EEZO_BLOCK_MAX_TX=2000         - Pack up to 2000 txs per block
#   EEZO_BLOCK_TARGET_TIME_MS=250  - Target 250ms block time (short blocks)
#   EEZO_MEMPOOL_MAX_TX=50000      - Large mempool capacity
#   EEZO_MEMPOOL_MAX_BYTES=100000000 - 100MB mempool
#
# STM Configuration (optimized defaults from T93.0):
#   EEZO_EXEC_LANES=16             - 16 parallel execution lanes
#   EEZO_EXECUTOR_THREADS=(nproc)  - All available CPU threads
#   EEZO_EXEC_WAVE_CAP=256         - Wave size cap (256 often performs best)
#   EEZO_EXEC_BUCKETS=64           - 64 STM buckets
#   EEZO_EXEC_HYBRID=1             - Enable hybrid execution
#   EEZO_EXEC_WAVE_COMPACT=1       - Enable wave compaction
#
# Requirements:
#   - cargo, jq, curl, awk, bc
#   - ml_dsa_keygen and eezo-txgen binaries built
#   - Port 8080 and 9898 available
#
# Profiler Instructions (separate terminal):
#   # Attach perf for 20 seconds while spam is running
#   sudo perf record -F 99 -p $(pgrep -f eezo-node) -g -- sleep 20
#   sudo perf script > perf.script
#
#   # Or using cargo-flamegraph (simpler)
#   cargo flamegraph -p eezo-node --bin eezo-node ...

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Arguments
# ─────────────────────────────────────────────────────────────────────────────
TX_COUNT="${1:-5000}"
KEEP_ALIVE_SECONDS="${2:-60}"

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
for cmd in jq curl awk bc cargo; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        MISSING_TOOLS+=("$cmd")
    fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    echo "[t93_fat_block] ERROR: Missing required tools: ${MISSING_TOOLS[*]}" >&2
    echo "  Ubuntu/Debian: sudo apt-get install bc jq curl gawk" >&2
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8)
DATADIR="/tmp/eezo-t93-fat-block"

echo "═══════════════════════════════════════════════════════════════════════════════════"
echo "  T93.1: Fat-Block STM Profiler"
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "Configuration:"
echo "  TX_COUNT:              $TX_COUNT"
echo "  KEEP_ALIVE_SECONDS:    $KEEP_ALIVE_SECONDS"
echo "  NPROC:                 $NPROC"
echo "  DATADIR:               $DATADIR"
echo ""
echo "Fat-Block Settings:"
echo "  EEZO_BLOCK_MAX_TX:         2000"
echo "  EEZO_BLOCK_TARGET_TIME_MS: 250"
echo "  EEZO_MEMPOOL_MAX_TX:       50000"
echo ""
echo "STM Settings (optimized):"
echo "  EEZO_EXEC_LANES:       16"
echo "  EEZO_EXECUTOR_THREADS: $NPROC"
echo "  EEZO_EXEC_WAVE_CAP:    256"
echo "  EEZO_EXEC_BUCKETS:     64"
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
# Helper: Wait for node to be ready
# ─────────────────────────────────────────────────────────────────────────────
wait_for_ready() {
    local url="$1"
    local max_wait="${2:-60}"
    local waited=0
    
    # First wait for HTTP server to be up via /health
    while [[ $waited -lt 15 ]]; do
        if curl -sf "${url}/health" >/dev/null 2>&1; then
            break
        fi
        sleep 1
        ((waited++))
    done
    
    if [[ $waited -ge 15 ]]; then
        echo "[t93_fat_block] ERROR: Node HTTP server did not start within 15s" >&2
        return 1
    fi
    
    # Now wait for /ready to return 200
    while [[ $waited -lt $max_wait ]]; do
        if curl -sf "${url}/ready" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        ((waited++))
    done
    echo "[t93_fat_block] ERROR: Node /ready did not return 200 within ${max_wait}s" >&2
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper: Cleanup background node process
# ─────────────────────────────────────────────────────────────────────────────
cleanup_node() {
    local pid="$1"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        echo "[t93_fat_block] Shutting down node (PID: $pid)..."
        kill "$pid" 2>/dev/null || true
        sleep 2
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Ensure cleanup on exit
# ─────────────────────────────────────────────────────────────────────────────
NODE_PID=""
trap 'cleanup_node "$NODE_PID"' EXIT

# ─────────────────────────────────────────────────────────────────────────────
# Build the node binary
# ─────────────────────────────────────────────────────────────────────────────
echo "[t93_fat_block] Building eezo-node (release)..."
cargo build -p eezo-node --bin eezo-node \
    --features "pq44-runtime,metrics,checkpoints,stm-exec,dag-consensus,cuda-hash" \
    --release --quiet 2>/dev/null || \
cargo build -p eezo-node --bin eezo-node \
    --features "pq44-runtime,metrics,checkpoints,stm-exec,dag-consensus,cuda-hash" \
    --release

# Build helper binaries
echo "[t93_fat_block] Building helper binaries..."
cargo build -p eezo-crypto --bin ml_dsa_keygen --release --quiet 2>/dev/null || \
    cargo build -p eezo-crypto --bin ml_dsa_keygen --release
cargo build -p eezo-node --bin eezo-txgen --release --quiet 2>/dev/null || \
    cargo build -p eezo-node --bin eezo-txgen --release

# Ensure target/debug/eezo-txgen exists (spam_tps.sh needs it)
if [[ ! -x "target/debug/eezo-txgen" ]]; then
    if [[ -x "target/release/eezo-txgen" ]]; then
        echo "[t93_fat_block] creating symlink target/debug/eezo-txgen -> ../release/eezo-txgen"
        mkdir -p target/debug
        ln -sf ../release/eezo-txgen target/debug/eezo-txgen
    fi
fi

NODE_BIN="$REPO_ROOT/target/release/eezo-node"
if [[ ! -x "$NODE_BIN" ]]; then
    echo "[t93_fat_block] ERROR: eezo-node binary not found at $NODE_BIN" >&2
    exit 1
fi

echo "[t93_fat_block] Build complete"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Start node with fat-block configuration
# ─────────────────────────────────────────────────────────────────────────────
rm -rf "$DATADIR"

echo "[t93_fat_block] Starting node with fat-block config..."

EEZO_CUDA_HASH_ENABLED=1 \
EEZO_CONSENSUS_MODE=dag-primary \
EEZO_BLOCK_MAX_TX=2000 \
EEZO_BLOCK_TARGET_TIME_MS=250 \
EEZO_MEMPOOL_MAX_TX=50000 \
EEZO_MEMPOOL_MAX_BYTES=100000000 \
EEZO_EXEC_LANES=16 \
EEZO_EXECUTOR_THREADS="$NPROC" \
RAYON_NUM_THREADS="$NPROC" \
EEZO_EXEC_WAVE_CAP=256 \
EEZO_EXEC_BUCKETS=64 \
EEZO_EXEC_HYBRID=1 \
EEZO_EXEC_WAVE_COMPACT=1 \
EEZO_DATADIR="$DATADIR" \
EEZO_LISTEN="127.0.0.1:8080" \
EEZO_METRICS_BIND="127.0.0.1:9898" \
"$NODE_BIN" --genesis genesis.min.json --datadir "$DATADIR" >"$DATADIR.log" 2>&1 &
NODE_PID=$!

echo "[t93_fat_block] Node started (PID: $NODE_PID, log: $DATADIR.log)"

# Wait for node to be ready
echo "[t93_fat_block] Waiting for node to be ready..."
if ! wait_for_ready "$NODE_URL" 60; then
    echo "[t93_fat_block] ERROR: Node failed to start" >&2
    cat "$DATADIR.log" | tail -50 >&2
    exit 1
fi
echo "[t93_fat_block] Node ready"
echo ""

# Small delay for metrics to initialize
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
# Capture baseline metrics
# ─────────────────────────────────────────────────────────────────────────────
echo "[t93_fat_block] Capturing baseline metrics..."
STM_BEFORE=$(get_metric "eezo_exec_stm_time_seconds" "$METRICS_URL")
HASH_BEFORE=$(get_metric "eezo_hash_cpu_time_seconds" "$METRICS_URL")
TX_BEFORE=$(get_metric "eezo_txs_included_total" "$METRICS_URL")
BLOCKS_BEFORE=$(get_metric "block_applied_total" "$METRICS_URL")

echo "  Baseline: stm=$STM_BEFORE hash=$HASH_BEFORE tx=$TX_BEFORE blocks=$BLOCKS_BEFORE"
echo ""

# Record wall-clock start
WALL_START=$(date +%s)

# ─────────────────────────────────────────────────────────────────────────────
# Run fund + spam
# ─────────────────────────────────────────────────────────────────────────────
echo "[t93_fat_block] Running fund + spam ($TX_COUNT transactions)..."
echo ""

if ! "$SCRIPT_DIR/t93_fund_and_spam.sh" "$TX_COUNT" "$NODE_URL"; then
    echo "[t93_fat_block] ERROR: Spam failed" >&2
    exit 1
fi

echo ""
echo "[t93_fat_block] Waiting for transactions to be included..."
sleep 10

# Record wall-clock end
WALL_END=$(date +%s)
WALL_ELAPSED=$((WALL_END - WALL_START))

# ─────────────────────────────────────────────────────────────────────────────
# Capture post metrics and compute deltas
# ─────────────────────────────────────────────────────────────────────────────
echo "[t93_fat_block] Capturing post metrics..."
STM_AFTER=$(get_metric "eezo_exec_stm_time_seconds" "$METRICS_URL")
HASH_AFTER=$(get_metric "eezo_hash_cpu_time_seconds" "$METRICS_URL")
TX_AFTER=$(get_metric "eezo_txs_included_total" "$METRICS_URL")
BLOCKS_AFTER=$(get_metric "block_applied_total" "$METRICS_URL")

echo "  Post:     stm=$STM_AFTER hash=$HASH_AFTER tx=$TX_AFTER blocks=$BLOCKS_AFTER"
echo ""

# Compute deltas
DELTA_STM=$(echo "$STM_AFTER - $STM_BEFORE" | bc -l)
DELTA_HASH=$(echo "$HASH_AFTER - $HASH_BEFORE" | bc -l)
DELTA_TX=$(echo "$TX_AFTER - $TX_BEFORE" | bc)
DELTA_BLOCKS=$(echo "$BLOCKS_AFTER - $BLOCKS_BEFORE" | bc)

# Handle integer conversion
if [[ "$DELTA_TX" == *"."* ]]; then
    DELTA_TX_INT=${DELTA_TX%.*}
else
    DELTA_TX_INT="$DELTA_TX"
fi
if [[ "$DELTA_BLOCKS" == *"."* ]]; then
    DELTA_BLOCKS_INT=${DELTA_BLOCKS%.*}
else
    DELTA_BLOCKS_INT="$DELTA_BLOCKS"
fi
[[ -z "$DELTA_TX_INT" ]] && DELTA_TX_INT=0
[[ -z "$DELTA_BLOCKS_INT" ]] && DELTA_BLOCKS_INT=0

# Compute derived metrics
if [[ "$DELTA_TX_INT" -gt 0 ]]; then
    STM_PER_TX=$(echo "scale=8; $DELTA_STM / $DELTA_TX_INT" | bc -l)
    HASH_PER_TX=$(echo "scale=10; $DELTA_HASH / $DELTA_TX_INT" | bc -l)
    STM_PER_TX_MS=$(echo "scale=4; $STM_PER_TX * 1000" | bc -l)
    HASH_PER_TX_US=$(echo "scale=4; $HASH_PER_TX * 1000000" | bc -l)
else
    STM_PER_TX="N/A"
    HASH_PER_TX="N/A"
    STM_PER_TX_MS="N/A"
    HASH_PER_TX_US="N/A"
fi

if [[ "$DELTA_BLOCKS_INT" -gt 0 ]]; then
    TX_PER_BLOCK=$(echo "scale=2; $DELTA_TX_INT / $DELTA_BLOCKS_INT" | bc -l)
else
    TX_PER_BLOCK="N/A"
fi

if [[ "$WALL_ELAPSED" -gt 0 ]] && [[ "$DELTA_TX_INT" -gt 0 ]]; then
    TPS=$(echo "scale=2; $DELTA_TX_INT / $WALL_ELAPSED" | bc -l)
else
    TPS="N/A"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Print summary
# ─────────────────────────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo "  Fat-Block Profiling Results"
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "Delta Metrics:"
printf "  Δeezo_exec_stm_time_seconds:  %.4f s\n" "$DELTA_STM"
printf "  Δeezo_hash_cpu_time_seconds:  %.6f s\n" "$DELTA_HASH"
echo "  Δeezo_txs_included_total:     $DELTA_TX_INT"
echo "  Δblock_applied_total:         $DELTA_BLOCKS_INT"
echo ""
echo "Derived Metrics:"
if [[ "$STM_PER_TX" != "N/A" ]]; then
    printf "  STM per tx:     %.6f s (%s ms)\n" "$STM_PER_TX" "$STM_PER_TX_MS"
    printf "  Hash per tx:    %.8f s (%s µs)\n" "$HASH_PER_TX" "$HASH_PER_TX_US"
else
    echo "  STM per tx:     N/A (no transactions included)"
    echo "  Hash per tx:    N/A"
fi
echo "  Tx per block:   $TX_PER_BLOCK"
echo "  Approximate TPS: $TPS"
echo "  Wall time:      ${WALL_ELAPSED}s"
echo ""
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "  Node is still running (PID: $NODE_PID) for profiler attachment."
echo "  Log file: $DATADIR.log"
echo ""
echo "  To attach a profiler in another terminal:"
echo "    sudo perf record -F 99 -p $NODE_PID -g -- sleep 20"
echo "    sudo perf script > perf.script"
echo ""
echo "  Or run more spam while profiling:"
echo "    scripts/t93_fund_and_spam.sh $TX_COUNT $NODE_URL"
echo ""
echo "  The node will shut down automatically in $KEEP_ALIVE_SECONDS seconds."
echo "  Press Ctrl+C to shut down immediately."
echo ""
echo "═══════════════════════════════════════════════════════════════════════════════════"

# Keep node alive for profiling
echo "[t93_fat_block] Keeping node alive for $KEEP_ALIVE_SECONDS seconds..."
sleep "$KEEP_ALIVE_SECONDS"

echo "[t93_fat_block] Done."
