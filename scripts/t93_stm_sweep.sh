#!/usr/bin/env bash
# T93.0: STM Executor Tuning Harness (Config Sweep & TPS Profiler)
#
# This script sweeps STM-related runtime knobs and runs standard spam scenarios,
# capturing Prometheus metrics to measure STM time per tx, hash time per tx,
# and TPS. It prints a summary table showing which configs perform better.
#
# Usage:
#   scripts/t93_stm_sweep.sh [TX_COUNT] [NODE_URL] [METRICS_URL]
#
# Arguments:
#   TX_COUNT    - Number of transactions to submit per config (default: 2000)
#   NODE_URL    - Node HTTP URL (default: http://127.0.0.1:8080)
#   METRICS_URL - Prometheus metrics endpoint (default: http://127.0.0.1:9898/metrics)
#
# Environment Variables (fixed during sweep):
#   EEZO_CUDA_HASH_ENABLED=1
#   EEZO_CONSENSUS_MODE=dag-primary
#   EEZO_EXEC_HYBRID=1
#   EEZO_EXEC_WAVE_COMPACT=1
#
# Swept Variables:
#   EEZO_EXEC_LANES       - {8, 16, 32}
#   EEZO_EXECUTOR_THREADS - {nproc, nproc/2}
#   EEZO_EXEC_WAVE_CAP    - {0, 128, 256}
#   EEZO_EXEC_BUCKETS     - {32, 64}
#
# Requirements:
#   - cargo, jq, curl, awk, bc
#   - ml_dsa_keygen and eezo-txgen binaries built
#   - Port 8080 and 9898 available
#
# Output:
#   Prints one summary line per config, e.g.:
#   lanes=16 threads=8 wavecap=256 buckets=64 \
#     tx=2000 blocks=320 \
#     stm_time=3.45s hash_time=0.01s \
#     stm_per_tx=0.0017s hash_per_tx=0.000003s \
#     tx_per_block=6.25

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Arguments
# ─────────────────────────────────────────────────────────────────────────────
TX_COUNT="${1:-2000}"
NODE_URL="${2:-http://127.0.0.1:8080}"
METRICS_URL="${3:-http://127.0.0.1:9898/metrics}"

# ─────────────────────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Check for required tools with helpful error messages
MISSING_TOOLS=()
for cmd in jq curl awk bc cargo; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        MISSING_TOOLS+=("$cmd")
    fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    echo "[t93_sweep] ERROR: Missing required tools: ${MISSING_TOOLS[*]}" >&2
    echo "" >&2
    echo "Installation hints:" >&2
    echo "  Ubuntu/Debian: sudo apt-get install bc jq curl gawk" >&2
    echo "  macOS:         brew install bc jq curl gawk" >&2
    echo "  Cargo:         https://rustup.rs/" >&2
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Config Matrix
# ─────────────────────────────────────────────────────────────────────────────
NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8)
HALF_NPROC=$((NPROC / 2))
if [[ "$HALF_NPROC" -lt 1 ]]; then
    HALF_NPROC=1
fi

LANES_SET=(8 16 32)
THREADS_SET=("$NPROC" "$HALF_NPROC")
WAVECAP_SET=(0 128 256)
BUCKETS_SET=(32 64)

echo "═══════════════════════════════════════════════════════════════════════════════════"
echo "  T93.0: STM Executor Tuning Harness"
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "Configuration:"
echo "  TX_COUNT:     $TX_COUNT"
echo "  NODE_URL:     $NODE_URL"
echo "  METRICS_URL:  $METRICS_URL"
echo "  nproc:        $NPROC"
echo ""
echo "Sweep Matrix:"
echo "  LANES:        ${LANES_SET[*]}"
echo "  THREADS:      ${THREADS_SET[*]}"
echo "  WAVECAP:      ${WAVECAP_SET[*]}"
echo "  BUCKETS:      ${BUCKETS_SET[*]}"
echo ""

# Calculate total configs
TOTAL_CONFIGS=$((${#LANES_SET[@]} * ${#THREADS_SET[@]} * ${#WAVECAP_SET[@]} * ${#BUCKETS_SET[@]}))
echo "Total configurations: $TOTAL_CONFIGS"
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
    # Default to 0 if empty
    if [[ -z "$val" ]]; then
        echo "0"
    else
        echo "$val"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper: Wait for node to be ready
# Uses /ready endpoint which returns 200 only when node is fully operational.
# Falls back to /health first to ensure the HTTP server is up, then checks /ready.
# ─────────────────────────────────────────────────────────────────────────────
wait_for_ready() {
    local url="$1"
    local max_wait="${2:-30}"
    local waited=0
    
    # First wait for HTTP server to be up via /health (always 200 when server is running)
    while [[ $waited -lt 10 ]]; do
        if curl -sf "${url}/health" >/dev/null 2>&1; then
            break
        fi
        sleep 1
        ((waited++))
    done
    
    if [[ $waited -ge 10 ]]; then
        echo "[t93_sweep] ERROR: Node HTTP server did not start within 10s" >&2
        return 1
    fi
    
    # Now wait for /ready to return 200 (node fully operational)
    while [[ $waited -lt $max_wait ]]; do
        if curl -sf "${url}/ready" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        ((waited++))
    done
    echo "[t93_sweep] ERROR: Node /ready did not return 200 within ${max_wait}s" >&2
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper: Cleanup background node process
# ─────────────────────────────────────────────────────────────────────────────
cleanup_node() {
    local pid="$1"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        # Wait briefly for graceful shutdown
        sleep 1
        # Force kill if still running
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
# Build the node binary (once, before sweep)
# ─────────────────────────────────────────────────────────────────────────────
echo "[t93_sweep] Building eezo-node (release)..."
cargo build -p eezo-node --bin eezo-node \
    --features "pq44-runtime,metrics,checkpoints,stm-exec,dag-consensus,cuda-hash" \
    --release --quiet 2>/dev/null || \
cargo build -p eezo-node --bin eezo-node \
    --features "pq44-runtime,metrics,checkpoints,stm-exec,dag-consensus,cuda-hash" \
    --release

# Build helper binaries if needed
echo "[t93_sweep] Building helper binaries..."
cargo build -p eezo-crypto --bin ml_dsa_keygen --release --quiet 2>/dev/null || \
    cargo build -p eezo-crypto --bin ml_dsa_keygen --release
cargo build -p eezo-node --bin eezo-txgen --release --quiet 2>/dev/null || \
    cargo build -p eezo-node --bin eezo-txgen --release

# spam_tps.sh hardcodes target/debug/eezo-txgen, so ensure it exists
if [[ ! -x "target/debug/eezo-txgen" ]]; then
    if [[ -x "target/release/eezo-txgen" ]]; then
        echo "[t93_sweep] creating symlink target/debug/eezo-txgen -> ../release/eezo-txgen"
        mkdir -p target/debug
        ln -sf ../release/eezo-txgen target/debug/eezo-txgen
    fi
fi

NODE_BIN="$REPO_ROOT/target/release/eezo-node"
if [[ ! -x "$NODE_BIN" ]]; then
    echo "[t93_sweep] error: eezo-node binary not found at $NODE_BIN" >&2
    exit 1
fi

echo "[t93_sweep] Build complete"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Summary collection
# ─────────────────────────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo "  Starting Sweep"
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo ""

CONFIG_NUM=0
RESULTS=()

for LANES in "${LANES_SET[@]}"; do
    for THREADS in "${THREADS_SET[@]}"; do
        for WAVECAP in "${WAVECAP_SET[@]}"; do
            for BUCKETS in "${BUCKETS_SET[@]}"; do
                ((CONFIG_NUM++))
                
                DATADIR="/tmp/eezo-t93-${LANES}-${THREADS}-${WAVECAP}-${BUCKETS}"
                
                echo "───────────────────────────────────────────────────────────────────────────────────"
                echo "[$CONFIG_NUM/$TOTAL_CONFIGS] lanes=$LANES threads=$THREADS wavecap=$WAVECAP buckets=$BUCKETS"
                echo "───────────────────────────────────────────────────────────────────────────────────"
                
                # Clean up datadir
                rm -rf "$DATADIR"
                
                # Start node with this config
                echo "  Starting node (datadir: $DATADIR)..."
                
                EEZO_CUDA_HASH_ENABLED=1 \
                EEZO_CONSENSUS_MODE=dag-primary \
                EEZO_EXEC_LANES="$LANES" \
                EEZO_EXECUTOR_THREADS="$THREADS" \
                RAYON_NUM_THREADS="$THREADS" \
                EEZO_EXEC_WAVE_CAP="$WAVECAP" \
                EEZO_EXEC_BUCKETS="$BUCKETS" \
                EEZO_EXEC_HYBRID=1 \
                EEZO_EXEC_WAVE_COMPACT=1 \
                EEZO_DATADIR="$DATADIR" \
                EEZO_LISTEN="127.0.0.1:8080" \
                EEZO_METRICS_BIND="127.0.0.1:9898" \
                "$NODE_BIN" --genesis genesis.min.json --datadir "$DATADIR" >"$DATADIR.log" 2>&1 &
                NODE_PID=$!
                
                # Wait for node to be ready
                echo "  Waiting for node to be ready..."
                if ! wait_for_ready "$NODE_URL" 30; then
                    echo "  ERROR: Node did not become ready within 30s" >&2
                    cleanup_node "$NODE_PID"
                    NODE_PID=""
                    RESULTS+=("lanes=$LANES threads=$THREADS wavecap=$WAVECAP buckets=$BUCKETS ERROR=timeout")
                    continue
                fi
                echo "  Node ready"
                
                # Small delay for metrics to initialize
                sleep 2
                
                # Capture baseline metrics
                echo "  Capturing baseline metrics..."
                STM_BEFORE=$(get_metric "eezo_exec_stm_time_seconds" "$METRICS_URL")
                HASH_BEFORE=$(get_metric "eezo_hash_cpu_time_seconds" "$METRICS_URL")
                TX_BEFORE=$(get_metric "eezo_txs_included_total" "$METRICS_URL")
                BLOCKS_BEFORE=$(get_metric "block_applied_total" "$METRICS_URL")
                
                echo "    stm=$STM_BEFORE hash=$HASH_BEFORE tx=$TX_BEFORE blocks=$BLOCKS_BEFORE"
                
                # Record wall-clock start
                WALL_START=$(date +%s)
                
                # Run fund + spam
                echo "  Running fund + spam ($TX_COUNT tx)..."
                if ! "$SCRIPT_DIR/t93_fund_and_spam.sh" "$TX_COUNT" "$NODE_URL"; then
                    echo "  ERROR: spam failed" >&2
                    cleanup_node "$NODE_PID"
                    NODE_PID=""
                    RESULTS+=("lanes=$LANES threads=$THREADS wavecap=$WAVECAP buckets=$BUCKETS ERROR=spam_failed")
                    continue
                fi
                
                # Wait for txs to be included
                echo "  Waiting for transactions to be included..."
                sleep 5
                
                # Record wall-clock end
                WALL_END=$(date +%s)
                WALL_ELAPSED=$((WALL_END - WALL_START))
                
                # Capture post metrics
                echo "  Capturing post metrics..."
                STM_AFTER=$(get_metric "eezo_exec_stm_time_seconds" "$METRICS_URL")
                HASH_AFTER=$(get_metric "eezo_hash_cpu_time_seconds" "$METRICS_URL")
                TX_AFTER=$(get_metric "eezo_txs_included_total" "$METRICS_URL")
                BLOCKS_AFTER=$(get_metric "block_applied_total" "$METRICS_URL")
                
                echo "    stm=$STM_AFTER hash=$HASH_AFTER tx=$TX_AFTER blocks=$BLOCKS_AFTER"
                
                # Compute deltas using bc for floating point
                DELTA_STM=$(echo "$STM_AFTER - $STM_BEFORE" | bc -l)
                DELTA_HASH=$(echo "$HASH_AFTER - $HASH_BEFORE" | bc -l)
                DELTA_TX=$(echo "$TX_AFTER - $TX_BEFORE" | bc)
                DELTA_BLOCKS=$(echo "$BLOCKS_AFTER - $BLOCKS_BEFORE" | bc)
                
                # Handle integer conversion for DELTA_TX and DELTA_BLOCKS
                # bc returns integers without decimal point, so we need to handle both cases
                # If the value contains a decimal point, strip it; otherwise use as-is
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
                # Default to 0 if empty or non-numeric
                if [[ -z "$DELTA_TX_INT" ]] || ! [[ "$DELTA_TX_INT" =~ ^-?[0-9]+$ ]]; then
                    DELTA_TX_INT=0
                fi
                if [[ -z "$DELTA_BLOCKS_INT" ]] || ! [[ "$DELTA_BLOCKS_INT" =~ ^-?[0-9]+$ ]]; then
                    DELTA_BLOCKS_INT=0
                fi
                
                # Compute per-tx metrics
                if [[ "$DELTA_TX_INT" -gt 0 ]]; then
                    STM_PER_TX=$(echo "scale=8; $DELTA_STM / $DELTA_TX_INT" | bc -l)
                    HASH_PER_TX=$(echo "scale=10; $DELTA_HASH / $DELTA_TX_INT" | bc -l)
                else
                    echo "[t93_sweep] WARNING: Δtx=0 for this config, skipping TPS calculation" >&2
                    STM_PER_TX="N/A"
                    HASH_PER_TX="N/A"
                fi
                
                # Compute txs per block
                if [[ "$DELTA_BLOCKS_INT" -gt 0 ]]; then
                    TX_PER_BLOCK=$(echo "scale=2; $DELTA_TX_INT / $DELTA_BLOCKS_INT" | bc -l)
                else
                    TX_PER_BLOCK="N/A"
                fi
                
                # Compute approximate TPS
                if [[ "$WALL_ELAPSED" -gt 0 ]] && [[ "$DELTA_TX_INT" -gt 0 ]]; then
                    TPS=$(echo "scale=2; $DELTA_TX_INT / $WALL_ELAPSED" | bc -l)
                else
                    TPS="N/A"
                fi
                
                # Format results
                # bc -l may return values like ".12345" without leading zero
                # printf handles this correctly, but we add a safeguard
                DELTA_STM_FMT=$(printf "%.4f" "$DELTA_STM" 2>/dev/null || echo "$DELTA_STM")
                DELTA_HASH_FMT=$(printf "%.6f" "$DELTA_HASH" 2>/dev/null || echo "$DELTA_HASH")
                
                if [[ "$STM_PER_TX" != "N/A" ]]; then
                    STM_PER_TX_FMT=$(printf "%.6f" "$STM_PER_TX" 2>/dev/null || echo "$STM_PER_TX")
                else
                    STM_PER_TX_FMT="N/A"
                fi
                
                if [[ "$HASH_PER_TX" != "N/A" ]]; then
                    HASH_PER_TX_FMT=$(printf "%.8f" "$HASH_PER_TX" 2>/dev/null || echo "$HASH_PER_TX")
                else
                    HASH_PER_TX_FMT="N/A"
                fi
                
                # Build summary line
                SUMMARY="lanes=$LANES threads=$THREADS wavecap=$WAVECAP buckets=$BUCKETS"
                SUMMARY="$SUMMARY tx=$DELTA_TX_INT blocks=$DELTA_BLOCKS_INT"
                SUMMARY="$SUMMARY stm_time=${DELTA_STM_FMT}s hash_time=${DELTA_HASH_FMT}s"
                SUMMARY="$SUMMARY stm_per_tx=${STM_PER_TX_FMT}s hash_per_tx=${HASH_PER_TX_FMT}s"
                SUMMARY="$SUMMARY tx_per_block=$TX_PER_BLOCK tps=$TPS"
                
                RESULTS+=("$SUMMARY")
                
                echo ""
                echo "  RESULT: $SUMMARY"
                echo ""
                
                # Shutdown node
                echo "  Shutting down node..."
                cleanup_node "$NODE_PID"
                NODE_PID=""
                
                # Brief pause between configs
                sleep 2
            done
        done
    done
done

# ─────────────────────────────────────────────────────────────────────────────
# Print Summary Table
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo "  T93.0 Sweep Summary"
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo ""

for result in "${RESULTS[@]}"; do
    echo "$result"
done

echo ""
echo "═══════════════════════════════════════════════════════════════════════════════════"
echo "  Sweep Complete: $CONFIG_NUM configurations tested"
echo "═══════════════════════════════════════════════════════════════════════════════════"