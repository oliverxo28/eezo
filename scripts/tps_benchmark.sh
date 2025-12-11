#!/usr/bin/env bash
# T82.0: DAG TPS Baseline & Profiling - Automated TPS Benchmark Script
#
# This script measures TPS on a running dag-primary devnet node using Prometheus metrics.
# It supports configurable measurement windows, warm-up periods, and detailed output.
#
# Usage:
#   ./scripts/tps_benchmark.sh [OPTIONS]
#
# Options:
#   -d, --duration     Measurement duration in seconds (default: 30)
#   -w, --warmup       Warm-up period in seconds before measurement (default: 5)
#   -m, --metrics-url  Prometheus metrics URL (default: http://127.0.0.1:9898/metrics)
#   -v, --verbose      Enable verbose output
#   -h, --help         Show this help message
#
# Prerequisites:
#   - A running eezo-node in dag-primary mode (use scripts/devnet_dag_primary.sh)
#   - curl and bc commands available
#   - Optional: rg (ripgrep) for faster metric parsing (falls back to grep)
#
# Example:
#   # Start the node in another terminal:
#   ./scripts/devnet_dag_primary.sh
#
#   # Run TPS benchmark with 60 second measurement and 10 second warm-up:
#   ./scripts/tps_benchmark.sh --duration 60 --warmup 10
#
# For TPS load generation, use spam_tps.sh in a separate terminal:
#   ./scripts/spam_tps.sh 5000

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Default Configuration
# ─────────────────────────────────────────────────────────────────────────────
DURATION=30
WARMUP=5
METRICS_URL="${EEZO_METRICS_URL:-http://127.0.0.1:9898/metrics}"
VERBOSE=0

# ─────────────────────────────────────────────────────────────────────────────
# Argument Parsing
# ─────────────────────────────────────────────────────────────────────────────
show_help() {
    cat << EOF
T82.0: DAG TPS Baseline & Profiling - Automated TPS Benchmark Script

Usage: $(basename "$0") [OPTIONS]

Options:
  -d, --duration <seconds>   Measurement duration (default: 30)
  -w, --warmup <seconds>     Warm-up period before measurement (default: 5)
  -m, --metrics-url <url>    Prometheus metrics URL (default: http://127.0.0.1:9898/metrics)
  -v, --verbose              Enable verbose output
  -h, --help                 Show this help message

Environment Variables:
  EEZO_METRICS_URL           Override default metrics URL

Example:
  $(basename "$0") --duration 60 --warmup 10

EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -w|--warmup)
            WARMUP="$2"
            shift 2
            ;;
        -m|--metrics-url)
            METRICS_URL="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Error: Unknown option: $1" >&2
            echo "" >&2
            show_help >&2
            exit 1
            ;;
    esac
done

# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

log_verbose() {
    if [[ $VERBOSE -eq 1 ]]; then
        echo "[debug] $*"
    fi
}

# Use rg (ripgrep) if available, otherwise fall back to grep
grep_cmd() {
    if command -v rg >/dev/null 2>&1; then
        rg "$@" || true
    else
        grep "$@" || true
    fi
}

# Fetch a metric value from /metrics endpoint
# Usage: get_metric "metric_name"
# Returns: the value (number) or "0" if not found
get_metric() {
    local metric_name="$1"
    local raw
    raw="$(curl -sf "$METRICS_URL" 2>/dev/null | grep_cmd "^${metric_name} " | awk '{print $2}')"
    
    # Handle empty/missing
    if [[ -z "$raw" ]]; then
        echo "0"
    else
        echo "$raw"
    fi
}

# Fetch multiple metrics at once (single HTTP request)
# Usage: fetch_all_metrics
# Sets global variables: TXS_INCLUDED, BLOCK_APPLIED, STM_WAVES, STM_CONFLICTS, STM_RETRIES
fetch_all_metrics() {
    local metrics_output
    metrics_output="$(curl -sf "$METRICS_URL" 2>/dev/null)" || {
        echo "[error] Failed to fetch metrics from $METRICS_URL"
        exit 1
    }
    
    TXS_INCLUDED="$(echo "$metrics_output" | grep_cmd '^eezo_txs_included_total ' | awk '{print $2}')"
    BLOCK_APPLIED="$(echo "$metrics_output" | grep_cmd '^block_applied_total ' | awk '{print $2}')"
    STM_WAVES="$(echo "$metrics_output" | grep_cmd '^eezo_exec_stm_waves_total ' | awk '{print $2}')"
    STM_CONFLICTS="$(echo "$metrics_output" | grep_cmd '^eezo_exec_stm_conflicts_total ' | awk '{print $2}')"
    STM_RETRIES="$(echo "$metrics_output" | grep_cmd '^eezo_exec_stm_retries_total ' | awk '{print $2}')"
    STM_ABORTED="$(echo "$metrics_output" | grep_cmd '^eezo_exec_stm_aborted_total ' | awk '{print $2}')"
    
    # Default to 0 if missing
    TXS_INCLUDED="${TXS_INCLUDED:-0}"
    BLOCK_APPLIED="${BLOCK_APPLIED:-0}"
    STM_WAVES="${STM_WAVES:-0}"
    STM_CONFLICTS="${STM_CONFLICTS:-0}"
    STM_RETRIES="${STM_RETRIES:-0}"
    STM_ABORTED="${STM_ABORTED:-0}"
}

# ─────────────────────────────────────────────────────────────────────────────
# Main Script
# ─────────────────────────────────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════════════"
echo "  T82.0: DAG TPS Baseline & Profiling Benchmark"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""
echo "Configuration:"
echo "  Metrics URL:         $METRICS_URL"
echo "  Warm-up period:      ${WARMUP}s"
echo "  Measurement window:  ${DURATION}s"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Verify Node Connectivity
# ─────────────────────────────────────────────────────────────────────────────

echo "[1/4] Verifying node connectivity..."
if ! curl -sf "$METRICS_URL" >/dev/null 2>&1; then
    echo "[error] Cannot reach metrics endpoint at $METRICS_URL"
    echo ""
    echo "Make sure the node is running with metrics enabled:"
    echo "  ./scripts/devnet_dag_primary.sh"
    exit 1
fi
echo "      ✓ Node is responding at $METRICS_URL"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Warm-up Period
# ─────────────────────────────────────────────────────────────────────────────

if [[ $WARMUP -gt 0 ]]; then
    echo "[2/4] Warming up for ${WARMUP}s (waiting for stable block production)..."
    sleep "$WARMUP"
    echo "      ✓ Warm-up complete"
    echo ""
else
    echo "[2/4] Skipping warm-up (--warmup 0)"
    echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# Start Measurement
# ─────────────────────────────────────────────────────────────────────────────

echo "[3/4] Starting measurement..."

# Capture start values
fetch_all_metrics
START_TXS="$TXS_INCLUDED"
START_BLOCKS="$BLOCK_APPLIED"
START_WAVES="$STM_WAVES"
START_CONFLICTS="$STM_CONFLICTS"
START_RETRIES="$STM_RETRIES"
START_ABORTED="$STM_ABORTED"
START_TS="$(date +%s)"

log_verbose "Start metrics: txs=$START_TXS blocks=$START_BLOCKS waves=$START_WAVES"

echo "      Measurement started at $(date +%H:%M:%S)"
echo "      Measuring for ${DURATION}s..."

sleep "$DURATION"

# Capture end values
fetch_all_metrics
END_TXS="$TXS_INCLUDED"
END_BLOCKS="$BLOCK_APPLIED"
END_WAVES="$STM_WAVES"
END_CONFLICTS="$STM_CONFLICTS"
END_RETRIES="$STM_RETRIES"
END_ABORTED="$STM_ABORTED"
END_TS="$(date +%s)"

log_verbose "End metrics: txs=$END_TXS blocks=$END_BLOCKS waves=$END_WAVES"

echo "      Measurement ended at $(date +%H:%M:%S)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Compute Results
# ─────────────────────────────────────────────────────────────────────────────

echo "[4/4] Computing results..."
echo ""

# Calculate deltas
DELTA_TXS=$((END_TXS - START_TXS))
DELTA_BLOCKS=$((END_BLOCKS - START_BLOCKS))
DELTA_WAVES=$((END_WAVES - START_WAVES))
DELTA_CONFLICTS=$((END_CONFLICTS - START_CONFLICTS))
DELTA_RETRIES=$((END_RETRIES - START_RETRIES))
DELTA_ABORTED=$((END_ABORTED - START_ABORTED))
DELTA_TIME=$((END_TS - START_TS))

# Calculate TPS using bc for floating-point
if [[ $DELTA_TIME -gt 0 ]]; then
    TPS="$(echo "scale=2; $DELTA_TXS / $DELTA_TIME" | bc -l)"
    BPS="$(echo "scale=2; $DELTA_BLOCKS / $DELTA_TIME" | bc -l)"
else
    TPS="0.00"
    BPS="0.00"
fi

# Calculate per-block averages
if [[ $DELTA_BLOCKS -gt 0 ]]; then
    AVG_TXS_PER_BLOCK="$(echo "scale=2; $DELTA_TXS / $DELTA_BLOCKS" | bc -l)"
    AVG_WAVES_PER_BLOCK="$(echo "scale=2; $DELTA_WAVES / $DELTA_BLOCKS" | bc -l)"
    AVG_CONFLICTS_PER_BLOCK="$(echo "scale=2; $DELTA_CONFLICTS / $DELTA_BLOCKS" | bc -l)"
else
    AVG_TXS_PER_BLOCK="0.00"
    AVG_WAVES_PER_BLOCK="0.00"
    AVG_CONFLICTS_PER_BLOCK="0.00"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Display Results
# ─────────────────────────────────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════════════"
echo "  TPS Benchmark Results"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""
echo "  Measurement Period:"
echo "    Duration:                 ${DELTA_TIME}s"
echo "    Start eezo_txs_included:  $START_TXS"
echo "    End eezo_txs_included:    $END_TXS"
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────────────┐"
echo "  │  TPS (Transactions Per Second):   $TPS                                  "
echo "  └─────────────────────────────────────────────────────────────────────────┘"
echo ""
echo "  Block Production:"
echo "    Blocks produced:          $DELTA_BLOCKS"
echo "    Blocks per second:        $BPS"
echo "    Avg txs per block:        $AVG_TXS_PER_BLOCK"
echo ""
echo "  STM Executor Metrics (T82.0):"
echo "    Total waves:              $DELTA_WAVES"
echo "    Avg waves per block:      $AVG_WAVES_PER_BLOCK"
echo "    Total conflicts:          $DELTA_CONFLICTS"
echo "    Avg conflicts per block:  $AVG_CONFLICTS_PER_BLOCK"
echo "    Total retries:            $DELTA_RETRIES"
echo "    Total aborted:            $DELTA_ABORTED"
echo ""
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# JSON Output (for scripting/automation)
# ─────────────────────────────────────────────────────────────────────────────

if [[ $VERBOSE -eq 1 ]]; then
    echo "[JSON Output]"
    cat << EOF
{
  "tps": $TPS,
  "blocks_per_second": $BPS,
  "duration_seconds": $DELTA_TIME,
  "delta_txs": $DELTA_TXS,
  "delta_blocks": $DELTA_BLOCKS,
  "avg_txs_per_block": $AVG_TXS_PER_BLOCK,
  "stm_waves": $DELTA_WAVES,
  "stm_conflicts": $DELTA_CONFLICTS,
  "stm_retries": $DELTA_RETRIES,
  "stm_aborted": $DELTA_ABORTED
}
EOF
    echo ""
fi

echo "Benchmark complete."
