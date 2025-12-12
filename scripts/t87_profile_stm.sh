#!/usr/bin/env bash
# T87.3: STM Profiling Helper Script
#
# This script captures STM executor metrics over a specified duration,
# making it easy to profile performance under load.
#
# Usage:
#   ./scripts/t87_profile_stm.sh [duration_secs]
#
# Prerequisites:
#   - Node running with metrics enabled
#   - Load generator running (e.g., spam_tps.sh or spam_multi_senders.sh)
#
# Example:
#   # Terminal 1: Start node
#   source devnet_tps.env && ./scripts/devnet_dag_primary.sh
#
#   # Terminal 2: Generate load
#   ./scripts/spam_tps.sh 5000
#
#   # Terminal 3: Profile STM
#   ./scripts/t87_profile_stm.sh 30

set -euo pipefail

DURATION=${1:-30}
METRICS_URL="${EEZO_METRICS_BIND:-127.0.0.1:9898}"

echo "═══════════════════════════════════════════════════════════════"
echo "  T87.3: STM Profiling Helper"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Configuration:"
echo "  Duration: ${DURATION}s"
echo "  Metrics URL: http://${METRICS_URL}/metrics"
echo ""

# Function to fetch and parse a specific metric
fetch_metric() {
    local name="$1"
    local metrics="$2"
    echo "$metrics" | grep "^${name}" | head -1 | awk '{print $2}'
}

# Function to fetch histogram sum/count from cached metrics
fetch_histogram() {
    local name="$1"
    local metrics="$2"
    local sum count
    sum=$(echo "$metrics" | grep "^${name}_sum" | head -1 | awk '{print $2}')
    count=$(echo "$metrics" | grep "^${name}_count" | head -1 | awk '{print $2}')
    echo "${sum:-0} ${count:-0}"
}

echo "Capturing BEFORE snapshot..."
echo ""

# Fetch all metrics once for BEFORE snapshot
BEFORE_METRICS=$(curl -s "http://${METRICS_URL}/metrics" 2>/dev/null)

# Before snapshot
BEFORE_WAVES=$(fetch_metric "eezo_exec_stm_waves_total" "$BEFORE_METRICS")
BEFORE_CONFLICTS=$(fetch_metric "eezo_exec_stm_conflicts_total" "$BEFORE_METRICS")
BEFORE_RETRIES=$(fetch_metric "eezo_exec_stm_retries_total" "$BEFORE_METRICS")
BEFORE_ABORTED=$(fetch_metric "eezo_exec_stm_aborted_total" "$BEFORE_METRICS")
BEFORE_WAVES_BUILT=$(fetch_metric "eezo_exec_stm_waves_built_total" "$BEFORE_METRICS")
BEFORE_PRESCREEN_HITS=$(fetch_metric "eezo_exec_stm_conflict_prescreen_hits_total" "$BEFORE_METRICS")
BEFORE_PRESCREEN_MISSES=$(fetch_metric "eezo_exec_stm_conflict_prescreen_misses_total" "$BEFORE_METRICS")
BEFORE_TXS=$(fetch_metric "eezo_txs_included_total" "$BEFORE_METRICS")
BEFORE_BLOCKS=$(fetch_metric "block_applied_total" "$BEFORE_METRICS")
read -r BEFORE_WAVE_SIZE_SUM BEFORE_WAVE_SIZE_COUNT <<< "$(fetch_histogram eezo_exec_stm_wave_size "$BEFORE_METRICS")"
read -r BEFORE_WAVE_BUILD_SUM BEFORE_WAVE_BUILD_COUNT <<< "$(fetch_histogram eezo_exec_stm_wave_build_seconds "$BEFORE_METRICS")"

echo "Waiting ${DURATION}s..."
sleep "$DURATION"

echo ""
echo "Capturing AFTER snapshot..."
echo ""

# Fetch all metrics once for AFTER snapshot
AFTER_METRICS=$(curl -s "http://${METRICS_URL}/metrics" 2>/dev/null)

# After snapshot
AFTER_WAVES=$(fetch_metric "eezo_exec_stm_waves_total" "$AFTER_METRICS")
AFTER_CONFLICTS=$(fetch_metric "eezo_exec_stm_conflicts_total" "$AFTER_METRICS")
AFTER_RETRIES=$(fetch_metric "eezo_exec_stm_retries_total" "$AFTER_METRICS")
AFTER_ABORTED=$(fetch_metric "eezo_exec_stm_aborted_total" "$AFTER_METRICS")
AFTER_WAVES_BUILT=$(fetch_metric "eezo_exec_stm_waves_built_total" "$AFTER_METRICS")
AFTER_PRESCREEN_HITS=$(fetch_metric "eezo_exec_stm_conflict_prescreen_hits_total" "$AFTER_METRICS")
AFTER_PRESCREEN_MISSES=$(fetch_metric "eezo_exec_stm_conflict_prescreen_misses_total" "$AFTER_METRICS")
AFTER_TXS=$(fetch_metric "eezo_txs_included_total" "$AFTER_METRICS")
AFTER_BLOCKS=$(fetch_metric "block_applied_total" "$AFTER_METRICS")
read -r AFTER_WAVE_SIZE_SUM AFTER_WAVE_SIZE_COUNT <<< "$(fetch_histogram eezo_exec_stm_wave_size "$AFTER_METRICS")"
read -r AFTER_WAVE_BUILD_SUM AFTER_WAVE_BUILD_COUNT <<< "$(fetch_histogram eezo_exec_stm_wave_build_seconds "$AFTER_METRICS")"

# Calculate deltas using bash arithmetic for integers
DELTA_WAVES=$((${AFTER_WAVES:-0} - ${BEFORE_WAVES:-0}))
DELTA_CONFLICTS=$((${AFTER_CONFLICTS:-0} - ${BEFORE_CONFLICTS:-0}))
DELTA_RETRIES=$((${AFTER_RETRIES:-0} - ${BEFORE_RETRIES:-0}))
DELTA_ABORTED=$((${AFTER_ABORTED:-0} - ${BEFORE_ABORTED:-0}))
DELTA_WAVES_BUILT=$((${AFTER_WAVES_BUILT:-0} - ${BEFORE_WAVES_BUILT:-0}))
DELTA_PRESCREEN_HITS=$((${AFTER_PRESCREEN_HITS:-0} - ${BEFORE_PRESCREEN_HITS:-0}))
DELTA_PRESCREEN_MISSES=$((${AFTER_PRESCREEN_MISSES:-0} - ${BEFORE_PRESCREEN_MISSES:-0}))
DELTA_TXS=$((${AFTER_TXS:-0} - ${BEFORE_TXS:-0}))
DELTA_BLOCKS=$((${AFTER_BLOCKS:-0} - ${BEFORE_BLOCKS:-0}))
DELTA_WAVE_SIZE_COUNT=$((${AFTER_WAVE_SIZE_COUNT:-0} - ${BEFORE_WAVE_SIZE_COUNT:-0}))
DELTA_WAVE_BUILD_COUNT=$((${AFTER_WAVE_BUILD_COUNT:-0} - ${BEFORE_WAVE_BUILD_COUNT:-0}))

# Use awk for floating-point calculations
DELTA_WAVE_SIZE_SUM=$(awk "BEGIN {printf \"%.6f\", ${AFTER_WAVE_SIZE_SUM:-0} - ${BEFORE_WAVE_SIZE_SUM:-0}}")
DELTA_WAVE_BUILD_SUM=$(awk "BEGIN {printf \"%.6f\", ${AFTER_WAVE_BUILD_SUM:-0} - ${BEFORE_WAVE_BUILD_SUM:-0}}")

# Calculate derived metrics using awk for floating-point
TPS=$(awk "BEGIN {printf \"%.2f\", ${DELTA_TXS} / ${DURATION}}")
BLOCKS_PER_SEC=$(awk "BEGIN {printf \"%.2f\", ${DELTA_BLOCKS} / ${DURATION}}")

if [ "${DELTA_BLOCKS:-0}" -gt 0 ]; then
    AVG_TXS_PER_BLOCK=$(awk "BEGIN {printf \"%.2f\", ${DELTA_TXS} / ${DELTA_BLOCKS}}")
    AVG_WAVES_PER_BLOCK=$(awk "BEGIN {printf \"%.2f\", ${DELTA_WAVES} / ${DELTA_BLOCKS}}")
else
    AVG_TXS_PER_BLOCK="N/A"
    AVG_WAVES_PER_BLOCK="N/A"
fi

if [ "${DELTA_WAVE_SIZE_COUNT:-0}" -gt 0 ]; then
    AVG_WAVE_SIZE=$(awk "BEGIN {printf \"%.2f\", ${DELTA_WAVE_SIZE_SUM} / ${DELTA_WAVE_SIZE_COUNT}}")
else
    AVG_WAVE_SIZE="N/A"
fi

if [ "${DELTA_WAVE_BUILD_COUNT:-0}" -gt 0 ]; then
    AVG_WAVE_BUILD_MS=$(awk "BEGIN {printf \"%.4f\", ${DELTA_WAVE_BUILD_SUM} / ${DELTA_WAVE_BUILD_COUNT} * 1000}")
else
    AVG_WAVE_BUILD_MS="N/A"
fi

PRESCREEN_TOTAL=$((${DELTA_PRESCREEN_HITS:-0} + ${DELTA_PRESCREEN_MISSES:-0}))
if [ "${PRESCREEN_TOTAL}" -gt 0 ]; then
    PRESCREEN_HIT_RATE=$(awk "BEGIN {printf \"%.2f\", ${DELTA_PRESCREEN_HITS} * 100 / ${PRESCREEN_TOTAL}}")
else
    PRESCREEN_HIT_RATE="N/A"
fi

# Print results
echo "═══════════════════════════════════════════════════════════════"
echo "  T87.3 Profile Results (${DURATION}s)"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "┌─────────────────────────────────────────────────────────────┐"
printf "│  TPS (Transactions Per Second):   %-25s │\n" "${TPS}"
echo "└─────────────────────────────────────────────────────────────┘"
echo ""
echo "Transaction Throughput:"
printf "  Transactions included:    %s\n" "${DELTA_TXS}"
printf "  Blocks applied:           %s\n" "${DELTA_BLOCKS}"
printf "  Blocks per second:        %s\n" "${BLOCKS_PER_SEC}"
printf "  Avg txs per block:        %s\n" "${AVG_TXS_PER_BLOCK}"
echo ""
echo "STM Executor Metrics:"
printf "  Total waves:              %s\n" "${DELTA_WAVES}"
printf "  Waves built:              %s\n" "${DELTA_WAVES_BUILT}"
printf "  Avg waves per block:      %s\n" "${AVG_WAVES_PER_BLOCK}"
printf "  Avg wave size:            %s\n" "${AVG_WAVE_SIZE}"
printf "  Avg wave build time (ms): %s\n" "${AVG_WAVE_BUILD_MS}"
echo ""
echo "Conflict Detection:"
printf "  Total conflicts:          %s\n" "${DELTA_CONFLICTS}"
printf "  Total retries:            %s\n" "${DELTA_RETRIES}"
printf "  Total aborted:            %s\n" "${DELTA_ABORTED}"
echo ""
echo "Pre-Screen Effectiveness:"
printf "  Prescreen hits:           %s\n" "${DELTA_PRESCREEN_HITS}"
printf "  Prescreen misses:         %s\n" "${DELTA_PRESCREEN_MISSES}"
printf "  Prescreen hit rate:       %s%%\n" "${PRESCREEN_HIT_RATE}"
echo ""
echo "═══════════════════════════════════════════════════════════════"
