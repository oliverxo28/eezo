#!/usr/bin/env bash
set -euo pipefail

# T76.12: DAG-Hybrid Canary SLO Checker
# 
# Usage: scripts/t76_dag_canary_check.sh [METRICS_URL] [--tps]
#
# Summarizes SLO-relevant metrics from Prometheus and prints a human-readable
# summary indicating whether SLOs are passing or failing.
#
# Options:
#   METRICS_URL  Prometheus metrics endpoint (default: http://127.0.0.1:9898/metrics)
#   --tps        Also measure TPS over a 10-second window
#
# Example:
#   scripts/t76_dag_canary_check.sh
#   scripts/t76_dag_canary_check.sh http://127.0.0.1:9898/metrics
#   scripts/t76_dag_canary_check.sh http://127.0.0.1:9898/metrics --tps
#
# SLOs checked:
#   1. Zero hybrid fallbacks (eezo_dag_hybrid_fallback_total)
#   2. Ordering in sync (eezo_dag_shadow_hash_mismatch_total, eezo_dag_shadow_in_sync)
#   3. Healthy queue (eezo_dag_ordered_ready < 10)
#   4. Apply quality ≥99.9% (apply_ok / (apply_ok + apply_fail))
#   5. Consensus mode = hybrid (eezo_consensus_mode_active == 1)
#
# Exit codes:
#   0 - All SLOs passing
#   1 - One or more SLOs failing
#   2 - Metrics endpoint unreachable

# Default values
METRICS_URL="http://127.0.0.1:9898/metrics"
MEASURE_TPS=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tps)
      MEASURE_TPS=true
      shift
      ;;
    -*)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
    *)
      # First non-flag argument is the metrics URL
      METRICS_URL="$1"
      shift
      ;;
  esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track SLO failures
SLO_FAILURES=0

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}       T76.12 DAG-Hybrid Canary SLO Check                       ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Metrics endpoint: ${YELLOW}$METRICS_URL${NC}"
echo ""

# Fetch metrics
METRICS=$(curl -sf "$METRICS_URL" 2>/dev/null) || {
  echo -e "${RED}ERROR: Failed to fetch metrics from $METRICS_URL${NC}"
  echo "Make sure eezo-node is running and metrics are enabled."
  exit 2
}

# Helper function to extract metric value (returns integer portion for counters)
get_metric() {
  local name="$1"
  local default="${2:-0}"
  local value
  value=$(echo "$METRICS" | grep "^${name} " | awk '{print $2}' | head -1)
  # Prometheus counters are integers, but may have .0 suffix - strip it
  value="${value%.0}"
  echo "${value:-$default}"
}

# Helper function to extract labeled metric value
get_labeled_metric() {
  local pattern="$1"
  local default="${2:-0}"
  local value
  value=$(echo "$METRICS" | grep "$pattern" | awk '{print $2}' | head -1)
  value="${value%.0}"
  echo "${value:-$default}"
}

# Helper to print status
print_status() {
  local label="$1"
  local value="$2"
  local ok="$3"
  local note="${4:-}"
  
  if [[ "$ok" == "true" ]]; then
    echo -e "  ${GREEN}✓${NC} $label: $value $note"
  else
    echo -e "  ${RED}✗${NC} $label: $value $note"
    ((SLO_FAILURES++))
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SLO 1: Consensus Mode
# Historical note (T81.4): 0=legacy (pre-T81), 1=hybrid, 2=dag, 3=dag-primary
# This script is for historical T76 hybrid canary; use t78_dag_primary_canary_check.sh for current DAG
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[Consensus Mode]${NC}"
CONSENSUS_MODE=$(get_metric "eezo_consensus_mode_active" "")
case "$CONSENSUS_MODE" in
  0) MODE_NAME="legacy"; MODE_OK=false ;;
  1) MODE_NAME="hybrid"; MODE_OK=true ;;
  2) MODE_NAME="dag"; MODE_OK=true ;;
  *) MODE_NAME="unknown"; MODE_OK=false ;;
esac

if [[ -z "$CONSENSUS_MODE" ]]; then
  print_status "eezo_consensus_mode_active" "(not found)" false "(metric not exported)"
else
  print_status "eezo_consensus_mode_active" "$CONSENSUS_MODE ($MODE_NAME)" "$MODE_OK" "(expected: 1=hybrid)"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SLO 2: Zero Hybrid Fallbacks
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[Fallbacks]${NC}"
FALLBACK_TOTAL=$(get_metric "eezo_dag_hybrid_fallback_total" "0")
FALLBACK_OK=$([[ "$FALLBACK_TOTAL" == "0" ]] && echo "true" || echo "false")
print_status "eezo_dag_hybrid_fallback_total" "$FALLBACK_TOTAL" "$FALLBACK_OK" "(expected: 0)"

# T76.12: Show labeled fallback reasons
FALLBACK_MIN_DAG=$(get_labeled_metric 'eezo_dag_hybrid_fallback_reason_total{reason="min_dag_not_met"}' "0")
FALLBACK_TIMEOUT=$(get_labeled_metric 'eezo_dag_hybrid_fallback_reason_total{reason="timeout"}' "0")
FALLBACK_EMPTY=$(get_labeled_metric 'eezo_dag_hybrid_fallback_reason_total{reason="empty"}' "0")
FALLBACK_NO_HANDLE=$(get_labeled_metric 'eezo_dag_hybrid_fallback_reason_total{reason="no_handle"}' "0")
FALLBACK_QUEUE_EMPTY=$(get_labeled_metric 'eezo_dag_hybrid_fallback_reason_total{reason="queue_empty"}' "0")

if [[ "${FALLBACK_TOTAL%.*}" -gt 0 ]]; then
  echo -e "  ${YELLOW}Fallback breakdown:${NC}"
  echo -e "    - min_dag_not_met: $FALLBACK_MIN_DAG"
  echo -e "    - timeout: $FALLBACK_TIMEOUT"
  echo -e "    - empty: $FALLBACK_EMPTY"
  echo -e "    - no_handle: $FALLBACK_NO_HANDLE"
  echo -e "    - queue_empty: $FALLBACK_QUEUE_EMPTY"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SLO 3: Ordering in Sync (Shadow DAG)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[Shadow DAG Sync]${NC}"
HASH_MISMATCH=$(get_metric "eezo_dag_shadow_hash_mismatch_total" "0")
MISMATCH_OK=$([[ "$HASH_MISMATCH" == "0" ]] && echo "true" || echo "false")
print_status "eezo_dag_shadow_hash_mismatch_total" "$HASH_MISMATCH" "$MISMATCH_OK" "(expected: 0)"

SHADOW_IN_SYNC=$(get_metric "eezo_dag_shadow_in_sync" "")
if [[ -z "$SHADOW_IN_SYNC" ]]; then
  echo -e "  ${YELLOW}○${NC} eezo_dag_shadow_in_sync: (not found)"
else
  SYNC_OK=$([[ "$SHADOW_IN_SYNC" == "1" ]] && echo "true" || echo "false")
  print_status "eezo_dag_shadow_in_sync" "$SHADOW_IN_SYNC" "$SYNC_OK" "(expected: 1)"
fi

SHADOW_LAG=$(get_metric "eezo_dag_shadow_lag_blocks" "")
if [[ -n "$SHADOW_LAG" ]]; then
  LAG_OK=$([[ $(echo "$SHADOW_LAG < 5" | bc -l 2>/dev/null || echo "0") == "1" ]] && echo "true" || echo "false")
  print_status "eezo_dag_shadow_lag_blocks" "$SHADOW_LAG" "$LAG_OK" "(expected: <5)"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SLO 4: Healthy Queue
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[Queue Health]${NC}"
ORDERED_READY=$(get_metric "eezo_dag_ordered_ready" "0")
QUEUE_OK=$([[ $(echo "$ORDERED_READY < 10" | bc -l 2>/dev/null || echo "0") == "1" ]] && echo "true" || echo "false")
print_status "eezo_dag_ordered_ready" "$ORDERED_READY" "$QUEUE_OK" "(expected: <10)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SLO 5: Apply Quality
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[Apply Quality]${NC}"
APPLY_OK=$(get_metric "eezo_dag_hybrid_apply_ok_total" "0")
APPLY_FAIL=$(get_metric "eezo_dag_hybrid_apply_fail_total" "0")

echo -e "  eezo_dag_hybrid_apply_ok_total: $APPLY_OK"
echo -e "  eezo_dag_hybrid_apply_fail_total: $APPLY_FAIL"

# Calculate apply ratio (metrics are already sanitized by get_metric)
TOTAL=$((APPLY_OK + APPLY_FAIL))
if [[ "$TOTAL" -gt 0 ]]; then
  RATIO=$(echo "scale=6; $APPLY_OK / $TOTAL" | bc -l)
  RATIO_PCT=$(echo "scale=2; $RATIO * 100" | bc -l)
  QUALITY_OK=$([[ $(echo "$RATIO >= 0.999" | bc -l) == "1" ]] && echo "true" || echo "false")
  print_status "Apply success ratio" "${RATIO_PCT}%" "$QUALITY_OK" "(expected: ≥99.9%)"
else
  echo -e "  ${YELLOW}○${NC} Apply success ratio: N/A (no transactions yet)"
fi

# Show per-reason failures if any
BAD_NONCE=$(get_metric "eezo_dag_hybrid_apply_fail_bad_nonce_total" "0")
INSUFF_FUNDS=$(get_metric "eezo_dag_hybrid_apply_fail_insufficient_funds_total" "0")
INVALID_SENDER=$(get_metric "eezo_dag_hybrid_apply_fail_invalid_sender_total" "0")
OTHER_FAIL=$(get_metric "eezo_dag_hybrid_apply_fail_other_total" "0")

if [[ "${APPLY_FAIL%.*}" -gt 0 ]]; then
  echo -e "  ${YELLOW}Failure breakdown:${NC}"
  echo -e "    - bad_nonce: $BAD_NONCE"
  echo -e "    - insufficient_funds: $INSUFF_FUNDS"
  echo -e "    - invalid_sender: $INVALID_SENDER"
  echo -e "    - other: $OTHER_FAIL"
fi

# Show dedup stats
SEEN_BEFORE=$(get_metric "eezo_dag_hybrid_seen_before_total" "0")
CANDIDATES=$(get_metric "eezo_dag_hybrid_candidate_total" "0")
NONCE_PREFILTER=$(get_metric "eezo_dag_hybrid_bad_nonce_prefilter_total" "0")

echo -e "  ${YELLOW}Dedup/filter stats:${NC}"
echo -e "    - seen_before (deduped): $SEEN_BEFORE"
echo -e "    - candidates (after dedup): $CANDIDATES"
echo -e "    - bad_nonce_prefilter: $NONCE_PREFILTER"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SLO 6: Performance (TXS Included)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[Performance]${NC}"
TXS_INCLUDED=$(get_metric "eezo_txs_included_total" "0")
BLOCK_HEIGHT=$(get_metric "eezo_block_height" "0")
MEMPOOL_LEN=$(get_metric "eezo_mempool_len" "0")

echo -e "  eezo_txs_included_total: $TXS_INCLUDED"
echo -e "  eezo_block_height: $BLOCK_HEIGHT"
echo -e "  eezo_mempool_len: $MEMPOOL_LEN"

# DAG batch usage
BATCHES_USED=$(get_metric "eezo_dag_hybrid_batches_used_total" "0")
echo -e "  eezo_dag_hybrid_batches_used_total: $BATCHES_USED"

# Executor stats
EXEC_LANES=$(get_metric "eezo_exec_lanes" "")
EXEC_WAVE_CAP=$(get_metric "eezo_exec_wave_cap" "")
if [[ -n "$EXEC_LANES" ]]; then
  echo -e "  eezo_exec_lanes: $EXEC_LANES"
fi
if [[ -n "$EXEC_WAVE_CAP" ]]; then
  echo -e "  eezo_exec_wave_cap: $EXEC_WAVE_CAP"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Optional TPS Measurement
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$MEASURE_TPS" == "true" ]]; then
  echo -e "${BLUE}[TPS Measurement (10s window)]${NC}"
  echo -e "  Measuring..."
  
  T1=$(get_metric "eezo_txs_included_total" "0")
  TS1=$(date +%s)
  
  sleep 10
  
  # Re-fetch metrics
  METRICS=$(curl -sf "$METRICS_URL" 2>/dev/null) || {
    echo -e "  ${RED}ERROR: Failed to re-fetch metrics${NC}"
  }
  
  T2=$(get_metric "eezo_txs_included_total" "0")
  TS2=$(date +%s)
  
  TX_DELTA=$((T2 - T1))
  TIME_DELTA=$((TS2 - TS1))
  
  if [[ "$TIME_DELTA" -gt 0 ]]; then
    TPS=$(echo "scale=2; $TX_DELTA / $TIME_DELTA" | bc -l)
    TPS_OK=$([[ $(echo "$TPS >= 100" | bc -l) == "1" ]] && echo "true" || echo "false")
    print_status "Measured TPS" "$TPS tx/s" "$TPS_OK" "(${TX_DELTA} tx over ${TIME_DELTA}s)"
  fi
  echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# Aggregation Stats
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[Aggregation]${NC}"
AGG_TIME_BUDGET=$(get_metric "eezo_hybrid_agg_time_budget_ms" "")
AGG_ADAPTIVE=$(get_metric "eezo_hybrid_agg_adaptive_enabled" "")

if [[ -n "$AGG_TIME_BUDGET" ]]; then
  echo -e "  eezo_hybrid_agg_time_budget_ms: ${AGG_TIME_BUDGET}ms"
fi
if [[ -n "$AGG_ADAPTIVE" ]]; then
  ADAPTIVE_STR=$([[ "$AGG_ADAPTIVE" == "1" ]] && echo "enabled" || echo "disabled")
  echo -e "  eezo_hybrid_agg_adaptive_enabled: $AGG_ADAPTIVE ($ADAPTIVE_STR)"
fi

# Check cap reasons if available (using helper function)
CAP_TIME=$(get_labeled_metric 'eezo_hybrid_agg_cap_reason_total{reason="time"}' "0")
CAP_BYTES=$(get_labeled_metric 'eezo_hybrid_agg_cap_reason_total{reason="bytes"}' "0")
CAP_TX=$(get_labeled_metric 'eezo_hybrid_agg_cap_reason_total{reason="tx"}' "0")
CAP_EMPTY=$(get_labeled_metric 'eezo_hybrid_agg_cap_reason_total{reason="empty"}' "0")

if [[ "$CAP_TIME" != "0" || "$CAP_BYTES" != "0" || "$CAP_TX" != "0" || "$CAP_EMPTY" != "0" ]]; then
  echo -e "  ${YELLOW}Cap reasons:${NC}"
  echo -e "    - time: ${CAP_TIME}"
  echo -e "    - bytes: ${CAP_BYTES}"
  echo -e "    - tx: ${CAP_TX}"
  echo -e "    - empty: ${CAP_EMPTY}"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
if [[ "$SLO_FAILURES" -eq 0 ]]; then
  echo -e "${GREEN}✓ All SLOs PASSING${NC}"
  echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
  echo ""
  exit 0
else
  echo -e "${RED}✗ $SLO_FAILURES SLO(s) FAILING${NC}"
  echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
  echo ""
  echo "Review the failed SLOs above and take corrective action."
  echo "See book/src/t76_dag_hybrid_canary.md for failure handling guidance."
  echo ""
  exit 1
fi