#!/usr/bin/env bash
set -euo pipefail

# T78.6: DAG-Primary Canary SLO Checker
# 
# Usage: scripts/t78_dag_primary_canary_check.sh [METRICS_URL] [--tps-window=N]
#
# Summarizes SLO-relevant metrics from Prometheus and prints a human-readable
# summary indicating whether SLOs are passing or failing.
#
# Options:
#   METRICS_URL      Prometheus metrics endpoint (default: http://127.0.0.1:9898/metrics)
#   --tps-window=N   Window in seconds for TPS measurement (default: 60)
#
# Example:
#   scripts/t78_dag_primary_canary_check.sh
#   scripts/t78_dag_primary_canary_check.sh http://127.0.0.1:9898/metrics
#   scripts/t78_dag_primary_canary_check.sh http://127.0.0.1:9898/metrics --tps-window=30
#
# SLOs checked:
#   1. Consensus mode = dag-primary (eezo_consensus_mode_active == 3)
#   2. Shadow checker active (eezo_dag_primary_shadow_checks_total > 0 and increasing)
#   3. Zero shadow mismatches (eezo_dag_primary_shadow_mismatch_total == 0)
#   4. Transaction liveness (eezo_txs_included_total increasing)
#   5. Optional: TPS >= 150 (when dev-unsafe enabled)
#
# Exit codes:
#   0 - All SLOs passing
#   1 - One or more SLOs failing
#   2 - Metrics endpoint unreachable

# Default values
METRICS_URL="http://127.0.0.1:9898/metrics"
TPS_WINDOW=60

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tps-window=*)
      TPS_WINDOW="${1#*=}"
      shift
      ;;
    -*)
      echo "Unknown option: $1" >&2
      echo "Usage: $0 [METRICS_URL] [--tps-window=N]" >&2
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
echo -e "${BLUE}       T78.6 dag-primary canary SLO check                       ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Metrics endpoint: ${YELLOW}$METRICS_URL${NC}"
echo -e "TPS window: ${YELLOW}${TPS_WINDOW}s${NC}"
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
# SLO 1: Consensus Mode = dag-primary (3)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[Consensus Mode]${NC}"
CONSENSUS_MODE=$(get_metric "eezo_consensus_mode_active" "")
case "$CONSENSUS_MODE" in
  0) MODE_NAME="hotstuff"; MODE_OK=false ;;
  1) MODE_NAME="hybrid"; MODE_OK=false ;;
  2) MODE_NAME="dag"; MODE_OK=false ;;
  3) MODE_NAME="dag-primary"; MODE_OK=true ;;
  *) MODE_NAME="unknown"; MODE_OK=false ;;
esac

if [[ -z "$CONSENSUS_MODE" ]]; then
  print_status "eezo_consensus_mode_active" "(not found)" false "(metric not exported)"
else
  print_status "eezo_consensus_mode_active" "$CONSENSUS_MODE ($MODE_NAME)" "$MODE_OK" "(expected: 3=dag-primary)"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SLO 2: Shadow Checker Active
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[Shadow Checker]${NC}"
SHADOW_CHECKS=$(get_metric "eezo_dag_primary_shadow_checks_total" "0")
SHADOW_CHECKS_OK=$([[ "$SHADOW_CHECKS" != "0" ]] && echo "true" || echo "false")
print_status "eezo_dag_primary_shadow_checks_total" "$SHADOW_CHECKS" "$SHADOW_CHECKS_OK" "(expected: > 0)"

# Take a snapshot for increase check
SHADOW_CHECKS_T1="$SHADOW_CHECKS"

# Check if shadow checks are increasing (wait a few seconds)
echo -e "  ${YELLOW}○${NC} Checking shadow check activity over 5s..."
sleep 5

# Re-fetch metrics
METRICS=$(curl -sf "$METRICS_URL" 2>/dev/null) || {
  echo -e "  ${RED}ERROR: Failed to re-fetch metrics${NC}"
}
SHADOW_CHECKS_T2=$(get_metric "eezo_dag_primary_shadow_checks_total" "0")
SHADOW_DELTA=$((SHADOW_CHECKS_T2 - SHADOW_CHECKS_T1))

if [[ "$SHADOW_DELTA" -gt 0 ]]; then
  print_status "Shadow checks increasing" "+$SHADOW_DELTA over 5s" true "(active)"
else
  print_status "Shadow checks increasing" "+$SHADOW_DELTA over 5s" false "(stalled or disabled)"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SLO 3: Zero Shadow Mismatches
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[Shadow Safety]${NC}"
SHADOW_MISMATCH=$(get_metric "eezo_dag_primary_shadow_mismatch_total" "0")
MISMATCH_OK=$([[ "$SHADOW_MISMATCH" == "0" ]] && echo "true" || echo "false")
print_status "eezo_dag_primary_shadow_mismatch_total" "$SHADOW_MISMATCH" "$MISMATCH_OK" "(expected: 0)"

# Show mismatch reasons if any
if [[ "${SHADOW_MISMATCH%.*}" -gt 0 ]]; then
  echo -e "  ${YELLOW}Mismatch breakdown:${NC}"
  
  # Check for labeled mismatch reasons
  MISMATCH_TX_COUNT=$(get_labeled_metric 'eezo_dag_primary_shadow_mismatch_reason_total{reason="tx_count"}' "0")
  MISMATCH_TX_HASH=$(get_labeled_metric 'eezo_dag_primary_shadow_mismatch_reason_total{reason="tx_hash"}' "0")
  MISMATCH_BLOCK_HASH=$(get_labeled_metric 'eezo_dag_primary_shadow_mismatch_reason_total{reason="block_hash"}' "0")
  MISMATCH_OTHER=$(get_labeled_metric 'eezo_dag_primary_shadow_mismatch_reason_total{reason="other"}' "0")
  
  echo -e "    - tx_count: $MISMATCH_TX_COUNT"
  echo -e "    - tx_hash: $MISMATCH_TX_HASH"
  echo -e "    - block_hash: $MISMATCH_BLOCK_HASH"
  echo -e "    - other: $MISMATCH_OTHER"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SLO 4: Transaction Liveness
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[Transaction Liveness]${NC}"
TXS_INCLUDED_T1=$(get_metric "eezo_txs_included_total" "0")
BLOCK_HEIGHT=$(get_metric "eezo_block_height" "0")
MEMPOOL_LEN=$(get_metric "eezo_mempool_len" "0")

echo -e "  eezo_txs_included_total: $TXS_INCLUDED_T1"
echo -e "  eezo_block_height: $BLOCK_HEIGHT"
echo -e "  eezo_mempool_len: $MEMPOOL_LEN"

# Check block_applied_total vs shadow checks (for warning)
BLOCK_APPLIED=$(get_metric "block_applied_total" "0")
echo -e "  block_applied_total: $BLOCK_APPLIED"

# Check if blocks are applying but shadow is not running
if [[ "$BLOCK_APPLIED" -gt 0 && "$SHADOW_CHECKS" -eq 0 ]]; then
  echo -e "  ${RED}WARNING: Blocks applied but no shadow checks running!${NC}"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SLO 5: TPS Measurement (over window)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[TPS Measurement (${TPS_WINDOW}s window)]${NC}"
echo -e "  Measuring..."

TS1=$(date +%s)

sleep "$TPS_WINDOW"

# Re-fetch metrics
METRICS=$(curl -sf "$METRICS_URL" 2>/dev/null) || {
  echo -e "  ${RED}ERROR: Failed to re-fetch metrics${NC}"
}

TXS_INCLUDED_T2=$(get_metric "eezo_txs_included_total" "0")
TS2=$(date +%s)

TX_DELTA=$((TXS_INCLUDED_T2 - TXS_INCLUDED_T1))
TIME_DELTA=$((TS2 - TS1))

# Check liveness (txs increased)
LIVENESS_OK=$([[ "$TX_DELTA" -gt 0 ]] && echo "true" || echo "false")
print_status "Transactions included" "+$TX_DELTA over ${TIME_DELTA}s" "$LIVENESS_OK" ""

if [[ "$TIME_DELTA" -gt 0 ]]; then
  TPS=$(echo "scale=2; $TX_DELTA / $TIME_DELTA" | bc -l)
  
  # TPS threshold check (150 for dev-unsafe mode)
  TPS_THRESHOLD=150
  TPS_OK=$([[ $(echo "$TPS >= $TPS_THRESHOLD" | bc -l) == "1" ]] && echo "true" || echo "false")
  
  if [[ "$TX_DELTA" -gt 0 ]]; then
    print_status "TPS" "$TPS tx/s" "$TPS_OK" "(target: >= ${TPS_THRESHOLD} with dev-unsafe)"
  else
    echo -e "  ${YELLOW}○${NC} TPS: N/A (no transactions during window)"
  fi
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# DAG Primary Specific Metrics
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[DAG Primary Stats]${NC}"
BATCHES_USED=$(get_metric "eezo_dag_hybrid_batches_used_total" "0")
FALLBACK_TOTAL=$(get_metric "eezo_dag_hybrid_fallback_total" "0")

echo -e "  eezo_dag_hybrid_batches_used_total: $BATCHES_USED"
echo -e "  eezo_dag_hybrid_fallback_total: $FALLBACK_TOTAL"

# In dag-primary mode, fallback should be 0 (no mempool fallback)
if [[ "${FALLBACK_TOTAL%.*}" -gt 0 ]]; then
  echo -e "  ${YELLOW}NOTE: Fallback occurred in dag-primary mode (unexpected)${NC}"
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
  echo "See book/src/t78_dag_primary_canary.md for failure handling guidance."
  echo ""
  exit 1
fi
