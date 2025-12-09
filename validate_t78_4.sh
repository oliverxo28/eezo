#!/bin/bash
# T78.4 Validation Script
# This script helps validate that dag-primary mode is working correctly

set -e

METRICS_URL="${1:-http://localhost:3030/metrics}"

echo "========================================="
echo "T78.4 DAG-Primary Mode Validation Script"
echo "========================================="
echo ""
echo "Checking metrics at: $METRICS_URL"
echo ""

# Function to get metric value
get_metric() {
    local metric_name=$1
    curl -s "$METRICS_URL" | grep "^$metric_name " | awk '{print $2}' | head -1
}

# Function to check metric exists
check_metric_exists() {
    local metric_name=$1
    local result=$(curl -s "$METRICS_URL" | grep -c "^$metric_name " || true)
    echo $result
}

echo "1. Checking consensus mode..."
MODE=$(get_metric "eezo_consensus_mode_active")
if [ "$MODE" = "3" ]; then
    echo "   ✅ dag-primary mode active (value: $MODE)"
else
    echo "   ❌ Expected mode 3 (dag-primary), got: $MODE"
    echo "      0=hotstuff, 1=dag-hybrid, 2=dag, 3=dag-primary"
fi
echo ""

echo "2. Checking fallback metrics (should be 0 in dag-primary)..."
FALLBACK=$(get_metric "eezo_dag_hybrid_fallback_total")
if [ "$FALLBACK" = "0" ] || [ -z "$FALLBACK" ]; then
    echo "   ✅ No fallback occurred (value: ${FALLBACK:-0})"
else
    echo "   ❌ Fallback counter is non-zero: $FALLBACK"
    echo "      This indicates dag-primary is falling back to mempool (BUG!)"
fi
echo ""

echo "3. Checking shadow checker metric..."
EXISTS=$(check_metric_exists "eezo_dag_primary_shadow_checks_total")
if [ "$EXISTS" -gt 0 ]; then
    SHADOW=$(get_metric "eezo_dag_primary_shadow_checks_total")
    echo "   ✅ Shadow checker metric registered (value: ${SHADOW:-0})"
    if [ -n "$SHADOW" ] && [ "$SHADOW" -gt 0 ]; then
        echo "      Shadow checks have run $SHADOW times"
    fi
else
    echo "   ❌ Shadow checker metric not found"
    echo "      Metric should be registered at startup"
fi
echo ""

echo "4. Checking DAG batch usage..."
BATCHES=$(get_metric "eezo_dag_hybrid_batches_used_total")
if [ -n "$BATCHES" ] && [ "$BATCHES" -gt 0 ]; then
    echo "   ✅ DAG batches are being used (count: $BATCHES)"
else
    echo "   ⚠️  No DAG batches used yet (count: ${BATCHES:-0})"
    echo "      This is expected if no transactions have been sent"
fi
echo ""

echo "5. Checking transaction inclusion..."
TXS=$(get_metric "eezo_txs_included_total")
BLOCKS=$(get_metric "block_applied_total")
echo "   Transactions included: ${TXS:-0}"
echo "   Blocks applied: ${BLOCKS:-0}"
if [ -n "$TXS" ] && [ "$TXS" -gt 0 ]; then
    echo "   ✅ Transactions are being processed"
else
    echo "   ⚠️  No transactions processed yet"
fi
echo ""

echo "6. Checking labeled fallback reasons (all should be 0)..."
echo "   Checking for any non-zero fallback reasons..."
FALLBACK_REASONS=$(curl -s "$METRICS_URL" | grep "eezo_dag_hybrid_fallback_reason_total" || true)
if [ -n "$FALLBACK_REASONS" ]; then
    NON_ZERO=$(echo "$FALLBACK_REASONS" | awk '$2 != "0" {print}')
    if [ -z "$NON_ZERO" ]; then
        echo "   ✅ All fallback reason counters are 0"
    else
        echo "   ❌ Found non-zero fallback reasons:"
        echo "$NON_ZERO" | sed 's/^/      /'
    fi
else
    echo "   ✅ No fallback reason metrics (as expected)"
fi
echo ""

echo "========================================="
echo "Validation Complete"
echo "========================================="
echo ""
echo "Expected behavior in dag-primary mode:"
echo "  - Consensus mode: 3"
echo "  - Fallback counter: 0 (never increments)"
echo "  - Shadow checker: Present and incrementing"
echo "  - DAG batches: Used when transactions available"
echo "  - Empty blocks: Allowed when DAG has no transactions"
echo ""
echo "See T78_4_SUMMARY.md for detailed validation steps."
