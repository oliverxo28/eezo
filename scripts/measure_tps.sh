#!/usr/bin/env bash
set -euo pipefail

DURATION="${1:-30}"
METRICS_URL="${2:-http://127.0.0.1:9898/metrics}"

echo "[tps] measuring TPS for $DURATION seconds from $METRICS_URL"

# read starting tx count
START=$(curl -s "$METRICS_URL" | rg '^eezo_txs_included_total ' | awk '{print $2}')
TS_START=$(date +%s)

sleep "$DURATION"

# read ending tx count
END=$(curl -s "$METRICS_URL" | rg '^eezo_txs_included_total ' | awk '{print $2}')
TS_END=$(date +%s)

# compute delta
TX_DELTA=$((END - START))
TIME_DELTA=$((TS_END - TS_START))

echo "[tps] start_tx=$START end_tx=$END"
echo "[tps] tx_delta=$TX_DELTA over ${TIME_DELTA}s"

# compute TPS using bc for decimals
TPS=$(echo "scale=4; $TX_DELTA / $TIME_DELTA" | bc -l)
echo "[tps] TPS = $TPS"
