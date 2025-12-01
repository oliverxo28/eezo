#!/usr/bin/env bash
set -euo pipefail

# T72.1 — Capture executor metrics for perf experiments
# Usage: scripts/t72_capture_metrics.sh <label> [METRICS_URL]

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <label> [METRICS_URL]"
  echo "  label       - required; used in output filename (e.g. baseline, fast500, fast250)"
  echo "  METRICS_URL - optional; defaults to http://127.0.0.1:9898/metrics"
  exit 1
fi

LABEL="$1"
METRICS_URL="${2:-http://127.0.0.1:9898/metrics}"
OUTFILE="/tmp/eezo-t72-${LABEL}-metrics.txt"

# Fetch metrics (fail on HTTP errors)
METRICS=$(curl -sf "$METRICS_URL") || {
  echo "[t72] error: failed to fetch metrics from $METRICS_URL" >&2
  exit 1
}

# Filter to executor-related lines:
#  - eezo_txs_included_total (transaction counter)
#  - eezo_block_exec_seconds* (block execution timing)
#  - eezo_exec_* (executor metrics from T72.0)
echo "$METRICS" | \
  grep -E '^(eezo_txs_included_total |eezo_block_exec_seconds[_{ ]|eezo_exec_)' \
  > "$OUTFILE"

echo "[t72] wrote $OUTFILE"
