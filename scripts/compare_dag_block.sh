#!/usr/bin/env bash
# =============================================================================
# HISTORICAL SCRIPT (pre-T81 era)
# =============================================================================
# This script was used during T64–T78 to compare legacy blocks with DAG
# candidates. As of T81, EEZO uses pure DAG consensus and legacy mode
# is no longer available in production builds.
#
# Retained for historical reference and development/testing only.
# =============================================================================
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <node_http_base> <block_height>"
  echo "example: $0 http://127.0.0.1:8080 42"
  exit 1
fi

BASE="$1"
HEIGHT="$2"

echo "[i] comparing legacy block height=$HEIGHT vs current DAG candidate from $BASE"

# 1) Fetch block view
block_json=$(curl -s "$BASE/block/$HEIGHT")
if echo "$block_json" | jq -e '.error?' >/dev/null 2>&1; then
  echo "[!] block $HEIGHT not found:"
  echo "$block_json"
  exit 1
fi

# 2) Fetch DAG candidate
dag_json=$(curl -s "$BASE/dag/candidate")
if echo "$dag_json" | jq -e '.error?' >/dev/null 2>&1; then
  echo "[!] DAG candidate not available:"
  echo "$dag_json"
  exit 1
fi

echo
echo "=== Legacy block ==="
echo "$block_json" | jq '{height, tx_count: (.tx_hashes | length)}'

echo
echo "=== DAG candidate ==="
echo "$dag_json" | jq '{vertex_id, round, height, tx_count: (.tx_hashes | length)}'

# 3) Extract and sort tx hashes
block_txs=$(echo "$block_json" | jq -r '.tx_hashes[]?' | sort)
dag_txs=$(echo "$dag_json"   | jq -r '.tx_hashes[]?'   | sort)

# 4) Write to temp files for comm-diff
tmp_block=$(mktemp)
tmp_dag=$(mktemp)
printf "%s\n" "$block_txs" > "$tmp_block"
printf "%s\n" "$dag_txs"   > "$tmp_dag"

echo
echo "=== summary ==="
echo "block tx count: $(wc -l < "$tmp_block")"
echo "dag   tx count: $(wc -l < "$tmp_dag")"

echo
echo "tx present in BLOCK but missing in DAG (block − dag):"
comm -23 "$tmp_block" "$tmp_dag" || true

echo
echo "tx present in DAG but missing in BLOCK (dag − block):"
comm -13 "$tmp_block" "$tmp_dag" || true

rm -f "$tmp_block" "$tmp_dag"