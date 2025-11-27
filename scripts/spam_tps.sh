#!/usr/bin/env bash
set -euo pipefail

COUNT="${1:-1000}"
NODE="${NODE:-http://127.0.0.1:8080}"

: "${EEZO_TX_FROM:?EEZO_TX_FROM not set — export EEZO_TX_PK_HEX/EEZO_TX_SK_HEX and run ml_dsa_keygen first}"

ADDR_FROM="$EEZO_TX_FROM"

echo "[spam] using NODE=$NODE COUNT=$COUNT FROM=$ADDR_FROM"

# 1) Get starting nonce from /account
ACC_JSON=$(curl -s "$NODE/account/${ADDR_FROM}")
echo "[spam] account = $ACC_JSON"

START_NONCE=$(echo "$ACC_JSON" | jq -r '.nonce | tonumber')
echo "[spam] start_nonce = $START_NONCE"

# 2) Fire COUNT signed tx using eezo-txgen (one per nonce)
for ((i = 0; i < COUNT; i++)); do
  NONCE=$((START_NONCE + i))

  # eezo-txgen reads EEZO_TX_PK_HEX, EEZO_TX_SK_HEX, EEZO_TX_FROM, EEZO_TX_TO, EEZO_TX_CHAIN_ID
  BODY=$(target/debug/eezo-txgen "$NONCE")

  curl -s -X POST "$NODE/tx" \
    -H "Content-Type: application/json" \
    -d "$BODY" >/dev/null &
done

wait
echo "[spam] submitted $COUNT tx"
