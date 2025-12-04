#!/usr/bin/env bash
set -euo pipefail

# usage: scripts/spam_tps.sh [COUNT] [NODE_URL]
COUNT="${1:-1000}"
NODE="${2:-${NODE:-http://127.0.0.1:8080}}"

# need jq to parse the JSON account view
command -v jq >/dev/null || { echo "jq is required"; exit 1; }

: "${EEZO_TX_FROM:?EEZO_TX_FROM not set — export EEZO_TX_PK_HEX/EEZO_TX_SK_HEX and run ml_dsa_keygen first}"

# normalize address (our HTTP handler expects lowercase hex; 0x prefix OK)
ADDR_FROM_LC="${EEZO_TX_FROM,,}"

echo "[spam] using NODE=$NODE COUNT=$COUNT FROM=$ADDR_FROM_LC"

# --- resolve account state (new route) ---
ACCT_JSON="$(curl -sf "$NODE/account/$ADDR_FROM_LC" || true)"
BAL_HEX="$(echo "$ACCT_JSON" | jq -r '.balance // empty')"
NON_HEX="$(echo "$ACCT_JSON" | jq -r '.nonce // empty')"

# defaults if node returned 404/empty (fresh account before faucet)
[ -z "$BAL_HEX" ] && BAL_HEX="0x0"
[ -z "$NON_HEX" ] && NON_HEX="0x0"

# hex -> decimal (bash handles 0x… in arithmetic expansion)
BAL_DEC=$((BAL_HEX))
NON_DEC=$((NON_HEX))

echo "[spam] account.balance = $BAL_HEX ($BAL_DEC)"
echo "[spam] start_nonce     = $NON_HEX ($NON_DEC)"

# if your txgen wants a hint, expose the hex start-nonce too
export EEZO_TX_START_NONCE="$NON_HEX"

# 2) Fire COUNT signed tx using eezo-txgen (one per nonce)
#    eezo-txgen must be built already (target/debug/eezo-txgen)
for ((i = 0; i < COUNT; i++)); do
  NONCE_DEC=$((NON_DEC + i))
  BODY="$(target/debug/eezo-txgen "$NONCE_DEC")"

  curl -s -X POST "$NODE/tx" \
    -H "Content-Type: application/json" \
    -d "$BODY" > /dev/null &
done

wait
echo "[spam] submitted $COUNT tx"
