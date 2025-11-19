#!/usr/bin/env bash
set -euo pipefail

ADDR_FROM="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
ADDR_TO="0xcafebabecafebabecafebabecafebabecafebabe"
COUNT="${1:-1000}"

METRICS="http://127.0.0.1:9898/metrics"
NODE="http://127.0.0.1:8080"

echo "[spam] using NODE=$NODE COUNT=$COUNT"

# 1) Get starting nonce from /account
ACC_JSON=$(curl -s "$NODE/account/${ADDR_FROM}")
echo "[spam] account = $ACC_JSON"

START_NONCE=$(echo "$ACC_JSON" | jq -r '.nonce')
if [ -z "$START_NONCE" ] || [ "$START_NONCE" = "null" ]; then
  START_NONCE=0
fi

echo "[spam] starting nonce = $START_NONCE"

for i in $(seq 0 $((COUNT-1))); do
  NONCE=$((START_NONCE + i))

  BODY=$(jq -n \
    --arg from "$ADDR_FROM" \
    --arg to "$ADDR_TO" \
    --arg amount "1" \
    --arg nonce "$NONCE" \
    --arg fee "0" \
    --arg cid "0x01" \
    --arg sig "" '
    {
      tx: {
        from: $from,
        to: $to,
        amount: $amount,
        nonce: $nonce,
        fee: $fee,
        chain_id: $cid
      },
      sig: $sig
    }')

  curl -s -X POST "$NODE/tx" \
    -H "Content-Type: application/json" \
    -d "$BODY" > /dev/null &
done

wait
echo "[spam] submitted $COUNT tx"
