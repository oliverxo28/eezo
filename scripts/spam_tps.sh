#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <count> <base_url> <from_addr> <to_addr>" >&2
  exit 1
fi

COUNT="$1"
BASE_URL="$2"
FROM="$3"
TO="$4"

echo "[spam] using BASE_URL=$BASE_URL COUNT=$COUNT FROM=$FROM TO=$TO"

# fetch account for correct starting nonce
ACC_JSON=$(curl -s "$BASE_URL/account/${FROM}")
START_NONCE=$(echo "$ACC_JSON" | jq -r '.nonce')

echo "[spam] starting from nonce=$START_NONCE"

for i in $(seq 0 $((COUNT-1))); do
  NONCE=$((START_NONCE + i))

  BODY=$(jq -n \
    --arg from "$FROM" \
    --arg to "$TO" \
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

  # print first 3 responses for debugging
  if [ "$i" -lt 3 ]; then
    echo "[spam] sending tx i=$i nonce=$NONCE"
    curl -s -w " [http_code=%{http_code}]\n" -X POST "$BASE_URL/tx" \
      -H "Content-Type: application/json" \
      -d "$BODY"
  else
    curl -s -o /dev/null -X POST "$BASE_URL/tx" \
      -H "Content-Type: application/json" \
      -d "$BODY"
  fi
done

echo "[spam] submitted $COUNT tx"
