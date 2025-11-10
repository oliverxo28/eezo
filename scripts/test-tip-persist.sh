#!/usr/bin/env bash
set -euo pipefail

PORT=18180
DATADIR=target/dev
CHAIN=0000000000000000000000000000000000000001

# clean and start
pkill -f eezo-node || true
rm -rf "$DATADIR"
EEZO_TREASURY=0x99 EEZO_CHAIN_ID=$CHAIN \
  cargo run -p eezo-node --features metrics -- \
  --datadir "$DATADIR" --listen 127.0.0.1:$PORT >/tmp/eezo.log 2>&1 &
PID=$!

# wait server
for i in {1..50}; do curl -sf localhost:$PORT/health && break; sleep 0.1; done

# fund and send two good txs
curl -s -X POST localhost:$PORT/faucet -H content-type:application/json -d '{"to":"0x01","amount":"1000"}' >/dev/null
H0=$(curl -s localhost:$PORT/block/head | jq -r .height)

HASH_OK=$(curl -s -X POST localhost:$PORT/tx -H content-type:application/json \
  -d '{"tx":{"from":"0x01","to":"0x02","amount":"7","nonce":"0","fee":"3","chain_id":"0x01"},"sig":"ok"}' | jq -r .hash)
sleep 1
H1=$(curl -s localhost:$PORT/block/head | jq -r .height)
[ "$H1" -eq $((H0+1)) ]

# bad tx should NOT bump height
HASH_BAD=$(curl -s -X POST localhost:$PORT/tx -H content-type:application/json \
  -d '{"tx":{"from":"0x01","to":"0x02","amount":"1","nonce":"999","fee":"0","chain_id":"0x01"},"sig":"x"}' | jq -r .hash)
sleep 1
H2=$(curl -s localhost:$PORT/block/head | jq -r .height)
[ "$H2" -eq "$H1" ]

# restart; tip must persist
kill $PID
EEZO_TREASURY=0x99 EEZO_CHAIN_ID=$CHAIN \
  cargo run -p eezo-node --features metrics -- \
  --datadir "$DATADIR" --listen 127.0.0.1:$PORT >/tmp/eezo.log 2>&1 &
PID=$!
for i in {1..50}; do curl -sf localhost:$PORT/health && break; sleep 0.1; done

H3=$(curl -s localhost:$PORT/block/head | jq -r .height)
[ "$H3" -eq "$H2" ]

echo "✅ tip persistence OK (height=$H3)"
kill $PID
