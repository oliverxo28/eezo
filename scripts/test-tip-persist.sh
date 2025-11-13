#!/usr/bin/env bash
# test-tip-persist.sh – validates block height persistence across node restart.
set -euo pipefail

require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1"; exit 1; }; }
require_cmd curl
require_cmd jq

PORT="${PORT:-18180}"
DATADIR="${DATADIR:-target/dev}"
CHAIN="${CHAIN:-0000000000000000000000000000000000000001}"

cleanup() {
  if [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; then
    kill "$PID"
  fi
}
trap cleanup EXIT

start_node() {
  EEZO_TREASURY=0x99 EEZO_CHAIN_ID="$CHAIN" \
    cargo run -q -p eezo-node --features metrics -- \
      --datadir "$DATADIR" --listen "127.0.0.1:$PORT" >/tmp/eezo.log 2>&1 &
  PID=$!
  for i in {1..80}; do
    if curl -sf "localhost:$PORT/health" >/dev/null; then
      return 0
    fi
    sleep 0.15
  done
  echo "❌ node failed to become healthy; tail:"
  tail -n 50 /tmp/eezo.log || true
  exit 1
}

stop_node() {
  if [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; then
    kill "$PID"
    wait "$PID" || true
  fi
}

pkill -f eezo-node 2>/dev/null || true
rm -rf "$DATADIR"
start_node

fund() {
  curl -s -X POST "localhost:$PORT/faucet" \
    -H content-type:application/json \
    -d '{"to":"0x01","amount":"1000"}' >/dev/null
}

send_good_tx() {
  curl -s -X POST "localhost:$PORT/tx" -H content-type:application/json \
    -d '{"tx":{"from":"0x01","to":"0x02","amount":"7","nonce":"0","fee":"3","chain_id":"0x01"},"sig":"ok"}' | jq -r .hash
}

send_bad_tx() {
  curl -s -X POST "localhost:$PORT/tx" -H content-type:application/json \
    -d '{"tx":{"from":"0x01","to":"0x02","amount":"1","nonce":"999","fee":"0","chain_id":"0x01"},"sig":"x"}' | jq -r .hash
}

fund
H0="$(curl -s "localhost:$PORT/block/head" | jq -r .height)"
GOOD_HASH="$(send_good_tx)"
sleep 1
H1="$(curl -s "localhost:$PORT/block/head" | jq -r .height)"
if [[ "$H1" -ne $((H0+1)) ]]; then
  echo "❌ expected height to increment: H0=$H0 H1=$H1"
  exit 1
fi

BAD_HASH="$(send_bad_tx)"
sleep 1
H2="$(curl -s "localhost:$PORT/block/head" | jq -r .height)"
if [[ "$H2" -ne "$H1" ]]; then
  echo "❌ bad tx changed height unexpectedly: H1=$H1 H2=$H2"
  exit 1
fi

stop_node
start_node

H3="$(curl -s "localhost:$PORT/block/head" | jq -r .height)"
if [[ "$H3" -ne "$H2" ]]; then
  echo "❌ tip persistence failed: H2=$H2 H3=$H3"
  exit 1
fi

echo "✅ tip persistence OK (height=$H3)"
