#!/usr/bin/env bash
set -euo pipefail

# --- Configuration ---
NODE="http://127.0.0.1:8080"
TOTAL_TX="${1:-2000}"      # Total transactions to send
NUM_USERS="${2:-20}"       # Number of concurrent "users" (threads)
# ---------------------

TX_PER_USER=$((TOTAL_TX / NUM_USERS))
ADDR_TO="0xcafebabecafebabecafebabecafebabecafebabe"

echo "[multi-spam] Spawning $NUM_USERS users, sending $TX_PER_USER txs each (Total: $TOTAL_TX)"

# Function to simulate a single user's behavior
run_user_thread() {
  local USER_ID=$1
  local MY_ADDR=$2
  local MY_COUNT=$3

  # 1. Fund the account (Create it)
  # Fund the account
  echo "[user-$USER_ID] Funding $MY_ADDR..."
  curl -s -X POST "$NODE/faucet" \
       -H "Content-Type: application/json" \
       -d "{\"to\":\"$MY_ADDR\",\"amount\":\"1000000000\"}" > /dev/null

  # 2. Sequential Spam Loop for Each User
  # We run this SEQUENTIALLY per user to ensure Nonce 0 arrives before Nonce 1
  # preventing the "Nonce Gap" error.
  for (( i=0; i<MY_COUNT; i++ )); do
    BODY=$(jq -n -c \
      --arg from "$MY_ADDR" \
      --arg to "$ADDR_TO" \
      --arg nonce "$i" \
      '
      {
        tx: {
          from: $from,
          to: $to,
          amount: "1",
          nonce: $nonce,
          fee: "0",
          chain_id: "0x01"
        },
        sig: ""
      }')

    # We use curl synchronously here (no & at the end)
    # This ensures Nonce 0 is sent before Nonce 1.
    curl -s -X POST "$NODE/tx" \
      -H "Content-Type: application/json" \
      -d "$BODY" > /dev/null
    echo "[user-$USER_ID] Sent tx $i"
  done
  
  echo "[user-$USER_ID] Finished $MY_COUNT txs"
}

# --- Main Launcher ---

pids=""

for (( u=1; u<=NUM_USERS; u++ )); do
  # Generate a random 20-byte address (40 hex chars)
  RAND_HEX=$(openssl rand -hex 20 2>/dev/null || echo "00000000000000000000000000000000$(date +%N)$u" | head -c 40)
  NEW_ADDR="0x$RAND_HEX"

  # Run the user function in the background
  run_user_thread "$u" "$NEW_ADDR" "$TX_PER_USER" &
  
  # Store PID to wait later (optional, 'wait' handles it)
  pids="$pids $!"
done

echo "[multi-spam] All $NUM_USERS users started. Waiting for completion..."
wait
echo "[multi-spam] Done."
