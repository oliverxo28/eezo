#!/usr/bin/env bash
# T93.0: Fund and spam helper script
#
# This script handles the faucet funding and spam submission workflow
# for the STM tuning harness. It generates keys if needed, funds the
# sender account, and runs spam_tps.sh.
#
# Usage:
#   scripts/t93_fund_and_spam.sh COUNT NODE_URL
#
# Arguments:
#   COUNT    - Number of transactions to submit (default: 2000)
#   NODE_URL - Node HTTP URL (default: http://127.0.0.1:8080)
#
# Environment Variables (optional, auto-generated if not set):
#   EEZO_TX_FROM      - Sender address (derived from pubkey)
#   EEZO_TX_PK_HEX    - ML-DSA public key hex
#   EEZO_TX_SK_HEX    - ML-DSA secret key hex
#
# Always set by this script:
#   EEZO_TX_TO        - Receiver address (random)
#   EEZO_TX_CHAIN_ID  - Chain ID (devnet standard)
#   EEZO_TX_AMOUNT    - Transfer amount (1)
#   EEZO_TX_FEE       - Transaction fee (1)

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Arguments
# ─────────────────────────────────────────────────────────────────────────────
COUNT="${1:-2000}"
NODE_URL="${2:-http://127.0.0.1:8080}"

# ─────────────────────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Check for required tools
command -v jq >/dev/null || { echo "[t93_fund_and_spam] error: jq is required"; exit 1; }
command -v curl >/dev/null || { echo "[t93_fund_and_spam] error: curl is required"; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# Find binaries
# ─────────────────────────────────────────────────────────────────────────────
KEYGEN_BIN=""
TXGEN_BIN=""

# Try release first, then debug
for dir in "target/release" "target/debug"; do
    if [[ -x "$dir/ml_dsa_keygen" ]] && [[ -z "$KEYGEN_BIN" ]]; then
        KEYGEN_BIN="$dir/ml_dsa_keygen"
    fi
    if [[ -x "$dir/eezo-txgen" ]] && [[ -z "$TXGEN_BIN" ]]; then
        TXGEN_BIN="$dir/eezo-txgen"
    fi
done

if [[ -z "$KEYGEN_BIN" ]]; then
    echo "[t93_fund_and_spam] error: ml_dsa_keygen not found. Build with:" >&2
    echo "  cargo build -p eezo-crypto --bin ml_dsa_keygen --release" >&2
    exit 1
fi

if [[ -z "$TXGEN_BIN" ]]; then
    echo "[t93_fund_and_spam] error: eezo-txgen not found. Build with:" >&2
    echo "  cargo build -p eezo-node --bin eezo-txgen --release" >&2
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Generate keypair if not provided
# ─────────────────────────────────────────────────────────────────────────────
if [[ -z "${EEZO_TX_PK_HEX:-}" ]] || [[ -z "${EEZO_TX_SK_HEX:-}" ]]; then
    echo "[t93_fund_and_spam] generating new ML-DSA keypair..."
    KEYGEN_OUTPUT=$("$KEYGEN_BIN" 2>/dev/null)
    
    # Parse keygen output
    export EEZO_TX_PK_HEX=$(echo "$KEYGEN_OUTPUT" | grep '^export EEZO_TX_PK_HEX=' | sed 's/^export EEZO_TX_PK_HEX=//' | tr -d '\n\r')
    export EEZO_TX_SK_HEX=$(echo "$KEYGEN_OUTPUT" | grep '^export EEZO_TX_SK_HEX=' | sed 's/^export EEZO_TX_SK_HEX=//' | tr -d '\n\r')
    
    if [[ -z "$EEZO_TX_PK_HEX" ]] || [[ -z "$EEZO_TX_SK_HEX" ]]; then
        echo "[t93_fund_and_spam] error: failed to parse keygen output" >&2
        exit 1
    fi
fi

# Derive sender address from pubkey (first 20 bytes)
PK_RAW="${EEZO_TX_PK_HEX#0x}"
export EEZO_TX_FROM="0x${PK_RAW:0:40}"

# ─────────────────────────────────────────────────────────────────────────────
# Set transaction parameters
# ─────────────────────────────────────────────────────────────────────────────
# Generate random receiver address
RAND_HEX=""
if command -v openssl >/dev/null 2>&1; then
    RAND_HEX=$(openssl rand -hex 20 2>/dev/null || true)
fi
if [[ -z "$RAND_HEX" ]] && [[ -r /dev/urandom ]]; then
    RAND_HEX=$(head -c 20 /dev/urandom | od -An -tx1 2>/dev/null | tr -d ' \n' || true)
fi
if [[ -z "$RAND_HEX" ]]; then
    RAND_HEX=$(printf '%08x%08x%08x%08x%08x' $RANDOM $RANDOM $RANDOM $RANDOM $RANDOM)
fi

export EEZO_TX_TO="0x$RAND_HEX"
export EEZO_TX_CHAIN_ID="0x0000000000000000000000000000000000000001"
export EEZO_TX_AMOUNT="1"
export EEZO_TX_FEE="1"

echo "[t93_fund_and_spam] sender: ${EEZO_TX_FROM:0:14}...${EEZO_TX_FROM: -6}"
echo "[t93_fund_and_spam] receiver: ${EEZO_TX_TO:0:14}...${EEZO_TX_TO: -6}"

# ─────────────────────────────────────────────────────────────────────────────
# Fund sender account
# ─────────────────────────────────────────────────────────────────────────────
# Calculate funding: enough for COUNT txs + buffer (each tx costs amount + fee = 2)
FUND_AMOUNT=$((COUNT * 10 + 100000))

echo "[t93_fund_and_spam] funding sender with $FUND_AMOUNT..."

FAUCET_RESP=$(curl -sf -X POST "$NODE_URL/faucet" \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$EEZO_TX_FROM\",\"amount\":\"$FUND_AMOUNT\"}" 2>/dev/null || echo "FAILED")

if [[ "$FAUCET_RESP" == "FAILED" ]]; then
    echo "[t93_fund_and_spam] error: failed to fund sender" >&2
    exit 1
fi

echo "[t93_fund_and_spam] sender funded successfully"

# ─────────────────────────────────────────────────────────────────────────────
# Run spam
# ─────────────────────────────────────────────────────────────────────────────
echo "[t93_fund_and_spam] running spam_tps.sh with $COUNT transactions..."

"$SCRIPT_DIR/spam_tps.sh" "$COUNT" "$NODE_URL"

echo "[t93_fund_and_spam] spam complete"
