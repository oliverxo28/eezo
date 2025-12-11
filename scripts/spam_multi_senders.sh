#!/usr/bin/env bash
# T83.1: Multi-sender spam script for TPS benchmarking with configurable conflict patterns
#
# PURPOSE:
#   Generate multi-sender PQ transactions with configurable conflict patterns to
#   stress-test the STM executor and measure TPS under various contention scenarios.
#
# USAGE:
#   ./scripts/spam_multi_senders.sh [OPTIONS]
#
# OPTIONS:
#   -s, --senders <num>        Number of distinct sender accounts (default: 16)
#   -t, --per-sender <num>     Transactions per sender (default: 200)
#   -r, --hot-receivers <num>  Number of "hot" target accounts (default: 1 for hotspot)
#   -p, --pattern <mode>       Conflict pattern: "disjoint" or "hotspot" (default: hotspot)
#   -n, --node <url>           Node HTTP URL (default: http://127.0.0.1:8080)
#   -h, --help                 Show this help message
#
# ENVIRONMENT VARIABLES (optional overrides):
#   NODE                       Node HTTP URL (overridden by --node)
#
# CONFLICT PATTERNS:
#   - disjoint: Each sender sends to unique receivers (low conflict).
#               Each sender has its own dedicated receiver pool.
#   - hotspot:  All senders send to a small set of "hot" receivers (high conflict).
#               Creates contention on shared state.
#
# REQUIREMENTS:
#   - ml_dsa_keygen binary (built from crates/crypto)
#   - eezo-txgen binary (built from crates/node)
#   - jq command for JSON processing
#   - curl for HTTP requests
#   - Running eezo-node in dag-primary mode (scripts/devnet_dag_primary.sh)
#
# EXAMPLES:
#   # Low conflict (disjoint pattern) - 16 senders, each with unique receiver
#   ./scripts/spam_multi_senders.sh --senders 16 --per-sender 200 --hot-receivers 16 --pattern disjoint
#
#   # High conflict (hotspot pattern) - 16 senders targeting 1 receiver
#   ./scripts/spam_multi_senders.sh --senders 16 --per-sender 200 --hot-receivers 1 --pattern hotspot
#
#   # Use with TPS benchmark:
#   # Terminal 1: ./scripts/devnet_dag_primary.sh
#   # Terminal 2: ./scripts/spam_multi_senders.sh --senders 16 --per-sender 200 --pattern hotspot
#   # Terminal 3: ./scripts/tps_benchmark.sh --duration 60 --warmup 10 --verbose
#
# SEE ALSO:
#   - book/src/t83_multi_sender_baseline.md for detailed workflow documentation
#   - scripts/tps_benchmark.sh for TPS measurement
#   - scripts/devnet_dag_primary.sh for starting the node

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Default Configuration
# ─────────────────────────────────────────────────────────────────────────────
NUM_SENDERS=16
TX_PER_SENDER=200
NUM_HOT_RECEIVERS=1
PATTERN="hotspot"
NODE="${NODE:-http://127.0.0.1:8080}"

# ─────────────────────────────────────────────────────────────────────────────
# Argument Parsing
# ─────────────────────────────────────────────────────────────────────────────
show_help() {
    cat << 'EOF'
T83.1: Multi-sender spam script for TPS benchmarking with configurable conflict patterns

Usage: spam_multi_senders.sh [OPTIONS]

Options:
  -s, --senders <num>        Number of distinct sender accounts (default: 16)
  -t, --per-sender <num>     Transactions per sender (default: 200)
  -r, --hot-receivers <num>  Number of "hot" target accounts (default: 1)
  -p, --pattern <mode>       Conflict pattern: "disjoint" or "hotspot" (default: hotspot)
  -n, --node <url>           Node HTTP URL (default: http://127.0.0.1:8080)
  -h, --help                 Show this help message

Conflict Patterns:
  disjoint   Each sender targets unique receivers (low conflict)
  hotspot    All senders target a shared pool of hot receivers (high conflict)

Examples:
  # Low conflict - each sender has unique receiver
  ./scripts/spam_multi_senders.sh --senders 16 --per-sender 200 --hot-receivers 16 --pattern disjoint

  # High conflict - all senders target 1 receiver
  ./scripts/spam_multi_senders.sh --senders 16 --per-sender 200 --hot-receivers 1 --pattern hotspot

EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--senders)
            NUM_SENDERS="$2"
            shift 2
            ;;
        -t|--per-sender)
            TX_PER_SENDER="$2"
            shift 2
            ;;
        -r|--hot-receivers)
            NUM_HOT_RECEIVERS="$2"
            shift 2
            ;;
        -p|--pattern)
            PATTERN="$2"
            shift 2
            ;;
        -n|--node)
            NODE="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Error: Unknown option: $1" >&2
            echo "Use --help for usage information." >&2
            exit 1
            ;;
    esac
done

# ─────────────────────────────────────────────────────────────────────────────
# Validate pattern
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$PATTERN" != "disjoint" && "$PATTERN" != "hotspot" ]]; then
    echo "[error] Invalid pattern: $PATTERN (must be 'disjoint' or 'hotspot')" >&2
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Check dependencies
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Check for required binaries
KEYGEN_BIN="target/debug/ml_dsa_keygen"
TXGEN_BIN="target/debug/eezo-txgen"

if [[ ! -x "$KEYGEN_BIN" ]]; then
    # Try release build
    if [[ -x "target/release/ml_dsa_keygen" ]]; then
        KEYGEN_BIN="target/release/ml_dsa_keygen"
    else
        echo "[error] ml_dsa_keygen not found. Build with:" >&2
        echo "  cargo build -p eezo-crypto --bin ml_dsa_keygen" >&2
        exit 1
    fi
fi

if [[ ! -x "$TXGEN_BIN" ]]; then
    # Try release build
    if [[ -x "target/release/eezo-txgen" ]]; then
        TXGEN_BIN="target/release/eezo-txgen"
    else
        echo "[error] eezo-txgen not found. Build with:" >&2
        echo "  cargo build -p eezo-node --bin eezo-txgen" >&2
        exit 1
    fi
fi

command -v jq >/dev/null || { echo "[error] jq is required"; exit 1; }
command -v curl >/dev/null || { echo "[error] curl is required"; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# Verify node connectivity
# ─────────────────────────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════════════════"
echo "  T83.1: Multi-sender Spam Generator"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""
echo "Configuration:"
echo "  Node URL:           $NODE"
echo "  Number of senders:  $NUM_SENDERS"
echo "  Tx per sender:      $TX_PER_SENDER"
echo "  Total txs:          $((NUM_SENDERS * TX_PER_SENDER))"
echo "  Hot receivers:      $NUM_HOT_RECEIVERS"
echo "  Pattern:            $PATTERN"
echo ""

echo "[1/4] Verifying node connectivity..."
if ! curl -sf "$NODE/health" >/dev/null 2>&1; then
    echo "[error] Cannot reach node at $NODE" >&2
    echo "Make sure the node is running:" >&2
    echo "  ./scripts/devnet_dag_primary.sh" >&2
    exit 1
fi
echo "      ✓ Node is responding at $NODE"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Generate hot receiver addresses (for hotspot pattern)
# ─────────────────────────────────────────────────────────────────────────────
echo "[2/4] Generating receiver addresses..."

declare -a HOT_RECEIVERS
for (( r=0; r < NUM_HOT_RECEIVERS; r++ )); do
    # Generate a deterministic receiver address based on index
    # Use openssl rand for randomness
    RAND_HEX=$(openssl rand -hex 20 2>/dev/null || printf '%040x' $((r + 1000000)))
    HOT_RECEIVERS+=("0x$RAND_HEX")
done

echo "      ✓ Generated $NUM_HOT_RECEIVERS receiver address(es)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Generate sender keypairs and fund accounts
# ─────────────────────────────────────────────────────────────────────────────
echo "[3/4] Generating sender keypairs and funding accounts..."

# Arrays to store sender info
declare -a SENDER_ADDRS
declare -a SENDER_PKS
declare -a SENDER_SKS

# Calculate funding amount: enough for all txs + some buffer
# Each tx sends amount=1 with fee=1, so need at least 2 * TX_PER_SENDER
FUND_AMOUNT=$((TX_PER_SENDER * 10 + 100000))

for (( s=0; s < NUM_SENDERS; s++ )); do
    # Generate ML-DSA keypair
    KEYGEN_OUTPUT=$("$KEYGEN_BIN" 2>/dev/null)
    
    # Parse the output (format: export EEZO_TX_PK_HEX=0x... \n export EEZO_TX_SK_HEX=0x...)
    PK_HEX=$(echo "$KEYGEN_OUTPUT" | grep 'EEZO_TX_PK_HEX' | sed 's/.*=0x/0x/' | tr -d '\n\r')
    SK_HEX=$(echo "$KEYGEN_OUTPUT" | grep 'EEZO_TX_SK_HEX' | sed 's/.*=0x/0x/' | tr -d '\n\r')
    
    if [[ -z "$PK_HEX" || -z "$SK_HEX" ]]; then
        echo "[error] Failed to parse keygen output for sender $s" >&2
        exit 1
    fi
    
    # Derive address: first 20 bytes of pubkey (matching sender_from_pubkey_first20)
    # Strip 0x prefix, take first 40 hex chars (20 bytes)
    PK_RAW="${PK_HEX#0x}"
    SENDER_ADDR="0x${PK_RAW:0:40}"
    
    SENDER_ADDRS+=("$SENDER_ADDR")
    SENDER_PKS+=("$PK_HEX")
    SENDER_SKS+=("$SK_HEX")
    
    # Fund the sender account
    FAUCET_RESP=$(curl -sf -X POST "$NODE/faucet" \
        -H "Content-Type: application/json" \
        -d "{\"to\":\"$SENDER_ADDR\",\"amount\":\"$FUND_AMOUNT\"}" 2>/dev/null || echo "FAILED")
    
    if [[ "$FAUCET_RESP" == "FAILED" ]]; then
        echo "[error] Failed to fund sender $s at $SENDER_ADDR" >&2
        exit 1
    fi
    
    echo "      Sender $((s+1))/$NUM_SENDERS: ${SENDER_ADDR:0:14}...${SENDER_ADDR: -6} (funded with $FUND_AMOUNT)"
done

echo "      ✓ Generated and funded $NUM_SENDERS sender accounts"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Send transactions
# ─────────────────────────────────────────────────────────────────────────────
echo "[4/4] Sending transactions (pattern: $PATTERN)..."
echo ""

# Standard chain_id for devnet (20 bytes of 0x01)
CHAIN_ID="0x0101010101010101010101010101010101010101"

# Function to select receiver based on pattern
select_receiver() {
    local sender_idx=$1
    local tx_idx=$2
    
    if [[ "$PATTERN" == "disjoint" ]]; then
        # Disjoint: each sender uses receivers in round-robin from their own pool
        # If we have enough hot_receivers, each sender gets unique ones
        # Otherwise, distribute evenly
        local receiver_idx=$(( (sender_idx + tx_idx) % NUM_HOT_RECEIVERS ))
        echo "${HOT_RECEIVERS[$receiver_idx]}"
    else
        # Hotspot: all senders target the same small pool of receivers
        local receiver_idx=$(( tx_idx % NUM_HOT_RECEIVERS ))
        echo "${HOT_RECEIVERS[$receiver_idx]}"
    fi
}

# Track progress
TOTAL_TX=0
FAILED_TX=0
START_TIME=$(date +%s)

# Run senders in parallel (up to NUM_SENDERS concurrent jobs)
run_sender() {
    local s=$1
    local sender_addr="${SENDER_ADDRS[$s]}"
    local pk_hex="${SENDER_PKS[$s]}"
    local sk_hex="${SENDER_SKS[$s]}"
    local local_sent=0
    local local_failed=0
    
    # Get current nonce for this sender
    ACCT_JSON="$(curl -sf "$NODE/account/${sender_addr,,}" 2>/dev/null || echo "{}")"
    NON_HEX="$(echo "$ACCT_JSON" | jq -r '.nonce // "0x0"')"
    NON_DEC=$((NON_HEX))
    
    for (( i=0; i < TX_PER_SENDER; i++ )); do
        local nonce_dec=$((NON_DEC + i))
        local receiver=$(select_receiver $s $i)
        
        # Set environment for eezo-txgen
        export EEZO_TX_FROM="$sender_addr"
        export EEZO_TX_TO="$receiver"
        export EEZO_TX_CHAIN_ID="$CHAIN_ID"
        export EEZO_TX_AMOUNT="1"
        export EEZO_TX_FEE="1"
        export EEZO_TX_PK_HEX="$pk_hex"
        export EEZO_TX_SK_HEX="$sk_hex"
        
        # Generate signed tx
        BODY=$("$TXGEN_BIN" "$nonce_dec" 2>/dev/null) || {
            ((local_failed++))
            continue
        }
        
        # Submit tx
        curl -sf -X POST "$NODE/tx" \
            -H "Content-Type: application/json" \
            -d "$BODY" >/dev/null 2>&1 && ((local_sent++)) || ((local_failed++))
    done
    
    echo "sender_${s}_sent=$local_sent"
    echo "sender_${s}_failed=$local_failed"
}

# Export functions and variables for subshells
export -f run_sender select_receiver
export TXGEN_BIN NODE TX_PER_SENDER PATTERN NUM_HOT_RECEIVERS CHAIN_ID
export SENDER_ADDRS SENDER_PKS SENDER_SKS HOT_RECEIVERS

# Run senders in parallel with a reasonable job limit
MAX_PARALLEL_JOBS=$NUM_SENDERS
if (( MAX_PARALLEL_JOBS > 32 )); then
    MAX_PARALLEL_JOBS=32
fi

# Simple parallel execution
pids=()
for (( s=0; s < NUM_SENDERS; s++ )); do
    (
        sender_addr="${SENDER_ADDRS[$s]}"
        pk_hex="${SENDER_PKS[$s]}"
        sk_hex="${SENDER_SKS[$s]}"
        local_sent=0
        local_failed=0
        
        # Get current nonce for this sender
        ACCT_JSON="$(curl -sf "$NODE/account/${sender_addr,,}" 2>/dev/null || echo "{}")"
        NON_HEX="$(echo "$ACCT_JSON" | jq -r '.nonce // "0x0"')"
        NON_DEC=$((NON_HEX))
        
        for (( i=0; i < TX_PER_SENDER; i++ )); do
            nonce_dec=$((NON_DEC + i))
            
            # Select receiver based on pattern
            if [[ "$PATTERN" == "disjoint" ]]; then
                receiver_idx=$(( (s + i) % NUM_HOT_RECEIVERS ))
            else
                receiver_idx=$(( i % NUM_HOT_RECEIVERS ))
            fi
            receiver="${HOT_RECEIVERS[$receiver_idx]}"
            
            # Set environment for eezo-txgen
            export EEZO_TX_FROM="$sender_addr"
            export EEZO_TX_TO="$receiver"
            export EEZO_TX_CHAIN_ID="$CHAIN_ID"
            export EEZO_TX_AMOUNT="1"
            export EEZO_TX_FEE="1"
            export EEZO_TX_PK_HEX="$pk_hex"
            export EEZO_TX_SK_HEX="$sk_hex"
            
            # Generate signed tx
            BODY=$("$TXGEN_BIN" "$nonce_dec" 2>/dev/null) || {
                ((local_failed++))
                continue
            }
            
            # Submit tx (fire and forget for speed)
            curl -sf -X POST "$NODE/tx" \
                -H "Content-Type: application/json" \
                -d "$BODY" >/dev/null 2>&1 &
        done
        
        # Wait for this sender's submissions
        wait
        
        echo "[sender $((s+1))/$NUM_SENDERS] Submitted $TX_PER_SENDER transactions"
    ) &
    pids+=($!)
    
    # Limit concurrent jobs
    if (( ${#pids[@]} >= MAX_PARALLEL_JOBS )); then
        wait "${pids[0]}"
        pids=("${pids[@]:1}")
    fi
done

# Wait for all remaining jobs
wait

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "═══════════════════════════════════════════════════════════════════════════"
echo "  Multi-sender Spam Complete"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""
echo "Summary:"
echo "  Pattern:            $PATTERN"
echo "  Senders:            $NUM_SENDERS"
echo "  Tx per sender:      $TX_PER_SENDER"
echo "  Total tx issued:    $((NUM_SENDERS * TX_PER_SENDER))"
echo "  Hot receivers:      $NUM_HOT_RECEIVERS"
echo "  Elapsed time:       ${ELAPSED}s"
echo ""
echo "Next steps:"
echo "  Run TPS benchmark to measure throughput and conflict metrics:"
echo "    ./scripts/tps_benchmark.sh --duration 60 --warmup 10 --verbose"
echo ""
echo "  Key metrics to watch:"
echo "    - eezo_exec_stm_conflicts_total"
echo "    - eezo_exec_stm_retries_total"
echo "    - eezo_exec_stm_waves_built_total"
echo ""
echo "═══════════════════════════════════════════════════════════════════════════"
