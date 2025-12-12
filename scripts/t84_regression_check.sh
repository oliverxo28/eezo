#!/usr/bin/env bash
# T84.5: Lightweight TPS Regression Guard
#
# Usage: scripts/t84_regression_check.sh [OPTIONS]
#
# This script checks that TPS hasn't fallen below a conservative floor.
# It's designed as a manual canary, not a CI test.
#
# Prerequisites:
#   - Node running with T84.5 profile (source devnet_tps.env first)
#   - eezo-txgen and ml_dsa_keygen binaries built
#   - jq, curl, bc available
#
# Options:
#   -f, --floor <tps>     TPS floor threshold (default: 100)
#   -n, --node <url>      Node HTTP URL (default: http://127.0.0.1:8080)
#   -m, --metrics <url>   Metrics URL (default: http://127.0.0.1:9898/metrics)
#   -c, --count <num>     Number of transactions to spam (default: 2000)
#   -d, --duration <sec>  Measurement duration in seconds (default: 20)
#   -w, --warmup <sec>    Warm-up period in seconds (default: 5)
#   -h, --help            Show this help message
#
# Exit codes:
#   0 - TPS meets floor (regression check passed)
#   1 - TPS below floor (potential regression detected)
#   2 - Node not reachable or other error
#
# Example:
#   # Start node first
#   source devnet_tps.env
#   ./scripts/devnet_dag_primary.sh
#
#   # In another terminal, run regression check
#   ./scripts/t84_regression_check.sh
#
# See book/src/t84_plateau.md for complete documentation.

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Default Configuration
# ─────────────────────────────────────────────────────────────────────────────
TPS_FLOOR=100
NODE_URL="${NODE:-http://127.0.0.1:8080}"
METRICS_URL="${EEZO_METRICS_URL:-http://127.0.0.1:9898/metrics}"
TX_COUNT=2000
DURATION=20
WARMUP=5

# ─────────────────────────────────────────────────────────────────────────────
# Argument Parsing
# ─────────────────────────────────────────────────────────────────────────────
show_help() {
    cat << 'EOF'
T84.5: Lightweight TPS Regression Guard

Usage: t84_regression_check.sh [OPTIONS]

Options:
  -f, --floor <tps>     TPS floor threshold (default: 100)
  -n, --node <url>      Node HTTP URL (default: http://127.0.0.1:8080)
  -m, --metrics <url>   Metrics URL (default: http://127.0.0.1:9898/metrics)
  -c, --count <num>     Number of transactions to spam (default: 2000)
  -d, --duration <sec>  Measurement duration in seconds (default: 20)
  -w, --warmup <sec>    Warm-up period in seconds (default: 5)
  -h, --help            Show this help message

Exit codes:
  0 - TPS meets floor (regression check passed)
  1 - TPS below floor (potential regression detected)
  2 - Node not reachable or other error

EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--floor)
            TPS_FLOOR="$2"
            shift 2
            ;;
        -n|--node)
            NODE_URL="$2"
            shift 2
            ;;
        -m|--metrics)
            METRICS_URL="$2"
            shift 2
            ;;
        -c|--count)
            TX_COUNT="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -w|--warmup)
            WARMUP="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Error: Unknown option: $1" >&2
            echo "Use --help for usage information." >&2
            exit 2
            ;;
    esac
done

# ─────────────────────────────────────────────────────────────────────────────
# Change to repo root
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}       T84.5 TPS Regression Guard                              ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Configuration:"
echo -e "  Node URL:        ${YELLOW}$NODE_URL${NC}"
echo -e "  Metrics URL:     ${YELLOW}$METRICS_URL${NC}"
echo -e "  TX count:        ${YELLOW}$TX_COUNT${NC}"
echo -e "  Duration:        ${YELLOW}${DURATION}s${NC}"
echo -e "  Warmup:          ${YELLOW}${WARMUP}s${NC}"
echo -e "  TPS Floor:       ${YELLOW}$TPS_FLOOR${NC} tx/s"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Check dependencies
# ─────────────────────────────────────────────────────────────────────────────
command -v curl >/dev/null || { echo -e "${RED}ERROR: curl is required${NC}"; exit 2; }
command -v bc >/dev/null || { echo -e "${RED}ERROR: bc is required${NC}"; exit 2; }

# ─────────────────────────────────────────────────────────────────────────────
# Verify node connectivity
# ─────────────────────────────────────────────────────────────────────────────
echo -e "[1/4] Verifying node connectivity..."
if ! curl -sf "$NODE_URL/health" >/dev/null 2>&1; then
    echo -e "${RED}ERROR: Cannot reach node at $NODE_URL${NC}"
    echo ""
    echo "Make sure the node is running with T84.5 profile:"
    echo "  source devnet_tps.env"
    echo "  ./scripts/devnet_dag_primary.sh"
    exit 2
fi
echo -e "      ${GREEN}✓${NC} Node is responding at $NODE_URL"

if ! curl -sf "$METRICS_URL" >/dev/null 2>&1; then
    echo -e "${RED}ERROR: Cannot reach metrics at $METRICS_URL${NC}"
    exit 2
fi
echo -e "      ${GREEN}✓${NC} Metrics endpoint available"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Helper function to get metric value
# ─────────────────────────────────────────────────────────────────────────────
get_metric() {
    local name="$1"
    local default="${2:-0}"
    local value
    value=$(curl -sf "$METRICS_URL" 2>/dev/null | grep "^${name} " | awk '{print $2}' | head -1)
    value="${value%.0}"
    echo "${value:-$default}"
}

# ─────────────────────────────────────────────────────────────────────────────
# Check if spam_tps.sh prerequisites are met
# ─────────────────────────────────────────────────────────────────────────────
echo -e "[2/4] Checking spam prerequisites..."

# Check for EEZO_TX_FROM (required by spam_tps.sh)
if [[ -z "${EEZO_TX_FROM:-}" ]]; then
    echo -e "${YELLOW}NOTE: EEZO_TX_FROM not set. Skipping spam generation.${NC}"
    echo -e "      Measuring TPS from existing traffic only."
    echo ""
    SKIP_SPAM=1
else
    # Check for txgen binary
    TXGEN_BIN=""
    if [[ -x "target/debug/eezo-txgen" ]]; then
        TXGEN_BIN="target/debug/eezo-txgen"
    elif [[ -x "target/release/eezo-txgen" ]]; then
        TXGEN_BIN="target/release/eezo-txgen"
    fi

    if [[ -z "$TXGEN_BIN" ]]; then
        echo -e "${YELLOW}NOTE: eezo-txgen not found. Skipping spam generation.${NC}"
        echo -e "      Build with: cargo build -p eezo-node --bin eezo-txgen"
        SKIP_SPAM=1
    else
        echo -e "      ${GREEN}✓${NC} EEZO_TX_FROM is set"
        echo -e "      ${GREEN}✓${NC} eezo-txgen found at $TXGEN_BIN"
        SKIP_SPAM=0
    fi
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Generate load (if prerequisites met)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "[3/4] Generating load and measuring TPS..."

if [[ "${SKIP_SPAM:-0}" != "1" ]]; then
    echo -e "      Starting spam_tps.sh with $TX_COUNT transactions..."
    ./scripts/spam_tps.sh "$TX_COUNT" "$NODE_URL" &
    SPAM_PID=$!
    
    # Give spam some time to start
    sleep 2
fi

# Capture start metrics
TXS_START=$(get_metric "eezo_txs_included_total" "0")
TS_START=$(date +%s)

echo -e "      Start txs_included: $TXS_START"
echo -e "      Warming up for ${WARMUP}s..."
sleep "$WARMUP"

echo -e "      Measuring for ${DURATION}s..."
sleep "$DURATION"

# Capture end metrics
TXS_END=$(get_metric "eezo_txs_included_total" "0")
TS_END=$(date +%s)

# Wait for spam to finish if running
if [[ "${SKIP_SPAM:-0}" != "1" && -n "${SPAM_PID:-}" ]]; then
    wait "$SPAM_PID" 2>/dev/null || true
fi

echo -e "      End txs_included: $TXS_END"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Calculate TPS
# ─────────────────────────────────────────────────────────────────────────────
echo -e "[4/4] Evaluating results..."
echo ""

TX_DELTA=$((TXS_END - TXS_START))
TIME_DELTA=$((TS_END - TS_START))

if [[ "$TIME_DELTA" -le 0 ]]; then
    echo -e "${RED}ERROR: Invalid time delta${NC}"
    exit 2
fi

TPS=$(echo "scale=2; $TX_DELTA / $TIME_DELTA" | bc -l)

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "  Transactions:     $TX_DELTA over ${TIME_DELTA}s"
echo -e "  Measured TPS:     ${YELLOW}$TPS${NC} tx/s"
echo -e "  TPS Floor:        $TPS_FLOOR tx/s"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Evaluate pass/fail
# ─────────────────────────────────────────────────────────────────────────────
if [[ $(echo "$TPS >= $TPS_FLOOR" | bc -l) == "1" ]]; then
    echo -e "${GREEN}✓ PASS: TPS ($TPS) meets floor ($TPS_FLOOR)${NC}"
    echo ""
    echo "Regression check passed. No performance degradation detected."
    exit 0
else
    echo -e "${RED}✗ FAIL: TPS ($TPS) below floor ($TPS_FLOOR)${NC}"
    echo ""
    echo "Potential performance regression detected!"
    echo ""
    echo "Troubleshooting steps:"
    echo "  1. Verify T84.5 env vars are set (source devnet_tps.env)"
    echo "  2. Check sigpool metrics: curl -s $METRICS_URL | grep eezo_sigpool"
    echo "  3. Check STM metrics: curl -s $METRICS_URL | grep eezo_exec_stm"
    echo "  4. Check persist metrics: curl -s $METRICS_URL | grep eezo_persist"
    echo ""
    echo "See book/src/t84_plateau.md for detailed troubleshooting."
    exit 1
fi
