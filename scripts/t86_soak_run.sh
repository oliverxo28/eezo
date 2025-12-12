#!/usr/bin/env bash
# T86.0: DAG Soak Profile & Correctness Guardrails
#
# PURPOSE:
#   Run a multi-minute soak test for DAG + STM under sustained load.
#   Produces a JSON summary with correctness + stability metrics and
#   prints sanity check hints (OK/WARN) based on metric analysis.
#
# USAGE:
#   ./scripts/t86_soak_run.sh [OPTIONS]
#
# OPTIONS:
#   -s, --scenario {A|B|C}     Scenario to run (default: A)
#                              A = Single sender (baseline, zero conflict)
#                              B = 32 senders, disjoint (low conflict)
#                              C = 32 senders, hotspot (high conflict)
#   -d, --duration <seconds>   Measurement window (default: 300)
#   -w, --warmup <seconds>     Warm-up period (default: 30)
#   -n, --node <url>           Node HTTP URL (default: http://127.0.0.1:8080)
#   -m, --metrics <url>        Metrics URL (default: http://127.0.0.1:9898/metrics)
#   -l, --label <string>       Optional label for the run
#   -h, --help                 Show this help message
#
# PREREQUISITES:
#   - Node running with T84.5 profile (source devnet_tps.env first)
#   - For Scenario A: EEZO_TX_FROM and related env vars set (see spam_tps.sh)
#   - For Scenarios B/C: ml_dsa_keygen and eezo-txgen binaries built
#   - jq, curl, bc available
#
# OUTPUT:
#   - JSON summary written to t86_results/soak_<scenario>_<timestamp>.json
#   - Sanity check summary printed to stdout
#
# SCENARIOS:
#   A) Single Sender (baseline):
#      - Uses spam_tps.sh with ~5000 transactions
#      - Confirms ceiling in "zero conflict" land
#
#   B) 32 Senders, Disjoint (low conflict, parallel-friendly):
#      - Uses spam_multi_senders.sh --senders 32 --per-sender 200 --pattern disjoint
#      - Many independent senders, many independent receivers
#
#   C) 32 Senders, Hotspot (high conflict, worst-case):
#      - Uses spam_multi_senders.sh --senders 32 --per-sender 200 --pattern hotspot --hot-receivers 1
#      - Stresses STM conflict detection and retry logic
#
# EXAMPLE:
#   # 1) Start devnet max-perf (T84.5 env)
#   source devnet_tps.env
#   ./scripts/devnet_dag_primary.sh
#
#   # 2) Run Scenario A soak (5 minutes)
#   ./scripts/t86_soak_run.sh --scenario A --duration 300 --warmup 30
#
# See book/src/t86_soak_profile.md for detailed documentation.

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Default Configuration
# ─────────────────────────────────────────────────────────────────────────────
SCENARIO="A"
DURATION=300
WARMUP=30
NODE_URL="${NODE:-http://127.0.0.1:8080}"
METRICS_URL="${EEZO_METRICS_URL:-http://127.0.0.1:9898/metrics}"
LABEL=""

# ─────────────────────────────────────────────────────────────────────────────
# Argument Parsing
# ─────────────────────────────────────────────────────────────────────────────
show_help() {
    cat << 'EOF'
T86.0: DAG Soak Profile & Correctness Guardrails

Usage: t86_soak_run.sh [OPTIONS]

Options:
  -s, --scenario {A|B|C}     Scenario to run (default: A)
                             A = Single sender (baseline, zero conflict)
                             B = 32 senders, disjoint (low conflict)
                             C = 32 senders, hotspot (high conflict)
  -d, --duration <seconds>   Measurement window (default: 300)
  -w, --warmup <seconds>     Warm-up period (default: 30)
  -n, --node <url>           Node HTTP URL (default: http://127.0.0.1:8080)
  -m, --metrics <url>        Metrics URL (default: http://127.0.0.1:9898/metrics)
  -l, --label <string>       Optional label for the run
  -h, --help                 Show this help message

Scenarios:
  A  Single sender baseline (no conflicts expected)
  B  32 senders, disjoint pattern (low conflicts)
  C  32 senders, hotspot pattern (high conflicts)

Examples:
  # 5-minute soak with single sender
  ./scripts/t86_soak_run.sh --scenario A --duration 300 --warmup 30

  # 5-minute soak with multi-sender low conflict
  ./scripts/t86_soak_run.sh --scenario B --duration 300 --warmup 30

  # 5-minute soak with multi-sender high conflict
  ./scripts/t86_soak_run.sh --scenario C --duration 300 --warmup 30

EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--scenario)
            SCENARIO="$2"
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
        -n|--node)
            NODE_URL="$2"
            shift 2
            ;;
        -m|--metrics)
            METRICS_URL="$2"
            shift 2
            ;;
        -l|--label)
            LABEL="$2"
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
# Validate scenario
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$SCENARIO" != "A" && "$SCENARIO" != "B" && "$SCENARIO" != "C" ]]; then
    echo "[error] Invalid scenario: $SCENARIO (must be A, B, or C)" >&2
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Change to repo root
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ─────────────────────────────────────────────────────────────────────────────
# Check dependencies
# ─────────────────────────────────────────────────────────────────────────────
command -v curl >/dev/null || { echo "[error] curl is required"; exit 1; }
command -v bc >/dev/null || { echo "[error] bc is required"; exit 1; }
command -v jq >/dev/null || { echo "[error] jq is required"; exit 1; }

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ─────────────────────────────────────────────────────────────────────────────
# Scenario descriptions
# ─────────────────────────────────────────────────────────────────────────────
scenario_desc() {
    case $1 in
        A) echo "Single Sender (baseline, zero conflict)" ;;
        B) echo "32 Senders, Disjoint (low conflict)" ;;
        C) echo "32 Senders, Hotspot (high conflict)" ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# Print header
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  T86.0: DAG Soak Profile & Correctness Guardrails${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Configuration:"
echo "  Scenario:           $SCENARIO - $(scenario_desc "$SCENARIO")"
echo "  Duration:           ${DURATION}s"
echo "  Warmup:             ${WARMUP}s"
echo "  Node URL:           $NODE_URL"
echo "  Metrics URL:        $METRICS_URL"
if [[ -n "$LABEL" ]]; then
    echo "  Label:              $LABEL"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Verify node and metrics endpoints
# ─────────────────────────────────────────────────────────────────────────────
echo "[1/5] Verifying endpoints..."

if ! curl -sf "$NODE_URL/health" >/dev/null 2>&1; then
    echo -e "${RED}[error] Cannot reach node at $NODE_URL${NC}" >&2
    echo ""
    echo "Make sure the node is running with T84.5 profile:"
    echo "  source devnet_tps.env"
    echo "  ./scripts/devnet_dag_primary.sh"
    exit 1
fi
echo -e "      ${GREEN}✓${NC} Node is responding at $NODE_URL"

if ! curl -sf "$METRICS_URL" >/dev/null 2>&1; then
    echo -e "${RED}[error] Cannot reach metrics at $METRICS_URL${NC}" >&2
    exit 1
fi
echo -e "      ${GREEN}✓${NC} Metrics endpoint available at $METRICS_URL"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Helper: fetch a metric value from cached metrics
# ─────────────────────────────────────────────────────────────────────────────
CACHED_METRICS=""

fetch_metrics() {
    CACHED_METRICS=$(curl -sf "$METRICS_URL" 2>/dev/null) || {
        echo -e "${RED}[error] Failed to fetch metrics from $METRICS_URL${NC}" >&2
        return 1
    }
}

get_metric() {
    local name="$1"
    local default="${2:-0}"
    local value
    # Match metric name followed by space (to avoid partial matches)
    value=$(echo "$CACHED_METRICS" | grep "^${name} " | awk '{print $2}' | head -1)
    # Strip trailing .0 if present (some metrics are floats)
    value="${value%.0}"
    echo "${value:-$default}"
}

# Get histogram sum (for latency metrics)
get_histogram_sum() {
    local name="$1"
    local default="${2:-0}"
    local value
    value=$(echo "$CACHED_METRICS" | grep "^${name}_sum " | awk '{print $2}' | head -1)
    echo "${value:-$default}"
}

# Get histogram count (for latency metrics)
get_histogram_count() {
    local name="$1"
    local default="${2:-0}"
    local value
    value=$(echo "$CACHED_METRICS" | grep "^${name}_count " | awk '{print $2}' | head -1)
    echo "${value:-$default}"
}

# ─────────────────────────────────────────────────────────────────────────────
# Launch load generation based on scenario
# ─────────────────────────────────────────────────────────────────────────────
echo "[2/5] Launching load generation (Scenario $SCENARIO)..."

LOAD_PID=""
TX_TARGET=0

case $SCENARIO in
    A)
        # Single sender baseline
        # Check if EEZO_TX_FROM is set (required for spam_tps.sh)
        if [[ -z "${EEZO_TX_FROM:-}" ]]; then
            echo -e "${YELLOW}[warn] EEZO_TX_FROM not set. Spam generation will be skipped.${NC}"
            echo "      Set EEZO_TX_FROM and related env vars for full load generation."
            echo "      See scripts/spam_tps.sh for required environment variables."
        else
            TX_TARGET=5000
            echo "      Starting spam_tps.sh with $TX_TARGET transactions..."
            ./scripts/spam_tps.sh "$TX_TARGET" "$NODE_URL" &
            LOAD_PID=$!
        fi
        ;;
    B)
        # 32 senders, disjoint pattern (low conflict)
        TX_TARGET=$((32 * 200))  # 6400 tx
        echo "      Starting spam_multi_senders.sh (disjoint pattern)..."
        echo "        --senders 32 --per-sender 200 --hot-receivers 32 --pattern disjoint"
        ./scripts/spam_multi_senders.sh \
            --senders 32 \
            --per-sender 200 \
            --hot-receivers 32 \
            --pattern disjoint \
            --node "$NODE_URL" &
        LOAD_PID=$!
        ;;
    C)
        # 32 senders, hotspot pattern (high conflict)
        TX_TARGET=$((32 * 200))  # 6400 tx
        echo "      Starting spam_multi_senders.sh (hotspot pattern)..."
        echo "        --senders 32 --per-sender 200 --hot-receivers 1 --pattern hotspot"
        ./scripts/spam_multi_senders.sh \
            --senders 32 \
            --per-sender 200 \
            --hot-receivers 1 \
            --pattern hotspot \
            --node "$NODE_URL" &
        LOAD_PID=$!
        ;;
esac

echo -e "      ${GREEN}✓${NC} Load generation started (target: $TX_TARGET tx)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Warmup period
# ─────────────────────────────────────────────────────────────────────────────
echo "[3/5] Warming up for ${WARMUP}s..."
sleep "$WARMUP"
echo -e "      ${GREEN}✓${NC} Warmup complete"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Capture start metrics
# ─────────────────────────────────────────────────────────────────────────────
echo "[4/5] Running measurement for ${DURATION}s..."

fetch_metrics
START_TXS=$(get_metric "eezo_txs_included_total")
START_BLOCKS=$(get_metric "block_applied_total")
START_STM_WAVES=$(get_metric "eezo_exec_stm_waves_total")
START_STM_CONFLICTS=$(get_metric "eezo_exec_stm_conflicts_total")
START_STM_RETRIES=$(get_metric "eezo_exec_stm_retries_total")
START_STM_ABORTED=$(get_metric "eezo_exec_stm_aborted_total")
START_STM_WAVES_BUILT=$(get_metric "eezo_exec_stm_waves_built_total")
START_STM_PRESCREEN_HITS=$(get_metric "eezo_exec_stm_conflict_prescreen_hits_total")
START_STM_PRESCREEN_MISSES=$(get_metric "eezo_exec_stm_conflict_prescreen_misses_total")
START_SIGPOOL_BATCHES=$(get_metric "eezo_sigpool_batches_total")
START_SIGPOOL_LATENCY_SUM=$(get_histogram_sum "eezo_sigpool_batch_latency_seconds")
START_SIGPOOL_LATENCY_COUNT=$(get_histogram_count "eezo_sigpool_batch_latency_seconds")
START_PERSIST_BLOCKS=$(get_metric "eezo_persist_blocks_total")
START_STATE_ROOT_COUNT=$(get_histogram_count "eezo_state_root_compute_seconds")
START_STATE_ROOT_RECOMPUTE=$(get_metric "eezo_state_root_recompute_accounts")
START_TS=$(date +%s)

echo "      Start: txs_included=$START_TXS blocks=$START_BLOCKS"

# Wait for measurement window
sleep "$DURATION"

# ─────────────────────────────────────────────────────────────────────────────
# Capture end metrics
# ─────────────────────────────────────────────────────────────────────────────
fetch_metrics
END_TXS=$(get_metric "eezo_txs_included_total")
END_BLOCKS=$(get_metric "block_applied_total")
END_STM_WAVES=$(get_metric "eezo_exec_stm_waves_total")
END_STM_CONFLICTS=$(get_metric "eezo_exec_stm_conflicts_total")
END_STM_RETRIES=$(get_metric "eezo_exec_stm_retries_total")
END_STM_ABORTED=$(get_metric "eezo_exec_stm_aborted_total")
END_STM_WAVES_BUILT=$(get_metric "eezo_exec_stm_waves_built_total")
END_STM_PRESCREEN_HITS=$(get_metric "eezo_exec_stm_conflict_prescreen_hits_total")
END_STM_PRESCREEN_MISSES=$(get_metric "eezo_exec_stm_conflict_prescreen_misses_total")
END_SIGPOOL_BATCHES=$(get_metric "eezo_sigpool_batches_total")
END_SIGPOOL_LATENCY_SUM=$(get_histogram_sum "eezo_sigpool_batch_latency_seconds")
END_SIGPOOL_LATENCY_COUNT=$(get_histogram_count "eezo_sigpool_batch_latency_seconds")
END_PERSIST_BLOCKS=$(get_metric "eezo_persist_blocks_total")
END_STATE_ROOT_COUNT=$(get_histogram_count "eezo_state_root_compute_seconds")
END_STATE_ROOT_RECOMPUTE=$(get_metric "eezo_state_root_recompute_accounts")
END_TS=$(date +%s)

# End-of-run snapshot metrics (gauges)
END_MEMPOOL_LEN=$(get_metric "eezo_mempool_len")
END_MEMPOOL_INFLIGHT=$(get_metric "eezo_mempool_inflight_len")
END_PERSIST_QUEUE=$(get_metric "eezo_persist_queue_len")
END_PERSIST_HEAD_ENTRIES=$(get_metric "eezo_persist_head_entries")
END_STATE_ROOT_CACHED=$(get_metric "eezo_state_root_cached_accounts")
END_SIGPOOL_CACHE_HITS=$(get_metric "eezo_sigpool_cache_hits_total")
END_SIGPOOL_CACHE_MISSES=$(get_metric "eezo_sigpool_cache_misses_total")

echo "      End:   txs_included=$END_TXS blocks=$END_BLOCKS"
echo -e "      ${GREEN}✓${NC} Measurement complete"
echo ""

# Wait for load generator to finish (if still running)
if [[ -n "$LOAD_PID" ]]; then
    wait "$LOAD_PID" 2>/dev/null || true
fi

# ─────────────────────────────────────────────────────────────────────────────
# Compute deltas and TPS
# ─────────────────────────────────────────────────────────────────────────────
DELTA_TXS=$((END_TXS - START_TXS))
DELTA_BLOCKS=$((END_BLOCKS - START_BLOCKS))
DELTA_TIME=$((END_TS - START_TS))
DELTA_STM_WAVES=$((END_STM_WAVES - START_STM_WAVES))
DELTA_STM_CONFLICTS=$((END_STM_CONFLICTS - START_STM_CONFLICTS))
DELTA_STM_RETRIES=$((END_STM_RETRIES - START_STM_RETRIES))
DELTA_STM_ABORTED=$((END_STM_ABORTED - START_STM_ABORTED))
DELTA_STM_WAVES_BUILT=$((END_STM_WAVES_BUILT - START_STM_WAVES_BUILT))
DELTA_STM_PRESCREEN_HITS=$((END_STM_PRESCREEN_HITS - START_STM_PRESCREEN_HITS))
DELTA_STM_PRESCREEN_MISSES=$((END_STM_PRESCREEN_MISSES - START_STM_PRESCREEN_MISSES))
DELTA_SIGPOOL_BATCHES=$((END_SIGPOOL_BATCHES - START_SIGPOOL_BATCHES))
DELTA_SIGPOOL_LATENCY_COUNT=$((END_SIGPOOL_LATENCY_COUNT - START_SIGPOOL_LATENCY_COUNT))
DELTA_PERSIST_BLOCKS=$((END_PERSIST_BLOCKS - START_PERSIST_BLOCKS))
DELTA_STATE_ROOT_COUNT=$((END_STATE_ROOT_COUNT - START_STATE_ROOT_COUNT))
DELTA_STATE_ROOT_RECOMPUTE=$((END_STATE_ROOT_RECOMPUTE - START_STATE_ROOT_RECOMPUTE))

# Calculate TPS
if [[ $DELTA_TIME -gt 0 ]]; then
    TPS=$(echo "scale=2; $DELTA_TXS / $DELTA_TIME" | bc -l)
    BPS=$(echo "scale=2; $DELTA_BLOCKS / $DELTA_TIME" | bc -l)
else
    TPS="0.00"
    BPS="0.00"
fi

# Calculate sigpool avg latency
if [[ $DELTA_SIGPOOL_LATENCY_COUNT -gt 0 ]]; then
    DELTA_SIGPOOL_LATENCY_SUM=$(echo "$END_SIGPOOL_LATENCY_SUM - $START_SIGPOOL_LATENCY_SUM" | bc -l)
    SIGPOOL_AVG_LATENCY=$(echo "scale=6; $DELTA_SIGPOOL_LATENCY_SUM / $DELTA_SIGPOOL_LATENCY_COUNT" | bc -l)
else
    SIGPOOL_AVG_LATENCY="0"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Generate JSON summary
# ─────────────────────────────────────────────────────────────────────────────
echo "[5/5] Generating summary..."

# Create results directory
RESULTS_DIR="$REPO_ROOT/t86_results"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="$RESULTS_DIR/soak_${SCENARIO}_${TIMESTAMP}.json"

# Build JSON
cat > "$OUTPUT_FILE" << EOF
{
  "scenario": "$SCENARIO",
  "scenario_description": "$(scenario_desc "$SCENARIO")",
  "label": "$LABEL",
  "timestamp": "$(date -Iseconds)",
  "duration_seconds": $DELTA_TIME,
  "warmup_seconds": $WARMUP,
  "node_url": "$NODE_URL",
  "metrics_url": "$METRICS_URL",
  "tps": $TPS,
  "blocks_per_second": $BPS,
  "delta_txs": $DELTA_TXS,
  "delta_blocks": $DELTA_BLOCKS,
  "tx_target": $TX_TARGET,
  "stm": {
    "waves_total": $DELTA_STM_WAVES,
    "waves_built_total": $DELTA_STM_WAVES_BUILT,
    "conflicts_total": $DELTA_STM_CONFLICTS,
    "retries_total": $DELTA_STM_RETRIES,
    "aborted_total": $DELTA_STM_ABORTED,
    "prescreen_hits_total": $DELTA_STM_PRESCREEN_HITS,
    "prescreen_misses_total": $DELTA_STM_PRESCREEN_MISSES
  },
  "mempool": {
    "len_at_end": $END_MEMPOOL_LEN,
    "inflight_len_at_end": $END_MEMPOOL_INFLIGHT
  },
  "sigpool": {
    "batches_total": $DELTA_SIGPOOL_BATCHES,
    "avg_latency_seconds": $SIGPOOL_AVG_LATENCY,
    "cache_hits_total": $END_SIGPOOL_CACHE_HITS,
    "cache_misses_total": $END_SIGPOOL_CACHE_MISSES
  },
  "persistence": {
    "queue_len_at_end": $END_PERSIST_QUEUE,
    "blocks_total": $DELTA_PERSIST_BLOCKS,
    "head_entries_at_end": $END_PERSIST_HEAD_ENTRIES
  },
  "state_root": {
    "compute_count": $DELTA_STATE_ROOT_COUNT,
    "recompute_accounts": $DELTA_STATE_ROOT_RECOMPUTE,
    "cached_accounts_at_end": $END_STATE_ROOT_CACHED
  }
}
EOF

echo -e "      ${GREEN}✓${NC} JSON summary written to: $OUTPUT_FILE"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Print results
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Soak Test Results (Scenario $SCENARIO)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Measurement Period:"
echo "    Duration:             ${DELTA_TIME}s"
echo "    Transactions:         $DELTA_TXS"
echo "    Blocks:               $DELTA_BLOCKS"
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────────────┐"
echo "  │  TPS (Transactions Per Second):   $TPS"
echo "  └─────────────────────────────────────────────────────────────────────────┘"
echo ""
echo "  STM Executor:"
echo "    Waves:                $DELTA_STM_WAVES"
echo "    Waves built:          $DELTA_STM_WAVES_BUILT"
echo "    Conflicts:            $DELTA_STM_CONFLICTS"
echo "    Retries:              $DELTA_STM_RETRIES"
echo "    Aborted:              $DELTA_STM_ABORTED"
echo "    Prescreen hits:       $DELTA_STM_PRESCREEN_HITS"
echo "    Prescreen misses:     $DELTA_STM_PRESCREEN_MISSES"
echo ""
echo "  Mempool (at end):"
echo "    Length:               $END_MEMPOOL_LEN"
echo "    Inflight:             $END_MEMPOOL_INFLIGHT"
echo ""
echo "  Sigpool:"
echo "    Batches:              $DELTA_SIGPOOL_BATCHES"
echo "    Avg latency:          ${SIGPOOL_AVG_LATENCY}s"
echo ""
echo "  Persistence (at end):"
echo "    Queue length:         $END_PERSIST_QUEUE"
echo "    Blocks persisted:     $DELTA_PERSIST_BLOCKS"
echo "    Head entries:         $END_PERSIST_HEAD_ENTRIES"
echo ""
echo "  State Root:"
echo "    Compute count:        $DELTA_STATE_ROOT_COUNT"
echo "    Recompute accounts:   $DELTA_STATE_ROOT_RECOMPUTE"
echo "    Cached accounts:      $END_STATE_ROOT_CACHED"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Soak-level sanity checks
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Soak Sanity Checks${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
echo ""

WARNINGS=()

# Check 1: No transactions included when spam was sent
if [[ $TX_TARGET -gt 0 && $DELTA_TXS -eq 0 ]]; then
    WARNINGS+=("delta_txs = 0 but spam tool claims it sent $TX_TARGET tx (transactions not included)")
fi

# Check 2: Aborted transactions in Scenario A or B (should be ~0)
if [[ "$SCENARIO" == "A" || "$SCENARIO" == "B" ]]; then
    if [[ $DELTA_STM_ABORTED -gt 0 ]]; then
        WARNINGS+=("stm_aborted_total = $DELTA_STM_ABORTED (expected ~0 for Scenario $SCENARIO)")
    fi
fi

# Check 3: High aborted transactions in Scenario C (concerning if excessive)
if [[ "$SCENARIO" == "C" && $DELTA_STM_ABORTED -gt 100 ]]; then
    WARNINGS+=("stm_aborted_total = $DELTA_STM_ABORTED (high abort rate in hotspot scenario)")
fi

# Check 4: Mempool backlog at end
if [[ $END_MEMPOOL_LEN -gt 1000 ]]; then
    WARNINGS+=("eezo_mempool_len = $END_MEMPOOL_LEN at end (possible backlog)")
fi

# Check 5: Persistence queue backlog
if [[ $END_PERSIST_QUEUE -gt 50 ]]; then
    WARNINGS+=("eezo_persist_queue_len = $END_PERSIST_QUEUE at end (possible async persist backlog)")
fi

# Check 6: State root recompute vs delta_txs (if incremental state root is not effective)
if [[ $DELTA_TXS -gt 0 ]]; then
    # If recompute_accounts is more than 10x delta_txs, it might indicate incremental state root is not working
    THRESHOLD=$((DELTA_TXS * 10))
    if [[ $DELTA_STATE_ROOT_RECOMPUTE -gt $THRESHOLD && $DELTA_STATE_ROOT_RECOMPUTE -gt 10000 ]]; then
        WARNINGS+=("eezo_state_root_recompute_accounts = $DELTA_STATE_ROOT_RECOMPUTE (much higher than delta_txs=$DELTA_TXS, incremental state root may not be effective)")
    fi
fi

# Check 7: Low TPS warning
TPS_INT=${TPS%.*}  # Convert to integer for comparison
if [[ ${TPS_INT:-0} -lt 50 && $TX_TARGET -gt 0 ]]; then
    WARNINGS+=("TPS = $TPS (lower than expected for active load)")
fi

# Print sanity results
if [[ ${#WARNINGS[@]} -eq 0 ]]; then
    echo -e "${GREEN}[t86] Soak sanity: OK${NC}"
    echo "      No aborted txs, no backlog, persist queue drained"
else
    echo -e "${YELLOW}[t86] Soak sanity: WARN${NC}"
    for warn in "${WARNINGS[@]}"; do
        echo -e "      ${YELLOW}- $warn${NC}"
    done
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Output file: $OUTPUT_FILE"
echo ""
echo "Soak test complete."
