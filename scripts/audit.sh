# a/scripts/audit.sh
#!/usr/bin/env bash
set -euo pipefail

# ---------------- core supply-chain checks (existing) ----------------
cargo deny check
cargo audit --deny warnings

# ---------------- T37: BridgeOps observability checks ----------------
# Usage:
#   ENVFILE=devnet.env ./scripts/audit.sh
#   ENVFILE=testnet.env ./scripts/audit.sh

check_cmd() { command -v "$1" >/dev/null 2>&1; }

# 1) load env profile if present
ENVFILE="${ENVFILE:-devnet.env}"
if [[ -f "$ENVFILE" ]]; then
  echo "→ loading env profile: $ENVFILE"
  set -a
  # shellcheck disable=SC1090
  . "$ENVFILE"
  set +a
else
  echo "⚠ no env profile found at $ENVFILE (continuing with defaults)"
fi

# Default binds if not provided by env files
EEZO_METRICS_BIND="${EEZO_METRICS_BIND:-127.0.0.1:9898}"
RELAY_METRICS_BIND="${METRICS_BIND:-127.0.0.1:9899}"

# 2) Prometheus config/rules validation (optional)
if check_cmd promtool; then
  if [[ -f ops/prometheus.yml ]]; then
    echo "→ promtool check config ops/prometheus.yml"
    promtool check config ops/prometheus.yml
  else
    echo "⚠ ops/prometheus.yml not found, skipping promtool config check"
  fi
  if [[ -f ops/alerts.yml ]]; then
    echo "→ promtool check rules ops/alerts.yml"
    promtool check rules ops/alerts.yml
  else
    echo "⚠ ops/alerts.yml not found, skipping promtool rules check"
  fi
else
  echo "ℹ promtool not installed, skipping Prometheus validations"
fi

# 3) Grafana dashboard lint (optional)
if check_cmd jq && [[ -f ops/grafana/eezo-bridge.json ]]; then
  echo "→ jq validate ops/grafana/eezo-bridge.json"
  jq empty ops/grafana/eezo-bridge.json
else
  echo "ℹ jq not installed or grafana dashboard missing; skipping"
fi

# 4) Metrics endpoints health checks
curl_get() {
  curl -fsS --max-time 3 "http://$1$2"
}

echo "→ probing node metrics at http://$EEZO_METRICS_BIND/metrics"
NODE_METRICS="$(curl_get "$EEZO_METRICS_BIND" /metrics || true)"
if [[ -z "$NODE_METRICS" ]]; then
  echo "❌ node /metrics unreachable at $EEZO_METRICS_BIND"
  exit 1
fi
echo "✓ node metrics reachable"

# require at least one BridgeOps time series exposed by node
if ! grep -qE 'eezo_bridge_(latest_height|last_served_height|node_lag)' <<<"$NODE_METRICS"; then
  echo "❌ node metrics missing expected bridge gauges (latest/served/lag)"
  exit 1
fi
echo "✓ node metrics include BridgeOps gauges"

echo "→ probing relay metrics at http://$RELAY_METRICS_BIND/metrics"
RELAY_METRICS="$(curl_get "$RELAY_METRICS_BIND" /metrics || true)"
if [[ -z "$RELAY_METRICS" ]]; then
  echo "❌ relay /metrics unreachable at $RELAY_METRICS_BIND"
  exit 1
fi
echo "✓ relay metrics reachable"

# require at least one Relay metric
if ! grep -qE 'eezo_relay_(store_attempts_total|store_success_total|onchain_height|node_latest_height|backoff_seconds)' <<<"$RELAY_METRICS"; then
  echo "❌ relay metrics missing expected series"
  exit 1
fi
echo "✓ relay metrics include expected series"

echo "✅ audit + observability checks passed"
