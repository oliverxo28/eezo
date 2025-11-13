#!/usr/bin/env bash
# Enhanced audit script (optional improvements).
set -euo pipefail

require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1"; exit 1; }; }
optional_cmd() { command -v "$1" >/dev/null 2>&1; }

require_cmd cargo
require_cmd curl

# Base supply-chain checks
if ! optional_cmd cargo-deny; then
  echo "Installing cargo-deny..."
  cargo install cargo-deny --locked
fi
if ! optional_cmd cargo-audit; then
  echo "Installing cargo-audit..."
  cargo install cargo-audit --locked
fi

echo "→ cargo deny check"
cargo deny check
echo "→ cargo audit"
cargo audit --deny warnings

ENVFILE="${ENVFILE:-devnet.env}"
if [[ -f "$ENVFILE" ]]; then
  echo "→ loading env profile: $ENVFILE"
  set -a
  # shellcheck disable=SC1090
  . "$ENVFILE"
  set +a
else
  echo "ℹ env profile not found ($ENVFILE), continuing"
fi

EEZO_METRICS_BIND="${EEZO_METRICS_BIND:-127.0.0.1:9898}"
RELAY_METRICS_BIND="${RELAY_METRICS_BIND:-127.0.0.1:9899}"  # use RELAY_METRICS_BIND for consistency

prometheus_checks() {
  if optional_cmd promtool; then
    if [[ -f ops/prometheus.yml ]]; then
      echo "→ promtool check config ops/prometheus.yml"
      promtool check config ops/prometheus.yml
    else
      echo "ℹ ops/prometheus.yml missing"
    fi
    if [[ -f ops/alerts.yml ]]; then
      echo "→ promtool check rules ops/alerts.yml"
      promtool check rules ops/alerts.yml
    else
      echo "ℹ ops/alerts.yml missing"
    fi
  else
    echo "ℹ promtool not installed; skipping Prometheus validation"
  fi
}
grafana_checks() {
  if optional_cmd jq && [[ -f ops/grafana/eezo-bridge.json ]]; then
    echo "→ validating grafana dashboard ops/grafana/eezo-bridge.json"
    jq empty ops/grafana/eezo-bridge.json
  else
    echo "ℹ jq not installed or dashboard missing; skipping grafana checks"
  fi
}

fetch_metrics() {
  local bind="$1"
  local http
  http="$(curl -fsS -w ' HTTP_STATUS:%{http_code}' --max-time 3 "http://$bind/metrics" || true)"
  local status="${http##*HTTP_STATUS:}"
  local body="${http% HTTP_STATUS:*}"
  if [[ "$status" != "200" || -z "$body" ]]; then
    echo "❌ metrics unreachable at $bind status=$status"
    return 1
  fi
  echo "$body"
}

prometheus_checks
grafana_checks

echo "→ probing node metrics at http://$EEZO_METRICS_BIND/metrics"
NODE_METRICS="$(fetch_metrics "$EEZO_METRICS_BIND")" || exit 1
echo "✓ node metrics reachable"

if ! grep -qE 'eezo_bridge_(latest_height|last_served_height|node_lag)' <<<"$NODE_METRICS"; then
  echo "❌ node metrics missing expected bridge gauges"
  exit 1
fi
echo "✓ node metrics contain bridge gauges"

echo "→ probing relay metrics at http://$RELAY_METRICS_BIND/metrics"
RELAY_METRICS="$(fetch_metrics "$RELAY_METRICS_BIND")" || exit 1
echo "✓ relay metrics reachable"

if ! grep -qE 'eezo_relay_(store_attempts_total|store_success_total|onchain_height|node_latest_height|backoff_seconds)' <<<"$RELAY_METRICS"; then
  echo "❌ relay metrics missing expected series"
  exit 1
fi
echo "✓ relay metrics contain expected series"

echo "✅ audit + observability checks passed"
