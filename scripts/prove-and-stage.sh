#!/usr/bin/env bash
# prove-and-stage.sh – run eezo-prover for a given height and stage artifacts.
set -euo pipefail

require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1"; exit 1; }; }
require_cmd cargo
require_cmd jq

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <height>"
  exit 1
fi

H="$1"
if ! [[ "$H" =~ ^[0-9]+$ ]]; then
  echo "Height must be a non-negative integer"
  exit 1
fi

ROOT="${EEZO_PROOF_DIR:-proof}"
OUTDIR="$ROOT/h$H"
mkdir -p "$OUTDIR"

echo "[*] generating proof for height $H → $OUTDIR/"
if ! cargo run -q -p eezo-prover -- prove-checkpoint --height "$H" --output "$OUTDIR/output.json"; then
  echo "❌ prover run failed"
  exit 1
fi

if [[ ! -s "$OUTDIR/output.json" ]]; then
  echo "❌ output.json missing or empty"
  exit 1
fi

PROOF="$(jq -r '.proof_hex' "$OUTDIR/output.json")"
PUBIN="$(jq -r '.public_inputs_abi_hex' "$OUTDIR/output.json")"

if [[ -z "$PROOF" || -z "$PUBIN" || "$PROOF" == "null" || "$PUBIN" == "null" ]]; then
  echo "❌ required fields missing in output.json"
  exit 1
fi

printf '%s\n' "$PROOF"  > "$OUTDIR/proof.hex"
printf '%s\n' "$PUBIN"  > "$OUTDIR/public_inputs.hex"

echo "✅ staged proof for height $H"
