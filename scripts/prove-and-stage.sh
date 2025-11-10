#!/usr/bin/env bash
# ----------------------------------------------------------------------
# prove-and-stage.sh  – run eezo-prover for a given height and stage
#                      proof/public_inputs into proof/h{height}/
# Usage: ./prove-and-stage.sh <height>
# ----------------------------------------------------------------------

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <height>"
  exit 1
fi
H=$1
ROOT=${EEZO_PROOF_DIR:-proof}
OUTDIR="$ROOT/h$H"

mkdir -p "$OUTDIR"
echo "[*] generating proof for height $H → $OUTDIR/"

cargo run -p eezo-prover -- prove-checkpoint --height "$H" --output "$OUTDIR/output.json"

PROOF=$(jq -r '.proof_hex' "$OUTDIR/output.json")
PUBIN=$(jq -r '.public_inputs_abi_hex' "$OUTDIR/output.json")

if [ -z "$PROOF" ] || [ -z "$PUBIN" ]; then
  echo "❌ missing fields in output.json"
  exit 1
fi

echo "$PROOF"  > "$OUTDIR/proof.hex"
echo "$PUBIN"  > "$OUTDIR/public_inputs.hex"
echo "✅ staged proof for height $H"
