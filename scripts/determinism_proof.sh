#!/usr/bin/env bash
set -euo pipefail

rm -rf ./proof_a ./proof_b ./proof_c

for run_dir in proof_a proof_b proof_c; do
  cargo run -q -p codex_core --bin scenario_runner -- --outdir "${run_dir}"
done

cmp -s proof_a/proof_manifest.json proof_b/proof_manifest.json || {
  echo "determinism mismatch: proof_a vs proof_b" >&2
  exit 1
}
cmp -s proof_a/proof_manifest.json proof_c/proof_manifest.json || {
  echo "determinism mismatch: proof_a vs proof_c" >&2
  exit 1
}

cp proof_a/proof_manifest.json ./proof_manifest.json

echo "DETERMINISTIC_PROOF_CONFIRMED"
