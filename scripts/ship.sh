#!/usr/bin/env bash
set -euo pipefail

./scripts/smoke.sh
./scripts/release_bundle.sh
./scripts/verify_bundle.sh dist/proof_bundle
cargo run -q -p codex_cli -- replay --ledger dist/proof_bundle/proof_a/ledger.bin
echo "SHIP_READY:dist/proof_bundle"
