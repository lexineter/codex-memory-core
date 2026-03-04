#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

hash_file() {
  local rel="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$rel" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$rel" | awk '{print $1}'
  else
    echo "release_bundle: neither sha256sum nor shasum found" >&2
    exit 1
  fi
}

rm -rf dist/proof_bundle
mkdir -p dist/proof_bundle

SKIP_RELEASE_BUNDLE_TEST=1 ./scripts/smoke.sh

if [[ "${SKIP_HEAVY:-0}" == "1" ]]; then
  rm -rf proof_a
  cargo run -q -p codex_core --bin scenario_runner -- --outdir proof_a
  cp proof_a/proof_manifest.json ./proof_manifest.json
else
  ./scripts/determinism_proof.sh
fi

cargo run -q -p codex_core --bin audit_bundle -- proof_a
cargo run -q -p codex_core --bin demo > proof_a/demo_transcript.txt

mkdir -p dist/proof_bundle/proof_a
mkdir -p dist/proof_bundle/proof_b
mkdir -p dist/proof_bundle/proof_c

cp proof_manifest.json dist/proof_bundle/proof_manifest.json
cp -R proof_a/. dist/proof_bundle/proof_a/

if [[ "${SKIP_HEAVY:-0}" != "1" ]]; then
  cp proof_b/proof_manifest.json dist/proof_bundle/proof_b/proof_manifest.json
  cp proof_c/proof_manifest.json dist/proof_bundle/proof_c/proof_manifest.json
fi

cp docs/WHITEPAPER.md dist/proof_bundle/WHITEPAPER.md
cp -R site dist/proof_bundle/site
cp docs/PROOF_BUNDLE_README.md dist/proof_bundle/README.md

cargo run -q -p codex_core --bin packaging_info -- --manifest proof_manifest.json > dist/proof_bundle/VERSION.json

(
  cd dist/proof_bundle
  find . -type f ! -name SHA256SUMS.txt | sed 's#^\./##' | LC_ALL=C sort | while IFS= read -r rel; do
    hash="$(hash_file "$rel")"
    printf "%s  %s\n" "$hash" "$rel"
  done > SHA256SUMS.txt
)

cargo run -q -p codex_core --bin bundle_manifest -- --dir dist/proof_bundle --out dist/proof_bundle/bundle_manifest.json
