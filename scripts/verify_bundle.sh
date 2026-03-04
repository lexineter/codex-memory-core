#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <bundle_dir>" >&2
  exit 1
fi

BUNDLE_DIR="$1"

if [[ ! -d "$BUNDLE_DIR" ]]; then
  echo "verify_bundle: bundle dir not found: $BUNDLE_DIR" >&2
  exit 1
fi

hash_file() {
  local rel="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$BUNDLE_DIR/$rel" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$BUNDLE_DIR/$rel" | awk '{print $1}'
  else
    echo "verify_bundle: neither sha256sum nor shasum found" >&2
    exit 1
  fi
}

required=(
  "proof_manifest.json"
  "VERSION.json"
  "SHA256SUMS.txt"
  "bundle_manifest.json"
  "proof_a/ledger.bin"
  "proof_a/audit_bundle.json"
)

for rel in "${required[@]}"; do
  if [[ ! -f "$BUNDLE_DIR/$rel" ]]; then
    echo "verify_bundle: missing required file: $rel" >&2
    exit 1
  fi
done

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  expected="${line%%  *}"
  rel="${line#*  }"
  if [[ ! -f "$BUNDLE_DIR/$rel" ]]; then
    echo "verify_bundle: listed file missing: $rel" >&2
    exit 1
  fi
  actual="$(hash_file "$rel")"
  if [[ "$actual" != "$expected" ]]; then
    echo "verify_bundle: hash mismatch for $rel" >&2
    echo "expected=$expected actual=$actual" >&2
    exit 1
  fi
done < "$BUNDLE_DIR/SHA256SUMS.txt"

bundle_manifest_text="$(cat "$BUNDLE_DIR/bundle_manifest.json")"

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  expected="${line%%  *}"
  rel="${line#*  }"
  needle="\"path\":\"$rel\",\"sha256\":\"$expected\""
  if ! grep -Fq "$needle" <<< "$bundle_manifest_text"; then
    echo "verify_bundle: bundle_manifest missing entry for $rel" >&2
    exit 1
  fi
done < "$BUNDLE_DIR/SHA256SUMS.txt"

if [[ -f "$BUNDLE_DIR/proof_b/proof_manifest.json" && -f "$BUNDLE_DIR/proof_c/proof_manifest.json" ]]; then
  cmp -s "$BUNDLE_DIR/proof_a/proof_manifest.json" "$BUNDLE_DIR/proof_b/proof_manifest.json" || {
    echo "verify_bundle: proof_a and proof_b manifests differ" >&2
    exit 1
  }
  cmp -s "$BUNDLE_DIR/proof_a/proof_manifest.json" "$BUNDLE_DIR/proof_c/proof_manifest.json" || {
    echo "verify_bundle: proof_a and proof_c manifests differ" >&2
    exit 1
  }
fi

echo "BUNDLE_VERIFIED"
