#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

CONTAINER_NAME="codex-memory-ship-run"

docker build -t codex-memory .
docker build -t codex-memory-ship --target shipper .

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run --name "$CONTAINER_NAME" codex-memory-ship bash -lc "cd /workspace && ./scripts/ship.sh"

rm -rf dist/proof_bundle
docker cp "$CONTAINER_NAME":/workspace/dist/proof_bundle dist/proof_bundle

./scripts/verify_bundle.sh dist/proof_bundle
