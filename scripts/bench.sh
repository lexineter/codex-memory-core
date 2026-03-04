#!/usr/bin/env bash
set -euo pipefail

mkdir -p dist
cargo build --release -p codex_core
cargo bench -q -p codex_core --bench benchmarks -- --out dist/benchmarks.json
