# Quickstart

## Prerequisites
- Rust toolchain (stable)

## One-Command Ship
```bash
./scripts/ship.sh
```

This runs smoke checks, builds the proof bundle, verifies it, and replay-verifies the bundled ledger.

## Verify Bundle
```bash
./scripts/verify_bundle.sh dist/proof_bundle
```

Expected output contains:
- `BUNDLE_VERIFIED`

## Replay Verify Bundle Ledger
```bash
cargo run -q -p codex_cli -- replay --ledger dist/proof_bundle/proof_a/ledger.bin
```

Expected output is one-line JSON containing:
- `"status":"VERIFIED"`
- `"final_mmr_root"`
- `"final_state_hash"`
- `"transcript_hash"`

## Expected Key Signals
- `DETERMINISTIC_PROOF_CONFIRMED`
- `BUNDLE_VERIFIED`
- `"status":"VERIFIED"`
- `SHIP_READY:dist/proof_bundle`
